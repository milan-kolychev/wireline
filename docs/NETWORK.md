# Network notes

How Wireline traffic looks on the wire, and how to look at it.

## 1. What the analyser does

`python -m wireline sniff <capture.pcap> --flows` walks a capture layer by layer:

```
L2 Ethernet -> L3 IPv4 -> L4 TCP/UDP -> L7 Wireline
```

Each step strips one header and passes the rest down. The pcap reader
(`src/wireline/sniff/pcap.py`) is written by hand rather than taken from a library, so the
file format is visible: a 24-byte header, then per packet a 16-byte record header and the
captured bytes. Byte order is decided by the magic number, which is why a capture written
on one machine opens on another.

The analyser is an observer and does not hold the shared secret. It parses Wireline
headers and checks CRC, but it does not verify the MAC. That is a property of the position
rather than a shortcut: someone who can read the traffic still cannot forge it.

## 2. Reading a session

Output for the committed fixture `tests/fixtures/tcp-session.pcap`:

```
1757000000.000000  L2 02:...:01 -> 02:...:02  L3 10.0.0.10 -> 10.0.0.20  L4 TCP 51234 -> 9000 [SYN]
1757000000.000500  L2 02:...:02 -> 02:...:01  L3 10.0.0.20 -> 10.0.0.10  L4 TCP 9000 -> 51234 [SYN|ACK]
1757000000.001000  L2 02:...:01 -> 02:...:02  L3 10.0.0.10 -> 10.0.0.20  L4 TCP 51234 -> 9000 [ACK]
1757000000.001500  ... [PSH|ACK]  len 117  L7 HELLO seq=0 len=66
1757000000.002000  ... [PSH|ACK]  len 116  L7 HELLO_ACK seq=0 len=65
1757000000.002500  ... [PSH|ACK]  len 30
1757000000.003000  ... [PSH|ACK]  len 60
1757000000.003500  ... [PSH|ACK]  len 90   L7 DATA seq=1 len=39
1757000000.004000  ... [PSH|ACK]  len 51   L7 BYE seq=2 len=0
1757000000.004500  ... [FIN|ACK]
1757000000.005000  ... [ACK]
```

Three TCP packets before any Wireline message: the transport handshake completes before
the protocol handshake starts. The two are independent, and mixing them up is the usual
reason a diagnosis stalls.

## 3. The two packets with no L7 line

Packets 6 and 7 carry 30 and 60 bytes and show nothing at L7. That is the frame split
across segments. Per-packet scanning cannot report it: packet 6 has a complete 19-byte
header but only 11 bytes of a 39-byte body, and reporting a message whose body is not
present would be a false positive.

Following the flow recovers it:

```
reassembled per direction:
  10.0.0.10:51234 -> 10.0.0.20:9000: HELLO(seq=0), DATA(seq=1), BYE(seq=2)
  10.0.0.20:9000 -> 10.0.0.10:51234: HELLO_ACK(seq=0), DATA(seq=1)
```

Reassembly uses the same `FrameBuffer` the server uses. Capture-side and receive-side
parsing agree because they are the same code.

## 4. Frame sizes on the wire

| Message | Payload | Frame on the wire |
|---|---|---|
| `HELLO` | 66 | 117 |
| `HELLO_ACK` | 65 | 116 |
| `BYE` | 0 | 51 |

Overhead is 51 bytes per frame: 19 header, 32 MAC. For a `BYE` that is the entire packet,
which is the price of authenticating every frame rather than authenticating the session
once (ADR-0002).

## 5. Capturing your own traffic

Windows: install Wireshark with Npcap and tick "support loopback traffic capture", then
capture on the `Adapter for loopback traffic capture` interface with the filter
`tcp port 9000 or udp port 9001`. Save as **pcap**, not pcapng: the reader here handles the
classic format only, and Wireshark offers both under File -> Save As.

Linux: `sudo tcpdump -i lo -w capture.pcap 'port 9000 or port 9001'`.

Then:

```powershell
python -m wireline serve --port 9000
python -m wireline send --text "capture me"
python -m wireline sniff capture.pcap --flows
```

Useful Wireshark display filters while a capture is open:

- `tcp.port == 9000` - only the lab traffic;
- `tcp.len > 0` - only packets that carry data, hiding pure ACKs;
- `tcp.analysis.retransmission` - retransmissions, if the loss emulator was in use;
- `data[0:4] == 57:49:52:45` - packets that start with the `WIRE` magic.

## 6. Fixtures

`tools/make_pcap_fixture.py` builds the committed captures by assembling Ethernet, IPv4 and
TCP headers by hand around real Wireline frames. A synthetic fixture is byte-identical on
every machine, so the analyser tests are deterministic and need neither privileges nor a
network, while still exercising the same parsing path as a capture from tcpdump.

## 7. UDP

`tests/fixtures/udp-session.pcap` holds a PING/PONG exchange. The request has
`FLAG_REQUIRE_ACK` set, which is what the UDP client sets on every message it wants
acknowledged. In a capture taken with loss emulation the same `seq` appears more than once
with `FLAG_RETRANSMIT` on the later copies, and the server answers each of them from its
deduplication window instead of executing the request again (ADR-0005).
