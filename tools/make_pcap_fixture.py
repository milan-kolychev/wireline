"""Build deterministic pcap fixtures containing Wireline traffic.

A real capture needs privileges and a network; a fixture built here is byte-identical on
every machine, which is what a test needs. The Ethernet/IP/TCP headers are assembled by
hand, so the fixture exercises the same parsing path as a capture from tcpdump.

    python tools/make_pcap_fixture.py --out tests/fixtures
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

from wireline.protocol import messages
from wireline.protocol.codec import Frame, MsgType, encode
from wireline.sniff.pcap import LINKTYPE_ETHERNET, write_packets

SECRET = b"fixture-secret"
CLIENT_MAC = bytes.fromhex("020000000001")
SERVER_MAC = bytes.fromhex("020000000002")
CLIENT_IP = "10.0.0.10"
SERVER_IP = "10.0.0.20"
CLIENT_PORT = 51234
SERVER_PORT = 9000


def ip_bytes(addr: str) -> bytes:
    return bytes(int(part) for part in addr.split("."))


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ethernet(src: bytes, dst: bytes, payload: bytes) -> bytes:
    return struct.pack("!6s6sH", dst, src, 0x0800) + payload


def ipv4(src: str, dst: str, proto: int, payload: bytes, ident: int) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
        ip_bytes(src), ip_bytes(dst),
    )
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def tcp(sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes) -> bytes:
    header = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, 65535, 0, 0)
    return header + payload


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def tcp_session() -> list[tuple[float, bytes]]:
    """Handshake, HELLO/HELLO_ACK, a DATA frame split across two segments, teardown."""
    packets: list[tuple[float, bytes]] = []
    ts = 1757000000.0
    ident = 1
    c_seq, s_seq = 1000, 5000

    def c2s(flags: int, payload: bytes = b"") -> None:
        nonlocal ts, ident, c_seq
        packets.append(
            (ts, ethernet(CLIENT_MAC, SERVER_MAC,
                          ipv4(CLIENT_IP, SERVER_IP, 6,
                               tcp(CLIENT_PORT, SERVER_PORT, c_seq, s_seq, flags, payload),
                               ident)))
        )
        ts += 0.0005
        ident += 1
        c_seq += max(len(payload), 1 if flags & 0x02 else 0)

    def s2c(flags: int, payload: bytes = b"") -> None:
        nonlocal ts, ident, s_seq
        packets.append(
            (ts, ethernet(SERVER_MAC, CLIENT_MAC,
                          ipv4(SERVER_IP, CLIENT_IP, 6,
                               tcp(SERVER_PORT, CLIENT_PORT, s_seq, c_seq, flags, payload),
                               ident)))
        )
        ts += 0.0005
        ident += 1
        s_seq += max(len(payload), 1 if flags & 0x02 else 0)

    c2s(0x02)                      # SYN
    s2c(0x12)                      # SYN-ACK
    c2s(0x10)                      # ACK
    c2s(0x18, encode(Frame(MsgType.HELLO, 0, messages.encode_hello("capture")), SECRET))
    s2c(0x18, encode(Frame(MsgType.HELLO_ACK, 0, messages.encode_hello_ack("cap01")), SECRET))

    # One DATA frame deliberately split across two segments: this is what the
    # packet-level scan cannot see and flow reassembly can.
    data = encode(Frame(MsgType.DATA, 1, b"payload that crosses a segment boundary"), SECRET)
    c2s(0x18, data[:30])
    c2s(0x18, data[30:])
    s2c(0x18, encode(Frame(MsgType.DATA, 1, b"payload that crosses a segment boundary"), SECRET))

    c2s(0x18, encode(Frame(MsgType.BYE, 2), SECRET))
    s2c(0x11)                      # FIN-ACK
    c2s(0x10)                      # ACK
    return packets


def udp_session() -> list[tuple[float, bytes]]:
    ts = 1757000100.0
    packets = []
    request = encode(Frame(MsgType.PING, 0, b"udp probe", flags=0x01), SECRET)
    reply = encode(Frame(MsgType.PONG, 0, b"udp probe"), SECRET)
    packets.append((ts, ethernet(CLIENT_MAC, SERVER_MAC,
                                 ipv4(CLIENT_IP, SERVER_IP, 17,
                                      udp(51235, 9001, request), 100))))
    packets.append((ts + 0.001, ethernet(SERVER_MAC, CLIENT_MAC,
                                         ipv4(SERVER_IP, CLIENT_IP, 17,
                                              udp(9001, 51235, reply), 101))))
    return packets


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="tests/fixtures")
    args = parser.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    write_packets(out / "tcp-session.pcap", tcp_session(), LINKTYPE_ETHERNET)
    write_packets(out / "udp-session.pcap", udp_session(), LINKTYPE_ETHERNET)
    print(f"wrote {out / 'tcp-session.pcap'}\nwrote {out / 'udp-session.pcap'}")
