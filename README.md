# Wireline

A small authenticated binary protocol over TCP, with an explicit frame format, an explicit
connection state machine and a test suite built around the ways framing goes wrong.

The protocol is specified in [docs/PROTOCOL.md](docs/PROTOCOL.md), which was written
before the code.

Russian versions of these two documents: [README.ru.md](README.ru.md),
[docs/PROTOCOL.ru.md](docs/PROTOCOL.ru.md).

## What it solves

TCP gives you an ordered byte stream. It does not give you message boundaries,
authentication, or a way to tell that the peer process died an hour ago. Wireline adds
exactly those three things and nothing else: framing with a length prefix, HMAC-SHA256 on
every frame, and a state machine with timeouts.

## Frame format

```
 0        4     5     6     7        11       15       19
 +--------+-----+-----+-----+--------+--------+--------+
 | magic  | ver | typ |flags|  seq   | length |  crc32 |
 +--------+-----+-----+-----+--------+--------+--------+
 |                  payload (length bytes)             |
 +-----------------------------------------------------+
 |         hmac-sha256 over header+payload (32)        |
 +-----------------------------------------------------+
```

## Quickstart

Windows / PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"

# terminal 1
$env:WIRELINE_SECRET = "local-dev-secret"
python -m wireline serve --port 9000

# terminal 2: $env: lives only in its own terminal, so set it again
$env:WIRELINE_SECRET = "local-dev-secret"
python -m wireline ping --count 5
python -m wireline send --text "hello"
```

- `py` is the Python launcher. A bare `python` can start the Microsoft Store stub, which
  prints `Python` and creates nothing.
- If PowerShell refuses to run the activation script:
  `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` (current window only).
- Activation is optional: `.venv\Scripts\python.exe -m pytest` works without it.
- Options go after the command: `serve --port 9000`, not `--port 9000 serve`.

Linux / macOS: `python3 -m venv .venv && source .venv/bin/activate`, then the same
commands with `export WIRELINE_SECRET=...`.

Expected output of `ping`:

```
session 72f08a418fb6
pong 1/5  rtt=0.52 ms
pong 2/5  rtt=0.37 ms
pong 3/5  rtt=0.36 ms
pong 4/5  rtt=0.44 ms
pong 5/5  rtt=0.42 ms
```

The session id is new on every connection.

## Tests

```powershell
pytest                        # everything
pytest tests/unit             # fast, no sockets
pytest -m security            # only the tests that assert a security property
pytest --cov=src --cov-report=term-missing
```

The test plan, including the risk-to-test mapping, is in
[docs/TEST_PLAN.md](docs/TEST_PLAN.md).

Three tests are worth opening first:

- `tests/unit/test_framing.py::test_one_frame_delivered_byte_by_byte` - the frame arrives
  one byte at a time and must be emitted exactly once, at the last byte.
- `tests/unit/test_naive_reader_fails.py` - the same input fed to the `read(n)` version
  everyone writes first, showing it break.
- `tests/integration/test_tcp_session.py::test_split_frame_is_reassembled` - the same
  thing over a real socket, with sleeps that force separate TCP segments.

## Performance

Measured on Windows 11 (build 26200), Python 3.13.3, loopback, echo application. Two runs
of the same command; the table gives the range between them. Raw output and method in
[docs/evidence/benchmark-loopback.md](docs/evidence/benchmark-loopback.md).

| Scenario | p50 | p95 | p99 | Throughput |
|---|---|---|---|---|
| sequential, 1 KiB payload, 2000 requests | 0.15-0.17 ms | 0.26-0.35 ms | 0.45-0.55 ms | ~5 200-6 000 msg/s, 10-12 MB/s |
| 100 concurrent clients, 20 requests each | 9.6-11.4 ms | 18.7-22.7 ms | 19.4-25.0 ms | ~3 900-4 800 rps, 0 errors |

Reading:

- The two runs differ by 20-35% (p95 sequential, rps under load), so single numbers from
  one run mean little on a laptop.
- Under 100 clients per-request latency grows 60-70 times (p50 0.16 ms to 10-11 ms), and
  total throughput does not grow: it is lower than in the sequential case. On this machine
  the saturation point is below 100 concurrent clients.
- The sequential throughput is requests divided by the sum of latencies, not by wall-clock
  time, so it ignores the client's gaps between requests and is somewhat inflated. The
  difference to the concurrent figure is too large to be explained by that alone.

Reproduce with:

```powershell
python benchmarks/bench_tcp.py --requests 2000 --payload 1024 --clients 100
```

## Evidence

- [Incident 001: partial read](docs/evidence/incident-001-partial-read.md) - framing was
  broken on purpose. The client saw `ConnectionResetError`; the server log said
  `ERR_LENGTH: short header: 10 bytes`. Symptom, hypotheses, root cause, fix, regression.
- [Benchmark output](docs/evidence/benchmark-loopback.md) - raw numbers and the method
  that produced them.
- [Capture walkthrough](docs/evidence/capture-walkthrough.md) - a session read off the wire
  layer by layer, including the frame that only reassembly can see.

## TLS

Wireline does not encrypt (ADR-0002); it runs inside TLS.

```powershell
python tools/make_certs.py --out certs      # throwaway self-signed cert for the lab
```

```python
from wireline.tls import server_context, client_context
server = WirelineServer(secret, ssl_context=server_context("certs/server.crt", "certs/server.key"))
client = WirelineClient(secret, ssl_context=client_context("certs/server.crt"),
                        server_hostname="localhost")
```

The TLS handshake and the Wireline handshake answer different questions and are tested
separately: TLS asks whether the host is who it claims to be, Wireline asks whether the
peer holds the shared key. `tests/integration/test_tls.py` includes the negative cases -
untrusted certificate, hostname mismatch, plaintext client against a TLS listener.

## UDP

```python
from wireline.transport.udp import UdpServer, UdpClient
```

Stop-and-wait, explicit ACK, retransmission on a fixed timeout, and a deduplication window
on the receiver. The reason the last one exists: a lost ACK makes the sender retransmit a
request the receiver already ran, so without deduplication the reliability layer becomes a
request multiplier. Details and trade-offs in
[ADR-0005](docs/adr/0005-stop-and-wait-over-udp.md).

Loss is emulated with a seeded generator, so `test_delivery_survives_forty_percent_loss`
drops the same datagrams on every run.

## Traffic analyser

```powershell
python -m wireline sniff tests/fixtures/tcp-session.pcap --flows
```

Walks a capture L2 -> L3 -> L4 -> L7 and reassembles Wireline messages per direction of
each TCP connection, using the same `FrameBuffer` as the server. The pcap reader is
hand-written: a capture file is a header plus a list of timestamped byte strings.

Worked example and how to capture your own traffic on Windows and Linux:
[docs/NETWORK.md](docs/NETWORK.md).

## Architecture

[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). The short version: the connection state
machine in `src/wireline/session.py` contains no I/O. It takes an event and returns a
`Reaction`, and the transport applies it. Every invariant in the specification therefore
has a unit test that runs without a socket.

Decisions and their trade-offs are recorded in [docs/adr/](docs/adr/):

1. [Length-prefixed binary framing](docs/adr/0001-length-prefixed-binary-framing.md)
2. [HMAC on every frame, TLS for confidentiality](docs/adr/0002-hmac-on-every-frame-tls-for-confidentiality.md)
3. [Sans-I/O session state machine](docs/adr/0003-sans-io-session-state-machine.md)
4. [Strictly increasing sequence numbers](docs/adr/0004-strictly-increasing-sequence-numbers.md)
5. [Stop-and-wait with deduplication over UDP](docs/adr/0005-stop-and-wait-over-udp.md)
6. [The analyser parses without the key](docs/adr/0006-analyser-parses-without-the-key.md)

## Troubleshooting

| Symptom | First check | Usual cause |
|---|---|---|
| `ConnectionRefusedError` (`WinError 1225` on Windows) | is `serve` running on that host and port | nothing is listening |
| `ERR_AUTH` on the first frame | `WIRELINE_SECRET` on both sides | client and server have different keys; in PowerShell `$env:` is set per terminal |
| `ERR_MAGIC` immediately | what is actually connecting to the port | a browser, a health check, or a port collision |
| client hangs then times out | `ss -tn` (Linux) or `netstat -ano` (Windows) for the connection state | server started but not listening on that interface |
| connection drops after ~30 s of silence | server log for "idle timeout" | working as designed; send PING to keep it |
| `ERR_SEQ` | whether frames are being replayed or reordered | a retransmit at the application level, or a real replay |

## Limitations

Deliberate, and each one is a decision rather than an omission:

- **No confidentiality of its own.** Encryption is delegated to TLS; the server and client
  accept an `ssl_context`. Writing a cipher was rejected in ADR-0002.
- **No sliding window and no adaptive RTO** in the UDP binding. Stop-and-wait with a fixed
  timeout is enough to show the trade-off; Jacobson's RTT estimation is not implemented,
  so throughput is bounded by one round trip per message.
- **The analyser reads classic pcap only**, not pcapng, and dissects IPv4 over Ethernet or
  raw IP. It does not follow TCP sequence numbers, so a capture with reordering or
  retransmission at L4 will confuse flow reassembly.
- **Sequence numbers wrap at 2^32** and the session does not renegotiate.
- **The secret is pre-shared**, with no key exchange and no rotation.
- **`FLAG_COMPRESSED` is reserved and not implemented**; setting it is rejected rather than
  ignored.
- **Single process, one task per connection.** No backpressure beyond the OS socket
  buffers.

## Known issues

The items below are open defects.

- **No replay protection across connections.** Within a connection `seq` rejects a
  replayed frame. A whole captured session, replayed on a new connection, is accepted: the
  `HELLO` nonces are not bound into the MAC. See PROTOCOL.md section 8.4 and the `xfail`
  test named there. TLS prevents the capture in the first place.
- **UDP peers are never expired.** `UdpClient.close()` does not send `BYE`, and the UDP
  server has no idle timeout, so every client address that completed a handshake keeps a
  session and a deduplication window in memory until the server stops.
- **The UDP client does not check payload size** against the datagram limit; a payload
  above roughly 64 KiB fails in `sendto` with an `OSError`, not a `ProtocolError`.

## Status

Implemented: specification, codec, framing, session state machine, TCP server and client,
TLS, UDP reliability binding, pcap analyser, CLI, unit and integration suites, benchmark.

Checked on Windows 11 (build 26200) with Python 3.13.3.

The reference application is an echo service. The protocol does not care what `DATA`
means; the echo is the smallest behaviour that makes the transport observable.

## What this demonstrates

- Designing a wire format and writing the specification before the implementation,
  including limits, error codes and a versioning rule.
- Correct framing over a stream transport, and tests that prove it with the exact inputs
  that break the naive version.
- Treating `length` as attacker-controlled input and validating it before allocation.
- The difference between an error-detection control (CRC32) and an authentication control
  (HMAC-SHA256), and knowing when to delegate to TLS instead of inventing crypto.
- A connection state machine specified as invariants and tested transition by transition.
- Measured latency and throughput with a stated method, including the saturation point.
- Rebuilding the minimum reliability layer over UDP, and knowing why deduplication is the
  part that cannot be skipped.
- Reading traffic off the wire layer by layer, and telling a capture-side false positive
  from a real message.
