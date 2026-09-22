# Architecture

## 1. Layers

```
        +-------------------------------+
        |  __main__.py  (CLI)           |
        +-------------------------------+
        |  server.py / client.py        |  sockets, timeouts, logging
        +-------------------------------+
        |  session.py                   |  state machine, no I/O
        +-------------------------------+
        |  transport/framing.py         |  stream -> frames
        +-------------------------------+
        |  protocol/codec.py, messages  |  bytes <-> Frame, CRC, HMAC
        +-------------------------------+
```

Dependencies point downwards only. `protocol/` imports nothing from the project except
`protocol/errors.py`; `session.py` imports `protocol/` but never `asyncio`. This allows the
state machine to be tested without a socket (ADR-0003).

## 2. Mapping to OSI

The table maps each OSI layer to the part of the system that implements it.

| OSI | Here |
|---|---|
| L2 Ethernet | outside the process; visible in a capture |
| L3 IP | outside the process; `socket` picks the interface |
| L4 TCP or UDP | `asyncio.start_server` / `open_connection`, or a datagram endpoint |
| L5 session | `session.py`: HELLO/HELLO_ACK, state, idle timeout |
| L6 presentation | `codec.py` (byte order, framing) and TLS when enabled |
| L7 application | message types and the echo reference application |

The mapping is also used for diagnosis. If a connection is established but no reply
arrives, each layer can be checked separately: `ss -tn` shows L4, a capture shows whether
frames left the host, the server log shows whether decoding succeeded, and the session
state shows whether the handshake completed.

## 3. Event flow

```
recv bytes
   |
   v
FrameBuffer / read_frame        decode_header -> length check -> body -> CRC -> HMAC
   |
   v
Frame
   |
   v
ServerSession.on_frame          seq check -> state check -> handler
   |
   v
Reaction(frames, close, reason)
   |
   v
transport: encode + write + drain, close if asked
```

Every failure in the decode chain raises `ProtocolError` with a code. The transport passes
it to `session.on_protocol_error`, which produces an ERROR frame and closes the connection.
No error in the decode path may stop the listener: the handler catches the exception, logs
it and closes only the affected connection.

## 4. Failure boundaries

| Boundary | What is caught | What happens |
|---|---|---|
| decode | malformed frame, bad MAC, bad length | ERROR frame, connection closed, listener stays up |
| state machine | illegal transition, replayed seq | ERROR frame, connection closed |
| timeout | silent peer before or after handshake | connection closed without an ERROR frame |
| unexpected exception | a bug in a handler | logged with traceback, connection closed |

## 5. Concurrency model

One asyncio task per connection, cooperative scheduling, single process. No locks are
needed because a `ServerSession` is accessed by exactly one task. The measured cost of this
model is recorded in `docs/evidence/benchmark-loopback.md`: with 100 concurrent clients,
per-request latency grows 60-70 times and total throughput does not grow, so on the
measured machine a single event loop saturates below 100 clients.
