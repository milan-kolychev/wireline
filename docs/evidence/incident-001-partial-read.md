# Incident 001. Client connection dropped on large messages

Type: intentional failure, injected to verify that the framing defence is real and that
the diagnostic path works.
Date: 2026-09-09.

## Impact

Every message larger than one TCP segment, or delayed between two writes, failed. The
client saw the connection torn down mid-request. Small messages that happened to arrive in
one segment kept working, which is what makes this class of bug survive manual testing.

## Symptom, as the client sees it

```
tests/conftest.py:47: in write_bytes
    await self.writer.drain()
...
E           ConnectionResetError: Connection lost
```

The client reports a transport-level failure and has no information about the cause. Taken
alone, this symptom points at the network.

## Scope

- Reproducible: yes, on every run of `test_split_frame_is_reassembled`.
- One request or all: only requests split across writes. A single-write frame of the same
  size succeeded.
- One component or the path: the connection was established and the handshake completed,
  so L3 and L4 were fine and the problem was above them.

## Hypotheses

1. The server crashed. Ruled out: the listener kept accepting other connections.
2. Network loss or MTU. Ruled out: loopback, and the same bytes in a single write worked.
3. The server closed the connection deliberately after a decode failure. Supported by
   ADR-0001, which says a decode failure is unrecoverable and closes the connection.

## Evidence

Server log, same run:

```
WARNING wireline.server:server.py:124 session d5a057fb22ec: ERR_LENGTH: short header: 10 bytes
```

That single line moves the diagnosis from "the network dropped us" to "the server received
10 bytes and tried to parse a 19-byte header". The client symptom is a consequence of the
server's decision to close.

## Root cause

`transport/framing.py` used `reader.read(n)` instead of `reader.readexactly(n)`. `read(n)`
returns *up to* n bytes, whatever has arrived so far. When the frame was split across two
TCP segments, the first call returned 10 bytes of a 19-byte header, `decode_header`
correctly rejected the short header, and the session closed as specified.

The defect is not in the check that fired. The check did its job. The defect is the
assumption that one read equals one message, which is precisely the property TCP does not
provide.

## Why the competing hypotheses are weaker

- "Server crash" predicts that subsequent connections fail too; they did not
  (`test_garbage_does_not_kill_the_listener` passes in the same run).
- "Network loss" predicts a size-dependent failure, not a write-count-dependent one. The
  same payload delivered in one write succeeded, which loss cannot explain.

## Fix

Use `readexactly` for all three reads (header, body, MAC), so the reader waits for the
full frame instead of parsing whatever arrived.

## Verification

```
$ pytest tests/integration/test_tcp_session.py::test_split_frame_is_reassembled -q
1 passed in 0.23s
```

## Regression and prevention

- `tests/unit/test_framing.py::test_one_frame_delivered_byte_by_byte` feeds the frame one
  byte at a time; it fails immediately if a partial read is ever emitted as a message.
- `tests/unit/test_naive_reader_fails.py` keeps the broken implementation in the suite as
  an executable explanation, so the next person to "simplify" this code sees why not.
- ADR-0001 records the framing decision and the reason.
