# Wireline protocol specification

Version: 1
Russian version: [PROTOCOL.ru.md](PROTOCOL.ru.md)
Status: stable for v1. Any change to the frame layout requires a version bump.

## 1. Purpose

Wireline is a small binary request/response protocol for authenticated message exchange
over TCP (and, in reliable mode, over UDP). The message boundary, the byte order, the
integrity check and the authentication check are defined explicitly, at the level of the
specification.

Scope:

- framing over a byte stream that does not preserve message boundaries;
- per-frame integrity (CRC32) and per-frame authentication (HMAC-SHA256);
- an explicit connection state machine with testable invariants;
- optional reliability (ACK, retransmit, deduplication) when carried over UDP.

Confidentiality is out of scope: Wireline does not encrypt and delegates encryption to TLS
(`ssl.SSLContext`), see section 9.

## 2. Frame layout

All integers are big-endian (network byte order), with no padding or alignment
(`struct` format `!4sBBBIII`).

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

| Field   | Size | Offset | Description                                                     |
|---------|------|--------|-----------------------------------------------------------------|
| magic   | 4    | 0      | `b"WIRE"`. Rejects foreign clients and detects stream desynchronisation. |
| ver     | 1    | 4      | Protocol version. A mismatch is rejected with `ERR_VERSION`.     |
| typ     | 1    | 5      | Message type, see section 3.                                     |
| flags   | 1    | 6      | Bit flags, see section 4.                                        |
| seq     | 4    | 7      | Sender sequence number, per connection, strictly increasing.      |
| length  | 4    | 11     | Payload length in bytes. Limit `MAX_PAYLOAD = 1 MiB`.            |
| crc32   | 4    | 15     | CRC32 of the payload only.                                       |
| payload | var  | 19     | `length` bytes. May be empty.                                     |
| mac     | 32   | 19+len | HMAC-SHA256 over `header || payload` with the pre-shared key.    |

Total frame size: `19 + length + 32`.

Header size is fixed, so a receiver reads a frame in three steps: 19 bytes of header, then
exactly `length` bytes, then exactly 32 bytes of MAC. `length` is validated against
`MAX_PAYLOAD` before any buffer of that size is allocated (section 8.1).

## 3. Message types

| Value | Name        | Direction       | Payload                                     |
|-------|-------------|-----------------|---------------------------------------------|
| 1     | `HELLO`     | client -> server | JSON `{"client_id": str, "nonce": hex}`     |
| 2     | `HELLO_ACK` | server -> client | JSON `{"session_id": str, "nonce": hex}`    |
| 3     | `DATA`      | both            | opaque bytes                                 |
| 4     | `ACK`       | both            | JSON `{"ack_seq": int}`                      |
| 5     | `PING`      | both            | empty or opaque                              |
| 6     | `PONG`      | both            | echo of the `PING` payload                   |
| 7     | `ERROR`     | both            | JSON `{"code": int, "message": str}`          |
| 8     | `BYE`       | both            | empty                                        |

Unknown type values are rejected with `ERR_TYPE`. New types may be added in a future
version. A v1 receiver must not silently ignore them, because silently accepting unknown
types would hide a version mismatch.

## 4. Flags

| Bit  | Name                | Meaning                                                  |
|------|---------------------|-----------------------------------------------------------|
| 0x01 | `FLAG_REQUIRE_ACK`  | Sender expects an `ACK` for this `seq`. Used in UDP mode.  |
| 0x02 | `FLAG_RETRANSMIT`   | This frame is a retransmission of an earlier `seq`.        |
| 0x04 | `FLAG_COMPRESSED`   | Reserved, not implemented in v1. Setting it is an error (`ERR_FLAGS`). |

## 5. State machine

```
NEW --HELLO--> HANDSHAKE --HELLO_ACK--> READY --BYE--> CLOSING --> CLOSED
 |                 |                      |
 +-- timeout ------+-- bad_auth ----------+-- protocol_error --> CLOSED
```

The server and the client move through the state machine differently.

The server session starts in `NEW`. A valid `HELLO` moves it to `READY`, and the server
answers with `HELLO_ACK`. The server never occupies `HANDSHAKE`, because validation and
response happen in one step.

The client session enters `HANDSHAKE` after sending `HELLO` and stays there until
`HELLO_ACK` arrives. The client-side timeout applies in this state.

Invariants that must be covered by explicit tests:

| # | Rule                                                             | Result                    |
|---|-------------------------------------------------------------------|---------------------------|
| 1 | Any frame other than `HELLO` in state `NEW`                       | `ERR_STATE`, close        |
| 2 | A second `HELLO` in state `READY`                                 | `ERR_STATE`, close        |
| 3 | `seq` not strictly greater than the last accepted peer `seq`      | `ERR_SEQ`, close          |
| 4 | No frame received within `idle_timeout`                           | close without `ERROR`     |
| 5 | Invalid MAC                                                       | `ERR_AUTH`, close         |
| 6 | Any `ProtocolError` while decoding                                | `ERROR` if possible, close |

Caveat to rule 6: after a decode failure the stream position is no longer trustworthy, so
recovery is not attempted. The connection is closed and the process keeps running.

Over UDP, rules 5 and 6 do not close anything. A datagram that fails decoding is dropped
without an answer, because its source address is not authenticated (section 9).

## 6. Error codes

| Code | Name           | Cause                                                |
|------|----------------|-------------------------------------------------------|
| 1    | `ERR_VERSION`  | `ver` does not match the supported version            |
| 2    | `ERR_MAGIC`    | `magic` is not `WIRE`                                 |
| 3    | `ERR_LENGTH`   | `length` exceeds `MAX_PAYLOAD` or does not match body |
| 4    | `ERR_CRC`      | CRC32 mismatch                                        |
| 5    | `ERR_AUTH`     | HMAC mismatch                                         |
| 6    | `ERR_TYPE`     | Unknown message type                                  |
| 7    | `ERR_STATE`    | Message not allowed in the current state              |
| 8    | `ERR_SEQ`      | Replayed or out-of-order sequence number              |
| 9    | `ERR_FLAGS`    | Reserved or unsupported flag bit set                  |
| 10   | `ERR_TIMEOUT`  | Idle timeout expired                                  |
| 99   | `ERR_INTERNAL` | Unexpected server-side failure                        |

## 7. Limits and timeouts

| Name             | Value    | Reason                                                   |
|------------------|----------|-----------------------------------------------------------|
| `MAX_PAYLOAD`    | 1 MiB    | Bounds a single allocation driven by a remote value.       |
| `MAX_FRAME`      | 1 MiB+51 | `MAX_PAYLOAD` plus header and MAC.                         |
| `idle_timeout`   | 30 s     | A TCP connection can look open long after the peer process has exited. |
| `handshake_timeout` | 5 s   | An unauthenticated connection must not hold resources.     |
| `udp_rto`        | 0.5 s    | Fixed retransmit timeout in v1, see limitations.           |
| `udp_max_retries`| 5        | Bounds the total time a send may block.                    |
| `dedup_window`   | 256      | Number of recent `seq` values remembered per UDP peer.     |

## 8. Security considerations

### 8.1 Length before allocation

`length` is a 4-byte field controlled by the remote side. If the body were read before
`length` is validated against `MAX_PAYLOAD`, 19 bytes of input could trigger a 4 GiB
allocation attempt. `decode_header` therefore rejects an oversized `length` before the body
is read. Covered by
`tests/unit/test_codec.py::test_rejects_oversized_length_before_allocation`.

### 8.2 CRC32 is not a security control

CRC32 detects accidental corruption. Forging a payload with a matching CRC is trivial.
CRC32 is kept because it is cheap and fails fast on a desynchronised stream. The security
property comes from the HMAC alone.

### 8.3 HMAC and comparison

The MAC covers the header as well as the payload, so `seq`, `type` and `flags` cannot be
altered in transit. Comparison uses `hmac.compare_digest`. The `==` operator returns on the
first differing byte and leaks the length of the matching prefix through timing.

### 8.4 Replay

A captured frame remains a valid frame and can be sent again. Within a connection, the
strictly increasing `seq` causes a replayed frame to be rejected with `ERR_SEQ`.

Across connections, v1 does not protect against replay. `seq` restarts at 0 on every
connection and every frame is signed with the same pre-shared key, so a captured session
replayed byte for byte on a new connection is accepted and executed. The `HELLO` and
`HELLO_ACK` nonces are exchanged but are not bound into the MAC, so they do not prevent
this. Binding them, for example through a per-session key derived from the pre-shared key
and both nonces, is not implemented. Until it is, TLS prevents an on-path attacker from
capturing and replaying traffic. The gap is recorded by
`tests/integration/test_tcp_session.py::test_a_session_replayed_from_a_capture_is_rejected`,
marked `xfail(strict=True)`: once the gap is closed, this test will fail the suite.

Over UDP the same `seq` may legitimately arrive twice as a retransmission, so the receiver
deduplicates against a window of recently seen values instead of rejecting the connection.

### 8.5 No custom cryptography

Wireline does not define an encryption scheme or include a custom cipher. Confidentiality
is obtained by running the protocol inside TLS, which already solves this problem.

## 9. Transport bindings

| Transport | Guarantees used from the transport | Provided by Wireline                    |
|-----------|------------------------------------|------------------------------------------|
| TCP       | ordering, retransmission, flow control | framing, auth, state machine           |
| TCP+TLS   | the above plus confidentiality      | same                                     |
| UDP       | nothing beyond best-effort datagrams | framing, ACK, retransmit, dedup |

Over UDP a frame must fit in a single datagram, so the practical payload limit is much
lower than `MAX_PAYLOAD` and is bounded by the path MTU.

A request is sent as one frame in one datagram. An answer is one datagram that holds the
`ACK` for the request, followed by the reply if the request produced one. The client uses
the `ack_seq` of that `ACK` to tell which request a datagram answers. A datagram that does
not start with the `ACK` for the request in flight is treated as a late copy of an earlier
answer and dropped.

A datagram that fails decoding (magic, version, length, CRC or MAC) is dropped by the
server without an `ERROR` and without affecting the session of its source address. The
address is not authenticated. Answering it, or closing the session it names, would allow
anyone able to spoof that address to terminate a live peer's session. Per-peer state,
including the deduplication window, is created only for a frame that passed its checks and
is discarded together with the session.

## 10. Versioning

`ver` is checked on every frame. A receiver rejects a mismatching version with
`ERR_VERSION` and does not attempt a best-effort parse, because refusing the connection is
safer than acting on a partly understood header. Compatible extensions in v1 are limited to
new `flags` bits and new payload fields inside existing JSON control messages. Any change
of field size, order or meaning requires `ver = 2`.
