# 1. Length-prefixed binary framing

Date: 2026-09-09. Status: accepted.

## Context

TCP delivers a byte stream and does not preserve message boundaries. A receiver must be
able to tell where one message ends and the next begins. The project also has a teaching
goal: the framing must be visible in this repository, not hidden inside a library.

## Decision

A fixed 19-byte header with an explicit `length` field, followed by exactly `length`
payload bytes and a 32-byte MAC. Big-endian throughout (`struct` format `!4sBBBIII`), so
that peers on different architectures agree on integer layout.

## Alternatives considered

- **Delimiter (`\n`)**: requires escaping, and any binary payload breaks the parser.
  Rejected.
- **Self-describing format (msgpack/protobuf streamed)**: the library owns the boundary
  logic, which removes the only thing this project is meant to demonstrate. Rejected.
- **JSON over TCP with a length prefix**: a reasonable production choice, and the payload
  of control messages is in fact JSON. The envelope stays binary so that field offsets,
  byte order and alignment are explicit.

## Consequences

- Maximum message size is bounded by the 4-byte `length` field and by `MAX_PAYLOAD`.
- `length` is attacker-controlled, so it must be validated **before** a buffer of that
  size is allocated. Without that check, 19 bytes of input cause a 4 GiB allocation
  attempt. Enforced in `decode_header`, covered by a test marked `security`.
- Reading happens in three steps (header, body, MAC), which is why header parsing is a
  separate function from body verification.
