# 4. Strictly increasing sequence numbers per connection

Date: 2026-09-09. Status: accepted.

## Context

A correctly signed frame that an attacker captured is still a correctly signed frame.
Replaying it must not work. The protocol needs an ordering rule that makes a captured
frame invalid the second time it is presented.

## Decision

Each peer numbers its own frames from 0, strictly increasing, per connection. A receiver
keeps the last accepted value and rejects anything not greater than it with `ERR_SEQ` and
closes. The `HELLO` nonce makes a frame captured from an earlier session invalid in a new
one.

## Alternatives considered

- **Nonce with a uniqueness set**: stronger, but needs storage that grows with the number
  of frames, or an eviction policy that reintroduces the same window problem.
- **Timestamp with a tolerance window**: adds a clock-skew failure mode that is annoying to
  diagnose in a lab.

## Consequences

- Replay of a captured frame within a live connection is rejected; there is a test for it.
- Over TCP the rule is exact, because the transport already guarantees order.
- Over UDP the same rule cannot be used as-is: a retransmission legitimately repeats a
  `seq`. The UDP binding therefore deduplicates against a window of recently seen values
  instead of tearing the session down. This difference is a property of the transport, not
  an inconsistency in the protocol.
- Sequence numbers wrap at 2^32. A connection that sends four billion frames is out of
  scope for v1 and is listed under limitations.
