# 5. Stop-and-wait with deduplication over UDP

Date: 2026-09-09. Status: accepted.

## Context

The project needs to show what a transport gives you by taking it away. UDP provides
datagram boundaries and nothing else: no delivery, no order, no protection from
duplicates. The question is how much of TCP to rebuild.

## Decision

Stop-and-wait: one message in flight, an explicit `ACK` for anything carrying
`FLAG_REQUIRE_ACK`, retransmission on a fixed 0.5 s timeout with `FLAG_RETRANSMIT` set on
the repeat, and at most five retries before the send fails with `ERR_TIMEOUT`.

On the receiving side, a deduplication window of the last 256 sequence numbers per peer,
storing the reply each one produced. A duplicate is answered from that cache; the handler
does not run twice.

## Alternatives considered

- **Reimplementing TCP** (sliding window, adaptive RTO, congestion control): weeks of work
  for a result that is worse than the TCP already in the kernel, and it would not teach
  more than the minimal version does.
- **No deduplication, only retries**: the sender cannot distinguish a lost request from a
  lost reply, so it retransmits in both cases. Without deduplication the receiver executes
  the request again, and the reliability layer turns into a request multiplier.
- **Implicit acknowledgement by the reply itself**: the reply frame does not say which
  request it answers. After a retransmission, a late copy of an earlier reply would be
  taken for the answer to the current request. The explicit `ACK` carries `ack_seq` and
  travels in the same datagram as the reply, ahead of it.

## Consequences

- Throughput is bounded by one round trip per message. This is a deliberate ceiling and it
  is stated in the README limitations, not hidden.
- The fixed RTO is wrong on any real path: too long on a LAN, too short across the
  internet. Jacobson's RTT estimation is the correct answer and is not implemented.
- The sequence rule from ADR-0004 cannot apply as-is over UDP, because a retransmission
  legitimately repeats a `seq`. Deduplication runs in front of the session, so the session
  keeps its strict rule and never sees the duplicate.
- Loss is emulated in tests through an injected `random.Random` with a fixed seed, so a
  probabilistic property is asserted deterministically.

## Amendment, 2026-09-10

- The original rationale for the explicit `ACK` was that it separates a slow handler from
  a lost request. That needs an `ACK` sent before the handler runs; the implementation
  always sent it in one datagram with the reply, so the benefit never existed. The `ACK`
  now does the job it can do in that position: the client accepts a datagram only if it
  starts with the `ACK` for the request in flight. Before this, a reply slower than the
  RTO shifted every later answer by one request.
- The deduplication window used to be keyed by address and to outlive the session, so a
  new session from the same address was answered from the old session's cache. It now
  belongs to the session.
- A datagram that fails decoding is dropped silently instead of producing an `ERROR` and
  closing the session of its source address, which was a spoofable teardown.
