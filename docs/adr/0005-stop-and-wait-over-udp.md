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
- **Implicit acknowledgement by the reply itself**: fewer datagrams, but then a slow
  handler is indistinguishable from a lost request, and the sender retransmits while the
  receiver is still working.

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
