# 6. The analyser parses without the key

Date: 2026-09-09. Status: accepted.

## Context

The traffic analyser reads captures. A capture is taken from a position on the network,
and that position does not come with the shared secret. The decoder, however, verifies a
MAC on every frame and refuses anything that fails.

## Decision

`decode_frame` and `FrameBuffer` accept `secret=None`, which parses the frame and checks
the CRC but skips MAC verification. Only the analyser passes `None`. Both peers of the
protocol always pass a key, and the parameter is documented as observer mode rather than
as an option.

## Alternatives considered

- **A separate parser for the analyser**: two implementations of the same layout drift
  apart, and the drift shows up as an analyser that disagrees with the server about what
  arrived, which is the one thing an analyser must never do.
- **Requiring the key to analyse**: makes the tool useless for any capture that is not
  from your own lab, and hides the fact that reading traffic and forging it are different
  capabilities.

## Consequences

- The analyser reports what a frame claims to be, not what is proven. Its output is
  evidence about structure, not about authenticity.
- A `None` default would be a security hole, so there is no default: the parameter is
  positional in `decode_frame` and explicit at every call site.
- Someone who can capture your traffic can read message types, sequence numbers and
  lengths. Payload contents are protected only when TLS is enabled (ADR-0002).
