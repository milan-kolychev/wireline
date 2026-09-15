# 2. HMAC on every frame, CRC kept, confidentiality delegated to TLS

Date: 2026-09-09. Status: accepted.

## Context

The protocol needs to detect accidental corruption, detect deliberate tampering, and
protect message contents. These are three different problems and they have three
different answers.

## Decision

- CRC32 over the payload, in the header: a cheap check for accidental corruption and for
  a desynchronised stream.
- HMAC-SHA256 over `header || payload` with a pre-shared key, as a 32-byte trailer on
  every frame. Verified with `hmac.compare_digest`.
- No encryption in Wireline. Confidentiality is obtained by running the protocol inside
  TLS via `ssl.SSLContext` (the server and client both accept an `ssl_context`).

Because a valid MAC already proves the peer holds the key, the handshake carries identity
and a nonce rather than a separate challenge/response round trip.

## Alternatives considered

- **CRC only**: forging a payload with a matching CRC is trivial. Rejected as a security
  control, kept as an error-detection control.
- **Custom encryption**: writing a cipher is the wrong answer to a solved problem, and in
  a portfolio it reads as a warning sign rather than as a skill.
- **MAC over the payload only**: would leave `seq`, `type` and `flags` malleable in
  flight. Rejected.

## Consequences

- Every frame costs 32 extra bytes and one SHA-256 pass. Measured overhead is acceptable
  at the target message rate (see docs/evidence/benchmark-loopback.md).
- Key distribution is out of scope: the secret comes from `WIRELINE_SECRET`, and the
  development fallback is logged as a warning so it cannot ship silently.
- `==` on MAC comparison would leak the matching prefix length through timing. The
  project uses `compare_digest` and says why in the code.
