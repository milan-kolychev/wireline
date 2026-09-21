# Test plan

Tests exist to cover risks, not to raise a coverage number. Each row below starts from a
risk and ends at the test that would fail if the risk materialised.

## 1. Levels

| Level | Location | Cost | What it can prove |
|---|---|---|---|
| unit | `tests/unit/` | microseconds | codec correctness, framing behaviour, every state transition |
| integration | `tests/integration/` | milliseconds | real segment boundaries, real timeouts, real teardown |
| benchmark | `benchmarks/` | seconds | latency percentiles, throughput, behaviour under concurrency |

Loss and TLS are tested at the integration level with injected dependencies: packet loss
through a seeded `random.Random`, certificates generated once per session into a temporary
directory. Neither needs a network fault or a real certificate authority.

There is no E2E level: the system is one process pair and integration already exercises
the full path.

## 2. Risk to test mapping

| # | Risk | Test |
|---|---|---|
| R1 | A message split across TCP segments is parsed as two messages or as garbage | `unit/test_framing.py::test_frame_split_at_an_arbitrary_offset`, `integration/test_tcp_session.py::test_split_frame_is_reassembled` |
| R2 | Two messages in one read are treated as one | `unit/test_framing.py::test_three_frames_in_one_chunk`, `integration::test_two_frames_in_one_write_are_both_handled` |
| R3 | A remote `length` value drives a huge allocation | `unit/test_codec.py::test_rejects_oversized_length_before_allocation` (security), `integration::test_oversized_length_does_not_allocate` |
| R4 | A tampered payload is accepted because the CRC was recomputed | `unit/test_codec.py::test_detects_tampering_with_a_recomputed_crc` (security) |
| R5 | An unauthenticated peer is served | `integration::test_frame_signed_with_the_wrong_secret_is_rejected` (security) |
| R6 | A captured frame is replayed successfully | `unit/test_session_fsm.py::test_invariant_3_replayed_seq_is_rejected`, `integration::test_replayed_frame_is_rejected` (security); across connections: `integration::test_a_session_replayed_from_a_capture_is_rejected`, **xfail, known gap** |
| R7 | Data is accepted before the handshake | `unit::test_invariant_1_*`, `integration::test_data_before_handshake_is_rejected` |
| R8 | A second handshake resets session state | `unit::test_invariant_2_second_hello_is_a_protocol_error`, `integration::test_second_handshake_is_rejected` |
| R9 | A dead or silent peer holds a connection forever | `integration::test_handshake_timeout_closes_a_silent_connection`, `integration::test_idle_timeout_closes_an_established_session` |
| R10 | One malformed client takes the listener down | `integration::test_garbage_does_not_kill_the_listener` |
| R11 | Someone replaces `readexactly` with `read` during a refactor | `unit/test_naive_reader_fails.py` |
| R12 | A struct change silently shifts field offsets | `unit/test_codec.py::test_header_size_is_19_bytes`, property-based roundtrip |
| R13 | Concurrency breaks session isolation | `integration::test_fifty_concurrent_clients` |
| R14 | A message is lost over UDP and never arrives | `integration/test_udp_reliability.py::test_delivery_survives_forty_percent_loss` |
| R15 | A retransmitted request is executed twice | `integration::test_a_retransmitted_request_is_executed_once` (security) |
| R16 | A silent UDP peer blocks the sender forever | `integration::test_client_gives_up_after_max_retries` |
| R17 | TLS is configured but not actually verifying anything | `integration/test_tls.py::test_untrusted_certificate_is_refused`, `::test_hostname_mismatch_is_refused` (security) |
| R18 | A plaintext client is served by a TLS listener | `integration::test_plaintext_client_cannot_talk_to_a_tls_listener` (security) |
| R19 | The analyser reports a frame whose body is not in the packet | `unit/test_sniff.py::test_split_frame_is_invisible_per_packet_but_visible_after_reassembly` |
| R20 | The analyser reports foreign traffic as Wireline | `unit::test_foreign_traffic_is_skipped_not_reported` |
| R21 | Analyser and server disagree about what arrived | `unit::test_reassembly_covers_both_directions` (same FrameBuffer as the server) |
| R22 | A late UDP reply is returned as the answer to the next request | `integration/test_udp_reliability.py::test_a_late_reply_is_not_taken_for_the_next_one` |
| R23 | A forged or garbage datagram closes a UDP session or allocates state | `integration::test_datagram_with_a_wrong_mac_is_dropped_without_touching_the_session`, `integration::test_unauthenticated_datagrams_leave_no_state_behind` (security) |
| R24 | A new UDP session is answered from the previous session's cache | `integration::test_a_new_session_is_not_answered_from_the_old_cache` |
| R25 | A malformed `ERROR` payload from the peer crashes the session | `unit/test_session_fsm.py::test_malformed_error_from_the_peer_does_not_raise` |

## 3. Test design techniques used

- **Equivalence classes** on `length`: negative is impossible (unsigned), `0` is valid,
  `1..MAX_PAYLOAD` is valid, `> MAX_PAYLOAD` is rejected.
- **Boundary values**: `MAX_PAYLOAD` and `MAX_PAYLOAD + 1` on encode; `0` and `1` byte
  payloads on roundtrip; `2**32 - 1` in the length field.
- **State transitions**: one test per row of the invariant table in PROTOCOL.md section 5,
  including the transitions that must be refused.
- **Property-based testing**: `hypothesis` generates payloads, sequence numbers and
  message types for the codec roundtrip, which covers input shapes nobody writes by hand.
- **Negative testing**: bad magic, wrong version, unknown type, short header, truncated
  frame, corrupted body, forged body, wrong key, replayed frame, reserved flags, HTTP
  request sent to a binary port, garbage datagram, untrusted certificate, hostname
  mismatch, plaintext client against a TLS listener, a capture that is not a pcap, a
  truncated capture.
- **Deterministic randomness**: probabilistic behaviour (packet loss) is tested with a
  fixed seed, so the same datagrams are dropped on every run and the assertion is exact.

## 4. Markers

- `security` marks tests that assert a security property rather than a feature. They are
  listed separately in the release checklist, because a failure there is not "a feature
  regressed", it is "a control is gone".
- `slow` is excluded from the fast CI gate.

## 5. Determinism

The analyser runs on committed fixtures built by `tools/make_pcap_fixture.py`, not on live
captures: no privileges, no network, byte-identical input on every machine.

Wall-clock timing matters in two places. The two TCP timeout tests use a server fixture
with short timeouts (0.5 s handshake, 1.0 s idle) and assert on the connection being
closed rather than on a duration. The UDP tests use short RTOs (0.05-0.2 s); the late-reply
test delays replies by 0.15 s against a 0.1 s RTO and asserts that a retransmission and a
replayed reply actually happened, so it cannot pass without going through the late-reply
path. Ports are ephemeral (`port=0`), so the suite can run in parallel with anything else
on the machine.
