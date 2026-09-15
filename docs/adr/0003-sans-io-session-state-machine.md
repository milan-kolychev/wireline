# 3. The session state machine contains no I/O

Date: 2026-09-09. Status: accepted.

## Context

The connection state machine has invariants that must be tested: no data before the
handshake, no second handshake, no replayed sequence numbers, close on idle. Testing them
through real sockets is slow, timing-dependent and gives a poor failure message when it
breaks.

## Decision

`wireline.session.ServerSession` accepts events (`on_frame`, `on_protocol_error`,
`on_idle_timeout`) and returns a `Reaction` describing which frames to send and whether to
close. It never touches a socket. `wireline.server` owns sockets, timeouts and logging and
simply applies the reaction.

## Alternatives considered

- **State machine inside the connection handler**: fewer files, but every transition test
  then needs a listener, a client and a timeout.
- **Callbacks into the transport**: inverts the dependency and makes the order of side
  effects implicit.

## Consequences

- Transition tests run in microseconds and are deterministic; `tests/unit/test_session_fsm.py`
  has one test per invariant in PROTOCOL.md section 5.
- The same session logic can be driven by a different transport (UDP, or a replay of a
  captured stream) without change.
- The transport must not make protocol decisions of its own. When it does, the invariant
  is no longer covered by the fast tests.
