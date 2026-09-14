"""Connection state machine, with no I/O in it.

The session decides *what* to answer; the transport decides *how* to send it. Keeping
them apart means the invariants from docs/PROTOCOL.md section 5 can be tested without
opening a socket, which is the difference between a unit test measured in microseconds
and an integration test measured in milliseconds.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum

from wireline.protocol import messages
from wireline.protocol.codec import MAX_SEQ, Frame, MsgType
from wireline.protocol.errors import ErrorCode, ProtocolError


class State(Enum):
    NEW = "NEW"
    HANDSHAKE = "HANDSHAKE"
    READY = "READY"
    CLOSING = "CLOSING"
    CLOSED = "CLOSED"


@dataclass(frozen=True, slots=True)
class Reaction:
    """What the transport must do after an event."""

    frames: tuple[Frame, ...] = ()
    close: bool = False
    reason: str | None = None


@dataclass
class ServerSession:
    """One client connection as seen by the server."""

    session_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    state: State = State.NEW
    client_id: str | None = None
    peer_nonce: str | None = None
    _out_seq: int = 0
    _last_peer_seq: int = -1

    # -- outbound helpers -------------------------------------------------

    def _next_seq(self) -> int:
        seq = self._out_seq
        self._out_seq = (self._out_seq + 1) & MAX_SEQ
        return seq

    def _frame(self, msg_type: MsgType, payload: bytes = b"", flags: int = 0) -> Frame:
        return Frame(msg_type, self._next_seq(), payload, flags)

    def _error(self, code: ErrorCode, message: str) -> Reaction:
        self.state = State.CLOSED
        return Reaction(
            frames=(self._frame(MsgType.ERROR, messages.encode_error(code, message)),),
            close=True,
            reason=f"{code.name}: {message}",
        )

    # -- events -----------------------------------------------------------

    def on_frame(self, frame: Frame) -> Reaction:
        """Handle one decoded frame. Never raises; failures become ERROR reactions."""
        if self.state in (State.CLOSING, State.CLOSED):
            return Reaction(close=True, reason="frame after close")

        if frame.seq <= self._last_peer_seq:
            return self._error(
                ErrorCode.ERR_SEQ,
                f"seq {frame.seq} not greater than last accepted {self._last_peer_seq}",
            )
        self._last_peer_seq = frame.seq

        try:
            return self._dispatch(frame)
        except ProtocolError as exc:
            return self._error(exc.code, exc.message)

    def on_protocol_error(self, exc: ProtocolError) -> Reaction:
        """The transport failed to decode. The stream position is no longer trusted."""
        return self._error(exc.code, exc.message)

    def on_idle_timeout(self) -> Reaction:
        """No frame within the idle window. Close quietly, without an ERROR frame:
        the peer is by definition not reading."""
        self.state = State.CLOSED
        return Reaction(close=True, reason="idle timeout")

    # -- dispatch ---------------------------------------------------------

    def _dispatch(self, frame: Frame) -> Reaction:
        if self.state is State.NEW:
            if frame.msg_type is not MsgType.HELLO:
                raise ProtocolError(
                    ErrorCode.ERR_STATE,
                    f"{frame.msg_type.name} is not allowed before the handshake",
                )
            return self._on_hello(frame)

        # state is READY from here on
        match frame.msg_type:
            case MsgType.HELLO:
                raise ProtocolError(ErrorCode.ERR_STATE, "handshake already completed")
            case MsgType.HELLO_ACK:
                raise ProtocolError(ErrorCode.ERR_STATE, "hello_ack is server to client")
            case MsgType.PING:
                return Reaction(frames=(self._frame(MsgType.PONG, frame.payload),))
            case MsgType.PONG:
                return Reaction()
            case MsgType.DATA:
                return self._on_data(frame)
            case MsgType.ACK:
                return Reaction()
            case MsgType.BYE:
                self.state = State.CLOSED
                return Reaction(
                    frames=(self._frame(MsgType.BYE),), close=True, reason="peer said bye"
                )
            case MsgType.ERROR:
                code, message = messages.decode_error(frame.payload)
                self.state = State.CLOSED
                return Reaction(close=True, reason=f"peer reported error {code}: {message}")
            case _:  # pragma: no cover - MsgType is exhaustive
                raise ProtocolError(
                    ErrorCode.ERR_TYPE, f"unhandled type {frame.msg_type!r}"
                )

    def _on_hello(self, frame: Frame) -> Reaction:
        # A valid MAC already proves the peer holds the pre-shared key; the handshake
        # carries identity and a nonce, not a separate authentication round trip.
        self.client_id, self.peer_nonce = messages.decode_hello(frame.payload)
        self.state = State.READY
        payload = messages.encode_hello_ack(self.session_id)
        return Reaction(frames=(self._frame(MsgType.HELLO_ACK, payload),))

    def _on_data(self, frame: Frame) -> Reaction:
        # Reference application: an echo service. The protocol does not care what DATA
        # means; this is the smallest behaviour that makes the transport observable.
        return Reaction(frames=(self._frame(MsgType.DATA, frame.payload),))
