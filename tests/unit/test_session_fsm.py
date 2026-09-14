"""State machine tests.

One test per invariant in docs/PROTOCOL.md section 5. No sockets: the session is pure
logic, so a transition test costs microseconds.
"""

from __future__ import annotations

import pytest

from wireline.protocol import messages
from wireline.protocol.codec import Frame, MsgType
from wireline.protocol.errors import ErrorCode, ProtocolError
from wireline.session import ServerSession, State


def hello(seq: int = 0, client_id: str = "test") -> Frame:
    return Frame(MsgType.HELLO, seq, messages.encode_hello(client_id))


def error_code_of(reaction) -> ErrorCode:
    assert len(reaction.frames) == 1
    frame = reaction.frames[0]
    assert frame.msg_type is MsgType.ERROR
    code, _ = messages.decode_error(frame.payload)
    return ErrorCode(code)


def ready_session() -> ServerSession:
    session = ServerSession()
    session.on_frame(hello())
    assert session.state is State.READY
    return session


def test_hello_completes_the_handshake() -> None:
    session = ServerSession()
    assert session.state is State.NEW
    reaction = session.on_frame(hello(client_id="probe"))
    assert session.state is State.READY
    assert session.client_id == "probe"
    assert not reaction.close
    assert reaction.frames[0].msg_type is MsgType.HELLO_ACK


@pytest.mark.parametrize(
    "msg_type", [MsgType.DATA, MsgType.PING, MsgType.ACK, MsgType.BYE, MsgType.HELLO_ACK]
)
def test_invariant_1_anything_but_hello_is_rejected_in_new(msg_type: MsgType) -> None:
    session = ServerSession()
    reaction = session.on_frame(Frame(msg_type, 0, b""))
    assert reaction.close
    assert session.state is State.CLOSED
    assert error_code_of(reaction) is ErrorCode.ERR_STATE


def test_invariant_2_second_hello_is_a_protocol_error() -> None:
    session = ready_session()
    reaction = session.on_frame(hello(seq=1))
    assert reaction.close
    assert error_code_of(reaction) is ErrorCode.ERR_STATE


@pytest.mark.security
def test_invariant_3_replayed_seq_is_rejected() -> None:
    session = ready_session()
    session.on_frame(Frame(MsgType.PING, 1))
    reaction = session.on_frame(Frame(MsgType.PING, 1))  # same frame again
    assert reaction.close
    assert error_code_of(reaction) is ErrorCode.ERR_SEQ


@pytest.mark.security
def test_invariant_3_also_covers_going_backwards() -> None:
    session = ready_session()
    session.on_frame(Frame(MsgType.PING, 10))
    reaction = session.on_frame(Frame(MsgType.PING, 4))
    assert error_code_of(reaction) is ErrorCode.ERR_SEQ


def test_invariant_4_idle_timeout_closes_without_an_error_frame() -> None:
    session = ready_session()
    reaction = session.on_idle_timeout()
    assert reaction.close
    assert reaction.frames == ()
    assert session.state is State.CLOSED


def test_invariant_6_decode_failure_produces_an_error_and_closes() -> None:
    session = ready_session()
    reaction = session.on_protocol_error(ProtocolError(ErrorCode.ERR_CRC, "crc mismatch"))
    assert reaction.close
    assert error_code_of(reaction) is ErrorCode.ERR_CRC


def test_ping_is_answered_with_pong_echoing_the_payload() -> None:
    session = ready_session()
    reaction = session.on_frame(Frame(MsgType.PING, 1, b"probe"))
    assert reaction.frames[0].msg_type is MsgType.PONG
    assert reaction.frames[0].payload == b"probe"
    assert not reaction.close


def test_data_is_echoed_by_the_reference_application() -> None:
    session = ready_session()
    reaction = session.on_frame(Frame(MsgType.DATA, 1, b"body"))
    assert reaction.frames[0].msg_type is MsgType.DATA
    assert reaction.frames[0].payload == b"body"


def test_bye_closes_politely() -> None:
    session = ready_session()
    reaction = session.on_frame(Frame(MsgType.BYE, 1))
    assert reaction.close
    assert reaction.frames[0].msg_type is MsgType.BYE
    assert session.state is State.CLOSED


def test_malformed_hello_payload_is_a_protocol_error() -> None:
    session = ServerSession()
    reaction = session.on_frame(Frame(MsgType.HELLO, 0, b"not json"))
    assert reaction.close
    assert session.state is State.CLOSED


def test_server_sequence_numbers_are_monotonic() -> None:
    session = ready_session()
    seqs = [session.on_frame(Frame(MsgType.PING, i)).frames[0].seq for i in range(1, 5)]
    assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs)
