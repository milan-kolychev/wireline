"""Framing tests.

These are the tests that encode the central fact of the project: a TCP read is not a
message. They run without a socket, so the partial delivery is exact rather than lucky.
"""

from __future__ import annotations

import pytest

from wireline.protocol.codec import HEADER, Frame, MsgType, encode
from wireline.protocol.errors import ErrorCode, ProtocolError
from wireline.transport.framing import FrameBuffer

SECRET = b"framing-secret"


def test_one_frame_delivered_byte_by_byte() -> None:
    frame = Frame(MsgType.DATA, 1, b"x" * 100)
    raw = encode(frame, SECRET)
    buf = FrameBuffer(SECRET)
    for i, byte in enumerate(raw):
        buf.feed(bytes([byte]))
        popped = buf.pop()
        if i < len(raw) - 1:
            assert popped is None, f"frame emitted after {i + 1} of {len(raw)} bytes"
        else:
            assert popped == frame


def test_three_frames_in_one_chunk() -> None:
    frames = [Frame(MsgType.PING, seq, b"n" * seq) for seq in (1, 2, 3)]
    buf = FrameBuffer(SECRET)
    buf.feed(b"".join(encode(f, SECRET) for f in frames))
    assert list(buf.drain()) == frames
    assert len(buf) == 0


def test_frame_split_at_an_arbitrary_offset() -> None:
    frame = Frame(MsgType.DATA, 5, b"payload-that-crosses-a-segment-boundary")
    raw = encode(frame, SECRET)
    for cut in (1, HEADER.size - 1, HEADER.size, HEADER.size + 3, len(raw) - 1):
        buf = FrameBuffer(SECRET)
        buf.feed(raw[:cut])
        assert buf.pop() is None
        buf.feed(raw[cut:])
        assert buf.pop() == frame


def test_leftover_bytes_are_kept_for_the_next_frame() -> None:
    first = encode(Frame(MsgType.PING, 1), SECRET)
    second = encode(Frame(MsgType.PONG, 2), SECRET)
    buf = FrameBuffer(SECRET)
    buf.feed(first + second[:5])
    assert buf.pop() is not None
    assert buf.pop() is None
    assert len(buf) == 5
    buf.feed(second[5:])
    assert buf.pop() is not None


def test_garbage_is_rejected_as_soon_as_the_header_is_complete() -> None:
    buf = FrameBuffer(SECRET)
    buf.feed(b"GET / HTTP/1.1\r\nHost: x")
    with pytest.raises(ProtocolError) as exc:
        buf.pop()
    assert exc.value.code is ErrorCode.ERR_MAGIC


@pytest.mark.security
def test_oversized_length_is_rejected_without_waiting_for_the_body() -> None:
    raw = bytearray(encode(Frame(MsgType.DATA, 1, b"x"), SECRET))
    raw[11:15] = (2**32 - 1).to_bytes(4, "big")
    buf = FrameBuffer(SECRET)
    buf.feed(bytes(raw[: HEADER.size]))
    with pytest.raises(ProtocolError) as exc:
        buf.pop()
    assert exc.value.code is ErrorCode.ERR_LENGTH
