"""Why `readexactly` and not `read`.

An ADR says what was decided. This file proves it. The naive reader below is the version
most people write first; the test shows the exact input that breaks it and shows that the
real reader survives the same input.

Keep it in the suite: if someone ever "simplifies" framing.py back to `read(n)`, the
second test starts failing and the reason is right here.
"""

from __future__ import annotations

import asyncio

import pytest

from wireline.protocol.codec import HEADER, MAC_SIZE, Frame, MsgType, decode_frame, encode
from wireline.protocol.errors import ProtocolError
from wireline.transport.framing import read_frame

SECRET = b"naive-secret"


async def read_frame_naive(reader: asyncio.StreamReader, secret: bytes) -> Frame:
    """The bug: `read(n)` returns *up to* n bytes, whatever has arrived so far."""
    from wireline.protocol.codec import decode_header

    raw_header = await reader.read(HEADER.size)
    header = decode_header(raw_header)
    payload = await reader.read(header.length) if header.length else b""
    mac = await reader.read(MAC_SIZE)
    return decode_frame(raw_header, payload, mac, secret)


def split_stream(raw: bytes, cut: int) -> asyncio.StreamReader:
    """A reader that has only the first `cut` bytes available right now."""
    reader = asyncio.StreamReader()
    reader.feed_data(raw[:cut])
    return reader


async def test_naive_reader_breaks_on_a_split_frame() -> None:
    raw = encode(Frame(MsgType.DATA, 1, b"y" * 200), SECRET)
    reader = split_stream(raw, cut=12)  # header itself is cut in half
    with pytest.raises(ProtocolError):
        await asyncio.wait_for(read_frame_naive(reader, SECRET), timeout=1.0)


async def test_correct_reader_waits_for_the_rest() -> None:
    frame = Frame(MsgType.DATA, 1, b"y" * 200)
    raw = encode(frame, SECRET)
    reader = split_stream(raw, cut=12)
    task = asyncio.ensure_future(read_frame(reader, SECRET))
    await asyncio.sleep(0.01)
    assert not task.done(), "readexactly must block until the frame is complete"
    reader.feed_data(raw[12:])
    assert await asyncio.wait_for(task, timeout=1.0) == frame
