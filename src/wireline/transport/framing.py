"""Turning a byte stream back into messages.

TCP delivers bytes, not messages. One write may arrive as three reads, and three writes
may arrive as one read. Everything here exists because of that single fact.

Two entry points:

* `read_frame` for asyncio streams: uses `readexactly`, never `read`.
* `FrameBuffer` for the cases where the bytes arrive from somewhere else, such as a pcap
  reassembly in the analyser or a unit test that feeds one byte at a time.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator

from wireline.protocol.codec import (
    HEADER,
    MAC_SIZE,
    Frame,
    decode_frame,
    decode_header,
)


async def read_frame(reader: asyncio.StreamReader, secret: bytes) -> Frame:
    """Read exactly one frame.

    `readexactly(n)` returns n bytes or raises; `read(n)` returns *up to* n bytes. Using
    the latter here is the classic framing bug.
    """
    raw_header = await reader.readexactly(HEADER.size)
    header = decode_header(raw_header)  # validates length before we allocate the body
    payload = await reader.readexactly(header.length) if header.length else b""
    mac = await reader.readexactly(MAC_SIZE)
    return decode_frame(raw_header, payload, mac, secret)


class FrameBuffer:
    """Incremental parser over an arbitrary byte stream.

    Feed it whatever arrived; pop whatever is complete. It holds at most one partial
    frame, and the partial frame is bounded by MAX_PAYLOAD because `decode_header`
    rejects an oversized length before this class ever waits for that many bytes.
    """

    __slots__ = ("_buf", "_secret")

    def __init__(self, secret: bytes | None) -> None:
        """`secret=None` parses without verifying the MAC; used by the analyser only."""
        self._buf = bytearray()
        self._secret = secret

    def __len__(self) -> int:
        return len(self._buf)

    def feed(self, chunk: bytes) -> None:
        self._buf += chunk

    def pop(self) -> Frame | None:
        """Return the next complete frame, or None if more bytes are needed."""
        if len(self._buf) < HEADER.size:
            return None
        raw_header = bytes(self._buf[: HEADER.size])
        header = decode_header(raw_header)
        total = HEADER.size + header.length + MAC_SIZE
        if len(self._buf) < total:
            return None
        payload = bytes(self._buf[HEADER.size : HEADER.size + header.length])
        mac = bytes(self._buf[HEADER.size + header.length : total])
        del self._buf[:total]
        return decode_frame(raw_header, payload, mac, self._secret)

    def drain(self) -> Iterator[Frame]:
        """Yield every frame that is currently complete."""
        while (frame := self.pop()) is not None:
            yield frame
