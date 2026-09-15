from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator

import pytest

from wireline.protocol import messages
from wireline.protocol.codec import Frame, MsgType, encode
from wireline.server import WirelineServer
from wireline.transport.framing import read_frame

SECRET = b"test-secret"


@pytest.fixture
def secret() -> bytes:
    return SECRET


@pytest.fixture
async def server() -> AsyncIterator[WirelineServer]:
    """A server on an ephemeral port with short timeouts, so tests stay fast."""
    srv = WirelineServer(
        SECRET, "127.0.0.1", 0, idle_timeout=1.0, handshake_timeout=0.5
    )
    await srv.start()
    try:
        yield srv
    finally:
        await srv.close()


class RawPeer:
    """A client that speaks the wire format directly, without the client state machine.

    Tests need to send things a well-behaved client never would.
    """

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader = reader
        self.writer = writer

    async def write_bytes(self, raw: bytes) -> None:
        self.writer.write(raw)
        await self.writer.drain()

    async def send(self, frame: Frame, secret: bytes = SECRET) -> None:
        await self.write_bytes(encode(frame, secret))

    async def recv(self, timeout: float = 2.0) -> Frame:
        return await asyncio.wait_for(read_frame(self.reader, SECRET), timeout=timeout)

    async def handshake(self) -> Frame:
        await self.send(Frame(MsgType.HELLO, 0, messages.encode_hello("raw-peer")))
        return await self.recv()

    async def close(self) -> None:
        self.writer.close()
        with contextlib.suppress(ConnectionResetError, BrokenPipeError):
            await self.writer.wait_closed()


@pytest.fixture
async def peer(server: WirelineServer) -> AsyncIterator[RawPeer]:
    reader, writer = await asyncio.open_connection(*server.address)
    raw = RawPeer(reader, writer)
    try:
        yield raw
    finally:
        await raw.close()
