"""Asyncio TCP client.

The client tracks the same states as the server (docs/PROTOCOL.md section 5) but occupies
HANDSHAKE for real: it sits there between sending HELLO and receiving HELLO_ACK.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import socket
import ssl
from types import TracebackType

from wireline.protocol import messages
from wireline.protocol.codec import MAX_SEQ, Frame, MsgType, encode
from wireline.protocol.errors import ErrorCode, ProtocolError
from wireline.session import State
from wireline.transport.framing import read_frame

log = logging.getLogger("wireline.client")

DEFAULT_TIMEOUT = 5.0


class WirelineClient:
    def __init__(
        self,
        secret: bytes,
        host: str = "127.0.0.1",
        port: int = 9000,
        *,
        client_id: str = "wireline-cli",
        timeout: float = DEFAULT_TIMEOUT,
        ssl_context: ssl.SSLContext | None = None,
        server_hostname: str | None = None,
    ) -> None:
        self._secret = secret
        self._host = host
        self._port = port
        self._client_id = client_id
        self._timeout = timeout
        self._ssl = ssl_context
        self._server_hostname = server_hostname
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._out_seq = 0
        self._last_peer_seq = -1
        self.state = State.NEW
        self.session_id: str | None = None

    # -- lifecycle --------------------------------------------------------

    async def connect(self) -> None:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                self._host,
                self._port,
                ssl=self._ssl,
                server_hostname=self._server_hostname if self._ssl else None,
            ),
            timeout=self._timeout,
        )
        self._reader, self._writer = reader, writer
        sock = writer.get_extra_info("socket")
        if sock is not None:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        await self._handshake()

    async def close(self) -> None:
        if self._writer is None:
            return
        with contextlib.suppress(ConnectionResetError, BrokenPipeError):
            if self.state is State.READY:
                await self._send(MsgType.BYE)
                self.state = State.CLOSING
        self._writer.close()
        with contextlib.suppress(ConnectionResetError, BrokenPipeError):
            await self._writer.wait_closed()
        self._reader = self._writer = None
        self.state = State.CLOSED

    async def __aenter__(self) -> WirelineClient:
        await self.connect()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.close()

    # -- protocol ---------------------------------------------------------

    async def _handshake(self) -> None:
        await self._send(MsgType.HELLO, messages.encode_hello(self._client_id))
        self.state = State.HANDSHAKE
        frame = await self._recv()
        if frame.msg_type is MsgType.ERROR:
            code, message = messages.decode_error(frame.payload)
            raise ProtocolError(ErrorCode(code), f"server rejected handshake: {message}")
        if frame.msg_type is not MsgType.HELLO_ACK:
            raise ProtocolError(
                ErrorCode.ERR_STATE, f"expected HELLO_ACK, got {frame.msg_type.name}"
            )
        self.session_id, _ = messages.decode_hello_ack(frame.payload)
        self.state = State.READY

    async def ping(self, payload: bytes = b"") -> Frame:
        return await self.request(MsgType.PING, payload)

    async def send_data(self, payload: bytes) -> bytes:
        return (await self.request(MsgType.DATA, payload)).payload

    async def request(self, msg_type: MsgType, payload: bytes = b"", flags: int = 0) -> Frame:
        if self.state is not State.READY:
            raise ProtocolError(
                ErrorCode.ERR_STATE, f"cannot send {msg_type.name} in state {self.state.value}"
            )
        await self._send(msg_type, payload, flags)
        return await self._recv()

    # -- transport --------------------------------------------------------

    async def _send(self, msg_type: MsgType, payload: bytes = b"", flags: int = 0) -> None:
        if self._writer is None:
            raise ProtocolError(ErrorCode.ERR_STATE, "client is not connected")
        frame = Frame(msg_type, self._next_seq(), payload, flags)
        self._writer.write(encode(frame, self._secret))
        await self._writer.drain()

    async def _recv(self) -> Frame:
        if self._reader is None:
            raise ProtocolError(ErrorCode.ERR_STATE, "client is not connected")
        frame = await asyncio.wait_for(
            read_frame(self._reader, self._secret), timeout=self._timeout
        )
        if frame.seq <= self._last_peer_seq:
            raise ProtocolError(
                ErrorCode.ERR_SEQ, f"replayed seq {frame.seq} from server"
            )
        self._last_peer_seq = frame.seq
        return frame

    def _next_seq(self) -> int:
        seq = self._out_seq
        self._out_seq = (self._out_seq + 1) & MAX_SEQ
        return seq
