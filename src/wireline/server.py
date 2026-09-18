"""Asyncio TCP server.

The server owns sockets, timeouts and logging. All protocol decisions live in
`wireline.session.ServerSession`.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import socket
import ssl
from types import TracebackType

from wireline.protocol.codec import Frame, encode
from wireline.protocol.errors import ProtocolError
from wireline.session import Reaction, ServerSession, State
from wireline.transport.framing import read_frame

log = logging.getLogger("wireline.server")

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9000
DEFAULT_IDLE_TIMEOUT = 30.0
DEFAULT_HANDSHAKE_TIMEOUT = 5.0


class WirelineServer:
    """A TCP listener. One `ServerSession` per accepted connection."""

    def __init__(
        self,
        secret: bytes,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        *,
        idle_timeout: float = DEFAULT_IDLE_TIMEOUT,
        handshake_timeout: float = DEFAULT_HANDSHAKE_TIMEOUT,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self._secret = secret
        self._host = host
        self._port = port
        self._idle_timeout = idle_timeout
        self._handshake_timeout = handshake_timeout
        self._ssl = ssl_context
        self._server: asyncio.AbstractServer | None = None
        self.connections = 0

    # -- lifecycle --------------------------------------------------------

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle, self._host, self._port, ssl=self._ssl
        )
        log.info("listening on %s:%s", *self.address)

    @property
    def address(self) -> tuple[str, int]:
        if self._server is None:
            raise RuntimeError("server is not started")
        sockets = getattr(self._server, "sockets", None)
        if not sockets:
            raise RuntimeError("server has no bound socket")
        host, port, *_ = sockets[0].getsockname()
        return str(host), int(port)

    async def serve_forever(self) -> None:
        if self._server is None:
            await self.start()
        assert self._server is not None
        async with self._server:
            await self._server.serve_forever()

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def __aenter__(self) -> WirelineServer:
        await self.start()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.close()

    # -- connection handling ----------------------------------------------

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        sock = writer.get_extra_info("socket")
        if sock is not None:
            # Nagle batches small writes and can add up to 40 ms to a request/response
            # protocol. Latency matters more here than a few extra packets.
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        session = ServerSession()
        self.connections += 1
        log.info("session %s open from %s", session.session_id, peer)
        try:
            while session.state not in (State.CLOSING, State.CLOSED):
                timeout = (
                    self._handshake_timeout
                    if session.state is State.NEW
                    else self._idle_timeout
                )
                try:
                    frame = await asyncio.wait_for(
                        read_frame(reader, self._secret), timeout=timeout
                    )
                except TimeoutError:
                    await self._apply(writer, session, session.on_idle_timeout())
                    break
                except ProtocolError as exc:
                    log.warning("session %s: %s", session.session_id, exc)
                    await self._apply(writer, session, session.on_protocol_error(exc))
                    break
                reaction = session.on_frame(frame)
                await self._apply(writer, session, reaction)
                if reaction.close:
                    break
        except asyncio.IncompleteReadError:
            log.info("session %s: peer closed mid-frame", session.session_id)
        except ConnectionResetError:
            log.info("session %s: connection reset", session.session_id)
        except Exception:  # pragma: no cover - a bug must not take the listener down
            log.exception("session %s: unhandled error", session.session_id)
        finally:
            writer.close()
            with contextlib.suppress(ConnectionResetError, BrokenPipeError):
                await writer.wait_closed()
            log.info("session %s closed", session.session_id)

    async def _apply(
        self, writer: asyncio.StreamWriter, session: ServerSession, reaction: Reaction
    ) -> None:
        if reaction.reason:
            log.info("session %s: %s", session.session_id, reaction.reason)
        for frame in reaction.frames:
            await self._send(writer, frame)

    async def _send(self, writer: asyncio.StreamWriter, frame: Frame) -> None:
        try:
            writer.write(encode(frame, self._secret))
            await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            log.info("peer went away before %s could be sent", frame.msg_type.name)
