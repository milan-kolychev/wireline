"""Reliability over UDP.

UDP gives neither delivery, nor order, nor protection from duplicates. Implementing a
minimal reliable layer reproduces a small part of what TCP does and makes its cost
visible.

Implemented: stop-and-wait, explicit ACK, retransmission on a fixed timeout, and a
deduplication window on the receiver. Not implemented: sliding window, adaptive RTO.
See ADR-0005 and the limitations section of the README.

The receiver is the interesting side. A lost ACK makes the sender retransmit a request
that was already executed. Without deduplication the protocol stops being idempotent, so
the receiver keeps a window of recently seen sequence numbers together with the reply each
produced, and replays that reply for a duplicate instead of running the handler again.
"""

from __future__ import annotations

import asyncio
import logging
import random
from collections import OrderedDict
from collections.abc import Callable
from types import TracebackType
from typing import Any, cast

from wireline.protocol import messages
from wireline.protocol.codec import (
    FLAG_REQUIRE_ACK,
    FLAG_RETRANSMIT,
    MAX_SEQ,
    Frame,
    MsgType,
    decode,
    encode,
)
from wireline.protocol.errors import ErrorCode, ProtocolError
from wireline.session import ServerSession, State
from wireline.transport.framing import FrameBuffer

log = logging.getLogger("wireline.udp")

DEFAULT_RTO = 0.5
DEFAULT_MAX_RETRIES = 5
DEFAULT_DEDUP_WINDOW = 256

# Wraps the raw sendto callable and returns another one. Tests use it to drop datagrams.
SendHook = Callable[[Callable[[bytes, Any], None]], Callable[[bytes, Any], None]]


class LossyLink:
    """Drops a fraction of outgoing datagrams.

    The random generator is injected, so a test of probabilistic behaviour stays
    deterministic: same seed, same datagrams dropped, same assertions.
    """

    def __init__(self, loss_rate: float, rng: random.Random) -> None:
        self.loss_rate = loss_rate
        self.rng = rng
        self.dropped = 0

    def __call__(self, inner: Callable[[bytes, Any], None]) -> Callable[[bytes, Any], None]:
        def sendto(data: bytes, addr: Any = None) -> None:
            if self.rng.random() < self.loss_rate:
                self.dropped += 1
                return  # silently, exactly like a real network
            inner(data, addr)

        return sendto


class DedupWindow:
    """The last N sequence numbers from one peer, with the reply each of them produced."""

    def __init__(self, size: int = DEFAULT_DEDUP_WINDOW) -> None:
        self._size = size
        self._entries: OrderedDict[int, bytes] = OrderedDict()

    def get(self, seq: int) -> bytes | None:
        return self._entries.get(seq)

    def put(self, seq: int, reply: bytes) -> None:
        self._entries[seq] = reply
        self._entries.move_to_end(seq)
        while len(self._entries) > self._size:
            self._entries.popitem(last=False)

    def __contains__(self, seq: int) -> bool:
        return seq in self._entries

    def __len__(self) -> int:
        return len(self._entries)


def split_datagram(data: bytes, secret: bytes) -> list[Frame]:
    """One datagram may carry an ACK and a reply back to back."""
    buffer = FrameBuffer(secret)
    buffer.feed(data)
    frames = list(buffer.drain())
    if len(buffer):
        raise ProtocolError(ErrorCode.ERR_LENGTH, f"{len(buffer)} trailing bytes in datagram")
    return frames


class _ServerProtocol(asyncio.DatagramProtocol):
    def __init__(self, server: UdpServer) -> None:
        self._server = server

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._server._attach(cast(asyncio.DatagramTransport, transport))

    def datagram_received(self, data: bytes, addr: Any) -> None:
        self._server._on_datagram(data, addr)

    def error_received(self, exc: Exception) -> None:  # pragma: no cover - ICMP noise
        log.info("udp error: %s", exc)


class UdpServer:
    """One session per peer address, with deduplication in front of the session."""

    def __init__(
        self,
        secret: bytes,
        host: str = "127.0.0.1",
        port: int = 9001,
        *,
        dedup_window: int = DEFAULT_DEDUP_WINDOW,
        send_hook: SendHook | None = None,
    ) -> None:
        self._secret = secret
        self._host = host
        self._port = port
        self._dedup_size = dedup_window
        self._send_hook = send_hook
        self._transport: asyncio.DatagramTransport | None = None
        self._sendto: Callable[[bytes, Any], None] | None = None
        # The dedup window belongs to the session: a new session from the same address
        # must not be answered from the previous session's cache.
        self._peers: dict[Any, tuple[ServerSession, DedupWindow]] = {}
        # counters that make the idempotence assertions in the tests possible
        self.duplicates = 0
        self.handled = 0

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        await loop.create_datagram_endpoint(
            lambda: _ServerProtocol(self), local_addr=(self._host, self._port)
        )

    def _attach(self, transport: asyncio.DatagramTransport) -> None:
        self._transport = transport
        raw = transport.sendto
        self._sendto = self._send_hook(raw) if self._send_hook else raw

    @property
    def address(self) -> tuple[str, int]:
        if self._transport is None:
            raise RuntimeError("server is not started")
        host, port, *_ = self._transport.get_extra_info("sockname")
        return str(host), int(port)

    def close(self) -> None:
        if self._transport is not None:
            self._transport.close()
            self._transport = None

    async def __aenter__(self) -> UdpServer:
        await self.start()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    # -- receive path ------------------------------------------------------

    def _on_datagram(self, data: bytes, addr: Any) -> None:
        assert self._sendto is not None
        try:
            frame = decode(data, self._secret)
        except ProtocolError as exc:
            # Unlike TCP there is no connection to close. The source address of a datagram
            # that failed its checks is not authenticated, so answering it or dropping the
            # session it names would let anyone who can spoof the address tear down a live
            # peer. Drop the datagram and keep no state for it.
            log.warning("udp %s: dropped: %s", addr, exc)
            return

        if addr not in self._peers:
            self._peers[addr] = (ServerSession(), DedupWindow(self._dedup_size))
        session, dedup = self._peers[addr]

        cached = dedup.get(frame.seq)
        if cached is not None:
            # A retransmission of something already executed. Replay the stored reply
            # instead of running the handler a second time.
            self.duplicates += 1
            log.info("udp %s: duplicate seq %s, replaying reply", addr, frame.seq)
            if cached:
                self._sendto(cached, addr)
            return

        # The ACK and the reply travel in one datagram, ACK first, so the client can tell
        # which request a datagram answers. The stored bytes are what a duplicate gets.
        acks = [session.ack(frame.seq)] if frame.flags & FLAG_REQUIRE_ACK else []
        reaction = session.on_frame(frame)
        self.handled += 1
        reply = b"".join(encode(f, self._secret) for f in (*acks, *reaction.frames))
        if reply:
            self._sendto(reply, addr)
        dedup.put(frame.seq, reply)
        if reaction.close:
            del self._peers[addr]


class _ClientProtocol(asyncio.DatagramProtocol):
    def __init__(self, queue: asyncio.Queue[bytes]) -> None:
        self._queue = queue

    def datagram_received(self, data: bytes, addr: Any) -> None:
        self._queue.put_nowait(data)

    def error_received(self, exc: Exception) -> None:  # pragma: no cover - ICMP noise
        log.info("udp error: %s", exc)


class UdpClient:
    """Stop-and-wait sender: one request in flight, retransmit until answered."""

    def __init__(
        self,
        secret: bytes,
        host: str = "127.0.0.1",
        port: int = 9001,
        *,
        client_id: str = "wireline-udp",
        rto: float = DEFAULT_RTO,
        max_retries: int = DEFAULT_MAX_RETRIES,
        send_hook: SendHook | None = None,
    ) -> None:
        self._secret = secret
        self._addr = (host, port)
        self._client_id = client_id
        self._rto = rto
        self._max_retries = max_retries
        self._send_hook = send_hook
        self._transport: asyncio.DatagramTransport | None = None
        self._queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._sendto: Callable[[bytes, Any], None] | None = None
        self._out_seq = 0
        self.state = State.NEW
        self.session_id: str | None = None
        self.retransmits = 0

    async def connect(self) -> None:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _ClientProtocol(self._queue), remote_addr=self._addr
        )
        self._transport = transport
        raw = transport.sendto
        self._sendto = self._send_hook(raw) if self._send_hook else raw
        self.state = State.HANDSHAKE
        reply = await self.request(MsgType.HELLO, messages.encode_hello(self._client_id))
        if reply.msg_type is not MsgType.HELLO_ACK:
            raise ProtocolError(
                ErrorCode.ERR_STATE, f"expected HELLO_ACK, got {reply.msg_type.name}"
            )
        self.session_id, _ = messages.decode_hello_ack(reply.payload)
        self.state = State.READY

    def close(self) -> None:
        if self._transport is not None:
            self._transport.close()
            self._transport = None
        self.state = State.CLOSED

    async def __aenter__(self) -> UdpClient:
        await self.connect()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    async def send_data(self, payload: bytes) -> bytes:
        return (await self.request(MsgType.DATA, payload)).payload

    async def request(self, msg_type: MsgType, payload: bytes = b"") -> Frame:
        """Send one message and wait for its reply, retransmitting on timeout."""
        if self._sendto is None:
            raise ProtocolError(ErrorCode.ERR_STATE, "client is not connected")
        seq = self._out_seq
        self._out_seq = (self._out_seq + 1) & MAX_SEQ

        for attempt in range(self._max_retries + 1):
            flags = FLAG_REQUIRE_ACK | (FLAG_RETRANSMIT if attempt else 0)
            self._sendto(encode(Frame(msg_type, seq, payload, flags), self._secret), None)
            if attempt:
                self.retransmits += 1
            try:
                return await asyncio.wait_for(self._await_reply(seq), timeout=self._rto)
            except TimeoutError:
                # A lost request and a lost reply look identical from here, and the
                # answer to both is the same: send it again. The receiver deduplicates,
                # so resending cannot execute the request twice.
                log.info("udp seq %s: no reply within %.2fs, retrying", seq, self._rto)
        raise ProtocolError(
            ErrorCode.ERR_TIMEOUT,
            f"no reply for seq {seq} after {self._max_retries} retries",
        )

    async def _await_reply(self, seq: int) -> Frame:
        """Read datagrams until the answer to `seq` arrives.

        An answer starts with an ACK naming the request. Anything else is a late copy of
        an earlier answer (the reply crossed a retransmission) or was not sent by the
        server, and returning it would hand this request someone else's reply.
        """
        while True:
            data = await self._queue.get()
            try:
                frames = split_datagram(data, self._secret)
                answers_seq = (
                    frames[0].msg_type is MsgType.ACK
                    and messages.decode_ack(frames[0].payload) == seq
                )
            except ProtocolError as exc:
                log.warning("udp seq %s: dropped undecodable datagram: %s", seq, exc)
                continue
            if not answers_seq:
                log.info("udp seq %s: dropped a datagram that answers another request", seq)
                continue
            reply = frames[-1]  # the ACK itself when the message has no reply
            if reply.msg_type is MsgType.ERROR:
                code, message = messages.decode_error(reply.payload)
                raise ProtocolError(ErrorCode(code), message)
            return reply
