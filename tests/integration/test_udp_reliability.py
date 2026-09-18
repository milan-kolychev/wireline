"""UDP reliability tests.

Loss is emulated with a seeded random generator, so a probabilistic property is asserted
deterministically: same seed, same dropped datagrams, same result on every run.
"""

from __future__ import annotations

import asyncio
import random
from collections.abc import Callable
from typing import Any

import pytest

from tests.conftest import SECRET
from wireline.protocol import messages
from wireline.protocol.codec import FLAG_REQUIRE_ACK, Frame, MsgType, encode
from wireline.protocol.errors import ErrorCode, ProtocolError
from wireline.transport.udp import DedupWindow, LossyLink, UdpClient, UdpServer, split_datagram

SendTo = Callable[[bytes, Any], None]


class DelayedLink:
    """Delivers every datagram, late. A slow path, not a lossy one."""

    def __init__(self, delay: float) -> None:
        self.delay = delay

    def __call__(self, inner: SendTo) -> SendTo:
        loop = asyncio.get_running_loop()

        def sendto(data: bytes, addr: Any = None) -> None:
            loop.call_later(self.delay, inner, data, addr)

        return sendto


class RawUdpPeer(asyncio.DatagramProtocol):
    """Speaks the wire format from one fixed local port, without the client logic."""

    def __init__(self) -> None:
        self.replies: asyncio.Queue[bytes] = asyncio.Queue()
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.DatagramTransport)
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Any) -> None:
        self.replies.put_nowait(data)

    async def rpc(self, msg_type: MsgType, seq: int, payload: bytes = b"") -> bytes:
        assert self.transport is not None
        self.transport.sendto(encode(Frame(msg_type, seq, payload, FLAG_REQUIRE_ACK), SECRET))
        return await asyncio.wait_for(self.replies.get(), timeout=1.0)


async def raw_peer(address: tuple[str, int]) -> RawUdpPeer:
    loop = asyncio.get_running_loop()
    _, peer = await loop.create_datagram_endpoint(RawUdpPeer, remote_addr=address)
    return peer


async def test_handshake_and_echo_without_loss() -> None:
    async with UdpServer(SECRET, "127.0.0.1", 0) as server:
        async with UdpClient(SECRET, *server.address, rto=0.5) as client:
            assert client.session_id
            assert await client.send_data(b"over udp") == b"over udp"
            assert client.retransmits == 0


async def test_delivery_survives_forty_percent_loss() -> None:
    """Request or reply may vanish; stop-and-wait must still complete."""
    link = LossyLink(loss_rate=0.4, rng=random.Random(20260909))
    async with UdpServer(SECRET, "127.0.0.1", 0, send_hook=link) as server, UdpClient(
        SECRET, *server.address, rto=0.1, max_retries=20, send_hook=link
    ) as client:
        for i in range(10):
            assert await client.send_data(f"msg-{i}".encode()) == f"msg-{i}".encode()
    assert link.dropped > 0, "the test proved nothing if nothing was dropped"
    assert client.retransmits > 0


async def test_a_retransmitted_request_is_executed_once() -> None:
    """The idempotence property: duplicates are answered, not re-run."""
    # Drop everything the server sends for the first attempts, so the client retransmits
    # a request the server has already handled.
    class DropFirstReplies:
        def __init__(self, count: int) -> None:
            self.remaining = count

        def __call__(self, inner):  # type: ignore[no-untyped-def]
            def sendto(data: bytes, addr=None) -> None:  # type: ignore[no-untyped-def]
                if self.remaining > 0:
                    self.remaining -= 1
                    return
                inner(data, addr)

            return sendto

    hook = DropFirstReplies(count=1)  # only the HELLO_ACK is lost
    async with UdpServer(SECRET, "127.0.0.1", 0, send_hook=hook) as server:
        async with UdpClient(SECRET, *server.address, rto=0.1, max_retries=5) as client:
            assert client.retransmits >= 1
            assert server.duplicates >= 1, "the duplicate was not recognised"
            assert await client.send_data(b"still working") == b"still working"
            # HELLO arrived at least twice, DATA once; the session handled each once
            assert server.handled == 2


async def test_duplicate_reply_is_byte_identical() -> None:
    """A replayed answer must be the same bytes, not a freshly generated one."""
    async with UdpServer(SECRET, "127.0.0.1", 0) as server:
        peer = await raw_peer(server.address)
        await peer.rpc(MsgType.HELLO, 0, messages.encode_hello("raw"))
        first = await peer.rpc(MsgType.DATA, 1, b"once")
        again = await peer.rpc(MsgType.DATA, 1, b"once")
        assert again == first
        assert server.handled == 2
        assert peer.transport is not None
        peer.transport.close()


async def test_a_late_reply_is_not_taken_for_the_next_one() -> None:
    """Regression: replies slower than the RTO used to shift every answer by one.

    The client retransmits, the server replays its cached reply, and two copies of the
    same answer arrive. The second copy must be dropped, not returned to the next request.
    """
    async with UdpServer(SECRET, "127.0.0.1", 0, send_hook=DelayedLink(0.15)) as server:
        async with UdpClient(SECRET, *server.address, rto=0.1, max_retries=5) as client:
            first = await client.send_data(b"first")
            await asyncio.sleep(0.3)  # the replayed copy of "first" lands in the queue
            second = await client.send_data(b"second")
    assert (first, second) == (b"first", b"second")
    assert client.retransmits > 0 and server.duplicates > 0, "no late reply was produced"


async def test_a_new_session_is_not_answered_from_the_old_cache() -> None:
    """Regression: the dedup window used to outlive the session it belonged to."""
    async with UdpServer(SECRET, "127.0.0.1", 0) as server:
        peer = await raw_peer(server.address)
        old_ack = await peer.rpc(MsgType.HELLO, 0, messages.encode_hello("old"))
        await peer.rpc(MsgType.DATA, 1, b"old")
        await peer.rpc(MsgType.BYE, 2)
        # same local port, fresh session: seq starts again from 0
        new_ack = await peer.rpc(MsgType.HELLO, 0, messages.encode_hello("new"))
        reply = split_datagram(await peer.rpc(MsgType.DATA, 1, b"new"), SECRET)[-1]
        assert new_ack != old_ack
        assert reply.payload == b"new"
        assert peer.transport is not None
        peer.transport.close()


def test_dedup_window_evicts_oldest_first() -> None:
    window = DedupWindow(size=3)
    for seq in range(5):
        window.put(seq, f"reply-{seq}".encode())
    assert len(window) == 3
    assert 0 not in window and 1 not in window
    assert window.get(4) == b"reply-4"


async def test_client_gives_up_after_max_retries() -> None:
    """A silent peer must not block forever."""
    link = LossyLink(loss_rate=1.0, rng=random.Random(1))  # nothing gets through
    async with UdpServer(SECRET, "127.0.0.1", 0) as server:
        client = UdpClient(
            SECRET, *server.address, rto=0.05, max_retries=2, send_hook=link
        )
        with pytest.raises(ProtocolError) as exc:
            await client.connect()
        assert exc.value.code is ErrorCode.ERR_TIMEOUT
        client.close()


@pytest.mark.security
async def test_datagram_with_a_wrong_mac_is_dropped_without_touching_the_session() -> None:
    """The source address of a forged datagram is not authenticated. If a bad MAC closed
    the session, anyone able to spoof the client's address could tear it down."""
    async with UdpServer(SECRET, "127.0.0.1", 0) as server:
        async with UdpClient(SECRET, *server.address, rto=0.2) as client:
            assert client._sendto is not None
            client._sendto(encode(Frame(MsgType.PING, 99), b"wrong-secret"), None)
            await asyncio.sleep(0.05)
            assert await client.send_data(b"after the bad one") == b"after the bad one"
            assert server.handled == 2  # HELLO and DATA; the forged PING never ran


@pytest.mark.security
async def test_unauthenticated_datagrams_leave_no_state_behind() -> None:
    """Per-peer state is created only for a frame that passed its MAC check."""
    async with UdpServer(SECRET, "127.0.0.1", 0) as server:
        peers = [await raw_peer(server.address) for _ in range(10)]
        for peer in peers:
            assert peer.transport is not None
            peer.transport.sendto(b"not a wireline frame")
        await asyncio.sleep(0.05)
        assert server._peers == {}
        for peer in peers:
            assert peer.transport is not None
            peer.transport.close()


async def test_garbage_datagram_does_not_kill_the_server() -> None:
    async with UdpServer(SECRET, "127.0.0.1", 0) as server:
        async with UdpClient(SECRET, *server.address, rto=0.2) as client:
            assert client._sendto is not None
            client._sendto(b"not a wireline frame at all", None)
        async with UdpClient(SECRET, *server.address, rto=0.5) as second:
            assert await second.send_data(b"still alive") == b"still alive"
