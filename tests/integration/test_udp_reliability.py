"""UDP reliability tests.

Loss is emulated with a seeded random generator, so a probabilistic property is asserted
deterministically: same seed, same dropped datagrams, same result on every run.
"""

from __future__ import annotations

import random

import pytest

from tests.conftest import SECRET
from wireline.protocol.codec import Frame, MsgType, encode
from wireline.protocol.errors import ErrorCode, ProtocolError
from wireline.transport.udp import DedupWindow, LossyLink, UdpClient, UdpServer


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
            # HELLO was received twice but the session was created once
            assert await client.send_data(b"still working") == b"still working"


async def test_duplicate_reply_is_byte_identical() -> None:
    """A replayed answer must be the same bytes, not a freshly generated one."""
    window = DedupWindow(size=4)
    reply = encode(Frame(MsgType.PONG, 1, b"x"), SECRET)
    window.put(1, reply)
    assert window.get(1) == reply


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
async def test_datagram_with_a_wrong_mac_is_rejected() -> None:
    async with UdpServer(SECRET, "127.0.0.1", 0) as server:
        async with UdpClient(SECRET, *server.address, rto=0.2) as client:
            assert client._sendto is not None
            client._sendto(encode(Frame(MsgType.PING, 99), b"wrong-secret"), None)
            with pytest.raises(ProtocolError) as exc:
                await client.request(MsgType.PING, b"after-the-bad-one")
            assert exc.value.code is ErrorCode.ERR_AUTH


async def test_garbage_datagram_does_not_kill_the_server() -> None:
    async with UdpServer(SECRET, "127.0.0.1", 0) as server:
        async with UdpClient(SECRET, *server.address, rto=0.2) as client:
            assert client._sendto is not None
            client._sendto(b"not a wireline frame at all", None)
        async with UdpClient(SECRET, *server.address, rto=0.5) as second:
            assert await second.send_data(b"still alive") == b"still alive"
