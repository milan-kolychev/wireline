"""Integration tests against a real listener on an ephemeral port.

These cover what unit tests cannot: actual segment boundaries, actual timeouts, actual
connection teardown.
"""

from __future__ import annotations

import asyncio

import pytest

from tests.conftest import SECRET, RawPeer
from wireline.client import WirelineClient
from wireline.protocol import messages
from wireline.protocol.codec import Frame, MsgType, encode
from wireline.protocol.errors import ErrorCode, ProtocolError
from wireline.server import WirelineServer
from wireline.session import State


async def test_client_handshake_and_ping(server: WirelineServer) -> None:
    async with WirelineClient(SECRET, *server.address) as client:
        assert client.state is State.READY
        assert client.session_id
        pong = await client.ping(b"probe")
        assert pong.msg_type is MsgType.PONG
        assert pong.payload == b"probe"


async def test_data_is_echoed(server: WirelineServer) -> None:
    async with WirelineClient(SECRET, *server.address) as client:
        assert await client.send_data(b"round trip") == b"round trip"


async def test_split_frame_is_reassembled(server: WirelineServer, peer: RawPeer) -> None:
    """A frame delivered in two TCP writes must still be parsed as one message.

    The sleep between the writes forces two separate segments, which is exactly the
    situation that a naive `read(n)` implementation gets wrong.
    """
    await peer.handshake()
    raw = encode(Frame(MsgType.PING, 1, b"x" * 100), SECRET)
    await peer.write_bytes(raw[:10])
    await asyncio.sleep(0.05)
    await peer.write_bytes(raw[10:37])
    await asyncio.sleep(0.05)
    await peer.write_bytes(raw[37:])
    response = await peer.recv()
    assert response.msg_type is MsgType.PONG
    assert response.payload == b"x" * 100


async def test_two_frames_in_one_write_are_both_handled(
    server: WirelineServer, peer: RawPeer
) -> None:
    await peer.handshake()
    batch = encode(Frame(MsgType.PING, 1, b"a"), SECRET) + encode(
        Frame(MsgType.PING, 2, b"b"), SECRET
    )
    await peer.write_bytes(batch)
    assert (await peer.recv()).payload == b"a"
    assert (await peer.recv()).payload == b"b"


async def test_data_before_handshake_is_rejected(
    server: WirelineServer, peer: RawPeer
) -> None:
    await peer.send(Frame(MsgType.DATA, 0, b"payload"))
    response = await peer.recv()
    assert response.msg_type is MsgType.ERROR
    code, _ = messages.decode_error(response.payload)
    assert code == ErrorCode.ERR_STATE
    with pytest.raises(asyncio.IncompleteReadError):
        await asyncio.wait_for(peer.reader.readexactly(1), timeout=2.0)


async def test_second_handshake_is_rejected(server: WirelineServer, peer: RawPeer) -> None:
    await peer.handshake()
    await peer.send(Frame(MsgType.HELLO, 1, messages.encode_hello("again")))
    response = await peer.recv()
    code, _ = messages.decode_error(response.payload)
    assert code == ErrorCode.ERR_STATE


@pytest.mark.security
async def test_frame_signed_with_the_wrong_secret_is_rejected(
    server: WirelineServer, peer: RawPeer
) -> None:
    await peer.handshake()
    await peer.write_bytes(encode(Frame(MsgType.PING, 1), b"wrong-secret"))
    response = await peer.recv()
    code, _ = messages.decode_error(response.payload)
    assert code == ErrorCode.ERR_AUTH


@pytest.mark.security
async def test_replayed_frame_is_rejected(server: WirelineServer, peer: RawPeer) -> None:
    await peer.handshake()
    raw = encode(Frame(MsgType.PING, 1, b"once"), SECRET)
    await peer.write_bytes(raw)
    assert (await peer.recv()).msg_type is MsgType.PONG
    await peer.write_bytes(raw)  # byte-for-byte capture replay
    response = await peer.recv()
    code, _ = messages.decode_error(response.payload)
    assert code == ErrorCode.ERR_SEQ


@pytest.mark.security
@pytest.mark.xfail(
    strict=True,
    reason="known gap: the HELLO nonces are exchanged but not bound into the MAC "
    "(PROTOCOL.md 8.4). Remove this marker together with the fix.",
)
async def test_a_session_replayed_from_a_capture_is_rejected(
    server: WirelineServer, peer: RawPeer
) -> None:
    """Every frame of an earlier session, replayed byte for byte on a new connection.

    Sequence numbers restart at 0 per connection and the MAC key is the same pre-shared
    key in every session, so nothing distinguishes these bytes from a fresh session.
    """
    captured = [
        encode(Frame(MsgType.HELLO, 0, messages.encode_hello("victim")), SECRET),
        encode(Frame(MsgType.DATA, 1, b"transfer 100"), SECRET),
    ]
    for raw in captured:  # the attacker never needs SECRET, only the capture
        await peer.write_bytes(raw)
    assert (await peer.recv()).msg_type is MsgType.HELLO_ACK
    assert (await peer.recv()).msg_type is not MsgType.DATA, "replayed DATA was executed"


async def test_garbage_does_not_kill_the_listener(
    server: WirelineServer, peer: RawPeer
) -> None:
    await peer.write_bytes(b"GET / HTTP/1.1\r\nHost: lab.local\r\n\r\n")
    response = await peer.recv()
    code, _ = messages.decode_error(response.payload)
    assert code == ErrorCode.ERR_MAGIC
    # the server is still accepting connections
    async with WirelineClient(SECRET, *server.address) as client:
        assert (await client.ping()).msg_type is MsgType.PONG


@pytest.mark.security
async def test_oversized_length_does_not_allocate(
    server: WirelineServer, peer: RawPeer
) -> None:
    """19 bytes claiming a 4 GiB body must be refused, not buffered."""
    await peer.handshake()
    raw = bytearray(encode(Frame(MsgType.DATA, 1, b"x"), SECRET))
    raw[11:15] = (2**32 - 1).to_bytes(4, "big")
    await peer.write_bytes(bytes(raw))
    response = await peer.recv()
    code, _ = messages.decode_error(response.payload)
    assert code == ErrorCode.ERR_LENGTH


async def test_handshake_timeout_closes_a_silent_connection(
    server: WirelineServer, peer: RawPeer
) -> None:
    """Server fixture uses handshake_timeout=0.5s."""
    with pytest.raises(asyncio.IncompleteReadError):
        await asyncio.wait_for(peer.reader.readexactly(1), timeout=3.0)


async def test_idle_timeout_closes_an_established_session(
    server: WirelineServer, peer: RawPeer
) -> None:
    """Server fixture uses idle_timeout=1.0s."""
    await peer.handshake()
    with pytest.raises(asyncio.IncompleteReadError):
        await asyncio.wait_for(peer.reader.readexactly(1), timeout=3.0)


async def test_client_reports_a_wrong_secret_as_an_auth_error(
    server: WirelineServer,
) -> None:
    client = WirelineClient(b"not-the-secret", *server.address, timeout=2.0)
    with pytest.raises(ProtocolError) as exc:
        await client.connect()
    assert exc.value.code is ErrorCode.ERR_AUTH
    await client.close()


async def test_fifty_concurrent_clients(server: WirelineServer) -> None:
    async def one(i: int) -> bytes:
        async with WirelineClient(SECRET, *server.address, client_id=f"c{i}") as client:
            return await client.send_data(f"payload-{i}".encode())

    results = await asyncio.gather(*(one(i) for i in range(50)))
    assert results == [f"payload-{i}".encode() for i in range(50)]
    assert server.connections >= 50
