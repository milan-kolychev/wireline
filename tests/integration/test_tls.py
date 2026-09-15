"""TLS tests.

Two questions are answered here and they are not the same question. TLS answers "is this
host the one it claims to be"; the Wireline handshake answers "does this peer hold the
shared key". A test suite that only checks the happy path proves neither.
"""

from __future__ import annotations

import asyncio
import ssl
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from tools.make_certs import make_self_signed

from tests.conftest import SECRET
from wireline.client import WirelineClient
from wireline.protocol.codec import MsgType
from wireline.server import WirelineServer
from wireline.tls import client_context, server_context


@pytest.fixture(scope="session")
def certs(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    """One throwaway certificate for the whole session: RSA keygen is not free."""
    return make_self_signed(tmp_path_factory.mktemp("certs"))


@pytest.fixture
async def tls_server(certs: tuple[Path, Path]) -> AsyncIterator[WirelineServer]:
    cert, key = certs
    srv = WirelineServer(
        SECRET,
        "127.0.0.1",
        0,
        idle_timeout=5.0,
        handshake_timeout=5.0,
        ssl_context=server_context(cert, key),
    )
    await srv.start()
    try:
        yield srv
    finally:
        await srv.close()


async def test_handshake_over_tls(
    tls_server: WirelineServer, certs: tuple[Path, Path]
) -> None:
    cert, _ = certs
    client = WirelineClient(
        SECRET,
        *tls_server.address,
        ssl_context=client_context(cert),
        server_hostname="localhost",
        timeout=5.0,
    )
    async with client:
        assert (await client.ping(b"encrypted")).msg_type is MsgType.PONG
        assert await client.send_data(b"body") == b"body"


@pytest.mark.security
async def test_untrusted_certificate_is_refused(tls_server: WirelineServer) -> None:
    """Default verification must reject the self-signed certificate when it is not
    explicitly trusted. If this passes silently, the transport is not authenticated."""
    client = WirelineClient(
        SECRET,
        *tls_server.address,
        ssl_context=client_context(),  # system trust store only
        server_hostname="localhost",
        timeout=5.0,
    )
    with pytest.raises(ssl.SSLCertVerificationError):
        await client.connect()


@pytest.mark.security
async def test_hostname_mismatch_is_refused(
    tls_server: WirelineServer, certs: tuple[Path, Path]
) -> None:
    cert, _ = certs
    client = WirelineClient(
        SECRET,
        *tls_server.address,
        ssl_context=client_context(cert),
        server_hostname="not-the-lab-host",
        timeout=5.0,
    )
    with pytest.raises(ssl.SSLCertVerificationError):
        await client.connect()


@pytest.mark.security
async def test_plaintext_client_cannot_talk_to_a_tls_listener(
    tls_server: WirelineServer,
) -> None:
    """A Wireline HELLO sent in the clear is not a TLS ClientHello, so the connection
    dies below the protocol.

    The observable result is `IncompleteReadError: 0 bytes read on a total of 19 expected`
    - the listener closed the socket without sending a single byte. That is the signature
    of a failure at L6, and it is worth recognising: an application-layer bug would have
    produced an ERROR frame instead."""
    client = WirelineClient(SECRET, *tls_server.address, timeout=2.0)
    with pytest.raises(
        (asyncio.IncompleteReadError, TimeoutError, ConnectionError, OSError)
    ):
        await client.connect()
    await client.close()


def test_contexts_pin_a_minimum_tls_version(certs: tuple[Path, Path]) -> None:
    cert, key = certs
    assert server_context(cert, key).minimum_version is ssl.TLSVersion.TLSv1_2
    assert client_context(cert).minimum_version is ssl.TLSVersion.TLSv1_2


def test_verify_false_is_explicit_about_what_it_disables() -> None:
    context = client_context(verify=False)
    assert context.check_hostname is False
    assert context.verify_mode is ssl.CERT_NONE
