"""TLS helpers.

Wireline does not encrypt anything itself (ADR-0002). It runs inside TLS, which means the
only code needed here is context construction: the certificate handling belongs to the
standard library.

Layer note: TLS sits below the Wireline handshake. By the time a HELLO frame is decoded,
the transport is already encrypted and the peer certificate already validated. The two
handshakes are independent and answer different questions - TLS asks "is this host who it
claims to be", Wireline asks "does this peer hold the shared key".
"""

from __future__ import annotations

import ssl
from pathlib import Path


def server_context(certfile: str | Path, keyfile: str | Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=str(certfile), keyfile=str(keyfile))
    return context


def client_context(cafile: str | Path | None = None, *, verify: bool = True) -> ssl.SSLContext:
    """A client context. `verify=False` exists for a lab with a throwaway certificate and
    says so in the log of whoever reads the code; it is not a default anywhere."""
    context = ssl.create_default_context(cafile=str(cafile) if cafile else None)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context
