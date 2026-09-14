"""Runtime configuration.

The shared secret comes from the environment. A default is provided for local runs only
and the code says so out loud, so that nobody ships it by accident.
"""

from __future__ import annotations

import logging
import os
import sys

SECRET_ENV = "WIRELINE_SECRET"
DEV_SECRET = b"dev-secret-not-for-real-use"


def load_secret(explicit: str | None = None) -> bytes:
    if explicit:
        return explicit.encode("utf-8")
    value = os.environ.get(SECRET_ENV)
    if value:
        return value.encode("utf-8")
    logging.getLogger("wireline").warning(
        "%s is not set, falling back to the development secret", SECRET_ENV
    )
    return DEV_SECRET


def setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        stream=sys.stderr,
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s %(message)s",
    )
