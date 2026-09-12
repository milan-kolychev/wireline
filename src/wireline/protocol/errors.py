"""Protocol level errors.

A single exception type carrying a machine readable code. The code is what goes on the
wire inside an ERROR frame; the message is for humans and logs.
"""

from __future__ import annotations

from enum import IntEnum


class ErrorCode(IntEnum):
    """Codes defined in docs/PROTOCOL.md section 6."""

    ERR_VERSION = 1
    ERR_MAGIC = 2
    ERR_LENGTH = 3
    ERR_CRC = 4
    ERR_AUTH = 5
    ERR_TYPE = 6
    ERR_STATE = 7
    ERR_SEQ = 8
    ERR_FLAGS = 9
    ERR_TIMEOUT = 10
    ERR_INTERNAL = 99


class ProtocolError(Exception):
    """A frame or a transition violates the specification."""

    def __init__(self, code: ErrorCode, message: str) -> None:
        super().__init__(f"{code.name}: {message}")
        self.code = code
        self.message = message
