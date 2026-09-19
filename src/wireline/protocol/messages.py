"""Payloads of control messages.

Control payloads are JSON: readable in a capture and easy to extend. The envelope stays
binary, because the point of the project is to own the framing, not the serialisation.
"""

from __future__ import annotations

import json
import secrets
from typing import Any

from wireline.protocol.errors import ErrorCode, ProtocolError

NONCE_BYTES = 16


def new_nonce() -> str:
    return secrets.token_hex(NONCE_BYTES)


def _dump(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _load(payload: bytes) -> dict[str, Any]:
    try:
        obj = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError(ErrorCode.ERR_LENGTH, f"malformed json payload: {exc}") from exc
    if not isinstance(obj, dict):
        raise ProtocolError(ErrorCode.ERR_LENGTH, "control payload must be an object")
    return obj


def encode_hello(client_id: str, nonce: str | None = None) -> bytes:
    return _dump({"client_id": client_id, "nonce": nonce or new_nonce()})


def decode_hello(payload: bytes) -> tuple[str, str]:
    obj = _load(payload)
    client_id, nonce = obj.get("client_id"), obj.get("nonce")
    if not isinstance(client_id, str) or not isinstance(nonce, str):
        raise ProtocolError(ErrorCode.ERR_STATE, "hello requires client_id and nonce")
    return client_id, nonce


def encode_hello_ack(session_id: str, nonce: str | None = None) -> bytes:
    return _dump({"session_id": session_id, "nonce": nonce or new_nonce()})


def decode_hello_ack(payload: bytes) -> tuple[str, str]:
    obj = _load(payload)
    session_id, nonce = obj.get("session_id"), obj.get("nonce")
    if not isinstance(session_id, str) or not isinstance(nonce, str):
        raise ProtocolError(ErrorCode.ERR_STATE, "hello_ack requires session_id and nonce")
    return session_id, nonce


def encode_error(code: ErrorCode, message: str) -> bytes:
    return _dump({"code": int(code), "message": message})


def decode_error(payload: bytes) -> tuple[ErrorCode, str]:
    """The payload comes from the peer: a code outside section 6 becomes ERR_INTERNAL."""
    obj = _load(payload)
    raw, message = obj.get("code"), str(obj.get("message", ""))
    if not isinstance(raw, int):
        raise ProtocolError(ErrorCode.ERR_STATE, "error requires an integer code")
    try:
        return ErrorCode(raw), message
    except ValueError:
        return ErrorCode.ERR_INTERNAL, f"unknown error code {raw}: {message}"


def encode_ack(ack_seq: int) -> bytes:
    return _dump({"ack_seq": ack_seq})


def decode_ack(payload: bytes) -> int:
    obj = _load(payload)
    ack_seq = obj.get("ack_seq")
    if not isinstance(ack_seq, int):
        raise ProtocolError(ErrorCode.ERR_STATE, "ack requires an integer ack_seq")
    return ack_seq
