from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from wireline.protocol.codec import (
    HEADER,
    MAC_SIZE,
    MAX_PAYLOAD,
    Frame,
    MsgType,
    decode,
    decode_header,
    encode,
)
from wireline.protocol.errors import ErrorCode, ProtocolError

SECRET = b"unit-secret"


@given(
    payload=st.binary(max_size=2048),
    seq=st.integers(min_value=0, max_value=2**32 - 1),
    msg_type=st.sampled_from(list(MsgType)),
)
@settings(max_examples=200)
def test_header_roundtrip(payload: bytes, seq: int, msg_type: MsgType) -> None:
    raw = encode(Frame(msg_type, seq, payload), SECRET)
    header = decode_header(raw[: HEADER.size])
    assert (header.msg_type, header.seq, header.length) == (msg_type, seq, len(payload))
    assert len(raw) == HEADER.size + len(payload) + MAC_SIZE


@given(payload=st.binary(max_size=4096))
@settings(max_examples=100)
def test_frame_roundtrip(payload: bytes) -> None:
    frame = Frame(MsgType.DATA, 7, payload)
    assert decode(encode(frame, SECRET), SECRET) == frame


def test_header_size_is_19_bytes() -> None:
    # The spec pins the offsets; a silent struct change would break every peer.
    assert HEADER.size == 19


def test_rejects_bad_magic() -> None:
    raw = bytearray(encode(Frame(MsgType.PING, 0), SECRET))
    raw[0] = ord("X")
    with pytest.raises(ProtocolError) as exc:
        decode_header(bytes(raw[: HEADER.size]))
    assert exc.value.code is ErrorCode.ERR_MAGIC


def test_rejects_unsupported_version() -> None:
    raw = bytearray(encode(Frame(MsgType.PING, 0), SECRET))
    raw[4] = 99
    with pytest.raises(ProtocolError) as exc:
        decode_header(bytes(raw[: HEADER.size]))
    assert exc.value.code is ErrorCode.ERR_VERSION


def test_rejects_unknown_message_type() -> None:
    raw = bytearray(encode(Frame(MsgType.PING, 0), SECRET))
    raw[5] = 200
    with pytest.raises(ProtocolError) as exc:
        decode_header(bytes(raw[: HEADER.size]))
    assert exc.value.code is ErrorCode.ERR_TYPE


@pytest.mark.security
def test_rejects_oversized_length_before_allocation() -> None:
    """A 19-byte header must not be able to request a 4 GiB buffer."""
    raw = bytearray(encode(Frame(MsgType.DATA, 1, b"x"), SECRET))
    raw[11:15] = (2**32 - 1).to_bytes(4, "big")
    with pytest.raises(ProtocolError) as exc:
        decode_header(bytes(raw[: HEADER.size]))
    assert exc.value.code is ErrorCode.ERR_LENGTH
    assert "limit" in exc.value.message


@pytest.mark.security
def test_encode_refuses_payload_over_the_limit() -> None:
    with pytest.raises(ProtocolError) as exc:
        encode(Frame(MsgType.DATA, 0, b"\x00" * (MAX_PAYLOAD + 1)), SECRET)
    assert exc.value.code is ErrorCode.ERR_LENGTH


def test_detects_corrupted_payload_via_crc() -> None:
    raw = bytearray(encode(Frame(MsgType.DATA, 1, b"payload"), SECRET))
    raw[HEADER.size] ^= 0xFF  # flip a bit in the body
    with pytest.raises(ProtocolError) as exc:
        decode(bytes(raw), SECRET)
    assert exc.value.code is ErrorCode.ERR_CRC


@pytest.mark.security
def test_detects_tampering_with_a_recomputed_crc() -> None:
    """CRC can be recomputed by an attacker; the MAC is what actually stops this."""
    import zlib

    original = Frame(MsgType.DATA, 1, b"transfer 10")
    raw = bytearray(encode(original, SECRET))
    forged = b"transfer 99"
    raw[HEADER.size : HEADER.size + len(forged)] = forged
    raw[15:19] = (zlib.crc32(forged) & 0xFFFFFFFF).to_bytes(4, "big")
    with pytest.raises(ProtocolError) as exc:
        decode(bytes(raw), SECRET)
    assert exc.value.code is ErrorCode.ERR_AUTH


@pytest.mark.security
def test_wrong_secret_fails_authentication() -> None:
    raw = encode(Frame(MsgType.DATA, 1, b"hi"), SECRET)
    with pytest.raises(ProtocolError) as exc:
        decode(raw, b"another-secret")
    assert exc.value.code is ErrorCode.ERR_AUTH


def test_rejects_reserved_flag_bits() -> None:
    with pytest.raises(ProtocolError) as exc:
        encode(Frame(MsgType.DATA, 0, b"", flags=0x80), SECRET)
    assert exc.value.code is ErrorCode.ERR_FLAGS


def test_rejects_short_header() -> None:
    with pytest.raises(ProtocolError) as exc:
        decode_header(b"WIRE\x01")
    assert exc.value.code is ErrorCode.ERR_LENGTH


def test_rejects_truncated_frame() -> None:
    raw = encode(Frame(MsgType.DATA, 1, b"abcdef"), SECRET)
    with pytest.raises(ProtocolError) as exc:
        decode(raw[:-4], SECRET)
    assert exc.value.code is ErrorCode.ERR_LENGTH
