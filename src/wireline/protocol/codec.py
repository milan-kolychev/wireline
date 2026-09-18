"""Wire format of a Wireline frame.

Layout (see docs/PROTOCOL.md section 2), all integers big-endian:

     0        4     5     6     7        11       15       19
     +--------+-----+-----+-----+--------+--------+--------+
     | magic  | ver | typ |flags|  seq   | length |  crc32 |
     +--------+-----+-----+-----+--------+--------+--------+
     |                  payload (length bytes)             |
     +-----------------------------------------------------+
     |         hmac-sha256 over header+payload (32)        |
     +-----------------------------------------------------+

The header is parsed separately from the body on purpose: a stream reader has to read the
header first in order to learn how many body bytes to ask for.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
import zlib
from dataclasses import dataclass
from enum import IntEnum
from typing import NamedTuple

from wireline.protocol.errors import ErrorCode, ProtocolError

MAGIC = b"WIRE"
VERSION = 1

# 4s magic, B version, B type, B flags, I seq, I length, I crc  ->  19 bytes
HEADER = struct.Struct("!4sBBBIII")
MAC_SIZE = hashlib.sha256().digest_size  # 32
MAX_PAYLOAD = 1 << 20  # 1 MiB
MAX_SEQ = (1 << 32) - 1

FLAG_REQUIRE_ACK = 0x01
FLAG_RETRANSMIT = 0x02
FLAG_COMPRESSED = 0x04  # reserved in v1
KNOWN_FLAGS = FLAG_REQUIRE_ACK | FLAG_RETRANSMIT


class MsgType(IntEnum):
    HELLO = 1
    HELLO_ACK = 2
    DATA = 3
    ACK = 4
    PING = 5
    PONG = 6
    ERROR = 7
    BYE = 8


class Header(NamedTuple):
    """Parsed header fields. Deliberately separate from the body."""

    msg_type: MsgType
    flags: int
    seq: int
    length: int
    crc: int


@dataclass(frozen=True, slots=True)
class Frame:
    """A fully decoded, integrity- and authenticity-checked message."""

    msg_type: MsgType
    seq: int
    payload: bytes = b""
    flags: int = 0

    def __repr__(self) -> str:  # keeps test output readable
        return (
            f"Frame({self.msg_type.name}, seq={self.seq}, "
            f"len={len(self.payload)}, flags=0x{self.flags:02x})"
        )


def encode(frame: Frame, secret: bytes) -> bytes:
    """Serialise a frame including its CRC and its MAC."""
    if len(frame.payload) > MAX_PAYLOAD:
        raise ProtocolError(
            ErrorCode.ERR_LENGTH, f"payload too large: {len(frame.payload)}"
        )
    if not 0 <= frame.seq <= MAX_SEQ:
        raise ProtocolError(ErrorCode.ERR_SEQ, f"seq out of range: {frame.seq}")
    if frame.flags & ~KNOWN_FLAGS:
        raise ProtocolError(ErrorCode.ERR_FLAGS, f"unsupported flags: {frame.flags:#x}")
    crc = zlib.crc32(frame.payload) & 0xFFFFFFFF
    header = HEADER.pack(
        MAGIC,
        VERSION,
        int(frame.msg_type),
        frame.flags,
        frame.seq,
        len(frame.payload),
        crc,
    )
    return header + frame.payload + sign(header, frame.payload, secret)


def decode_header(raw: bytes) -> Header:
    """Parse a header and validate everything that can be validated without the body.

    `length` is checked against MAX_PAYLOAD here, before the caller allocates a buffer of
    that size. See docs/PROTOCOL.md section 8.1.
    """
    if len(raw) != HEADER.size:
        raise ProtocolError(ErrorCode.ERR_LENGTH, f"short header: {len(raw)} bytes")
    magic, ver, typ, flags, seq, length, crc = HEADER.unpack(raw)
    if magic != MAGIC:
        raise ProtocolError(ErrorCode.ERR_MAGIC, f"bad magic {magic!r}")
    if ver != VERSION:
        raise ProtocolError(ErrorCode.ERR_VERSION, f"unsupported version {ver}")
    if length > MAX_PAYLOAD:  # checked BEFORE any allocation
        raise ProtocolError(
            ErrorCode.ERR_LENGTH, f"declared length {length} exceeds limit {MAX_PAYLOAD}"
        )
    if flags & ~KNOWN_FLAGS:
        raise ProtocolError(ErrorCode.ERR_FLAGS, f"unsupported flags: {flags:#x}")
    try:
        msg_type = MsgType(typ)
    except ValueError as exc:
        raise ProtocolError(ErrorCode.ERR_TYPE, f"unknown message type {typ}") from exc
    return Header(msg_type, flags, seq, length, crc)


def sign(header: bytes, payload: bytes, secret: bytes) -> bytes:
    return hmac.new(secret, header + payload, hashlib.sha256).digest()


def verify_crc(payload: bytes, expected: int) -> None:
    actual = zlib.crc32(payload) & 0xFFFFFFFF
    if actual != expected:
        raise ProtocolError(
            ErrorCode.ERR_CRC, f"crc mismatch: got {actual:#010x}, want {expected:#010x}"
        )


def verify_mac(header: bytes, payload: bytes, mac: bytes, secret: bytes) -> None:
    # compare_digest, not ==: a byte-by-byte comparison leaks the matching prefix length
    # through its running time.
    if not hmac.compare_digest(sign(header, payload, secret), mac):
        raise ProtocolError(ErrorCode.ERR_AUTH, "hmac mismatch")


def decode_frame(
    raw_header: bytes, payload: bytes, mac: bytes, secret: bytes | None
) -> Frame:
    """Assemble the three parts a reader collected into a verified frame.

    `secret=None` is observer mode: the frame is parsed and its CRC checked, but the MAC
    is not verified. The traffic analyser needs this, because an observer on the wire
    does not hold the key. No peer of the protocol may pass None.
    """
    header = decode_header(raw_header)
    if len(payload) != header.length:
        raise ProtocolError(
            ErrorCode.ERR_LENGTH,
            f"body is {len(payload)} bytes, header declared {header.length}",
        )
    if len(mac) != MAC_SIZE:
        raise ProtocolError(ErrorCode.ERR_AUTH, f"short mac: {len(mac)} bytes")
    verify_crc(payload, header.crc)  # cheap, catches accidental corruption
    if secret is not None:
        verify_mac(raw_header, payload, mac, secret)  # the actual security check
    return Frame(header.msg_type, header.seq, payload, header.flags)


def decode(raw: bytes, secret: bytes | None) -> Frame:
    """Decode one complete frame from a single buffer (datagram mode)."""
    if len(raw) < HEADER.size + MAC_SIZE:
        raise ProtocolError(ErrorCode.ERR_LENGTH, f"runt frame: {len(raw)} bytes")
    header = decode_header(raw[: HEADER.size])
    expected = HEADER.size + header.length + MAC_SIZE
    if len(raw) != expected:
        raise ProtocolError(
            ErrorCode.ERR_LENGTH, f"frame is {len(raw)} bytes, expected {expected}"
        )
    return decode_frame(
        raw[: HEADER.size],
        raw[HEADER.size : HEADER.size + header.length],
        raw[HEADER.size + header.length :],
        secret,
    )
