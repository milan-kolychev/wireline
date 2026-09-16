"""Minimal reader and writer for the classic pcap format.

Written by hand rather than taken from a library, because the point of the analyser is to
show that a capture file is a header plus a list of (timestamp, bytes) records, and that
nothing magic happens between the wire and Wireshark.

Format: a 24-byte file header, then per packet a 16-byte record header followed by the
captured bytes. Endianness is decided by the magic number, which is why the same file
opens correctly on machines that wrote it differently.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

MAGIC_LE = 0xA1B2C3D4  # seconds + microseconds, little-endian writer
MAGIC_BE = 0xD4C3B2A1
FILE_HEADER = struct.Struct("=IHHiIII")  # magic, major, minor, tz, sigfigs, snaplen, link
RECORD_HEADER_SIZE = 16

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW_IP = 101
LINKTYPE_LOOPBACK = 0


class PcapError(Exception):
    """The file is not a pcap, or is truncated."""


@dataclass(frozen=True, slots=True)
class Packet:
    timestamp: float
    data: bytes
    original_length: int


def read_packets(path: str | Path) -> Iterator[tuple[int, Packet]]:
    """Yield (linktype, packet) for every record. Truncated tails raise PcapError."""
    raw = Path(path).read_bytes()
    if len(raw) < FILE_HEADER.size:
        raise PcapError(f"file is {len(raw)} bytes, shorter than a pcap header")
    magic = struct.unpack("=I", raw[:4])[0]
    if magic == MAGIC_LE:
        endian = "<"
    elif magic == MAGIC_BE:
        endian = ">"
    else:
        raise PcapError(f"unknown pcap magic {magic:#010x}")

    header = struct.Struct(endian + "IHHiIII")
    record = struct.Struct(endian + "IIII")
    _, _, _, _, _, _, linktype = header.unpack(raw[: header.size])

    offset = header.size
    while offset < len(raw):
        if offset + RECORD_HEADER_SIZE > len(raw):
            raise PcapError(f"truncated record header at offset {offset}")
        ts_sec, ts_usec, incl_len, orig_len = record.unpack(
            raw[offset : offset + RECORD_HEADER_SIZE]
        )
        offset += RECORD_HEADER_SIZE
        if offset + incl_len > len(raw):
            raise PcapError(f"truncated packet data at offset {offset}")
        data = raw[offset : offset + incl_len]
        offset += incl_len
        yield linktype, Packet(ts_sec + ts_usec / 1_000_000, data, orig_len)


def write_packets(
    path: str | Path,
    packets: list[tuple[float, bytes]],
    linktype: int = LINKTYPE_ETHERNET,
    snaplen: int = 65535,
) -> None:
    """Write a capture. Used to build deterministic test fixtures."""
    out = bytearray(
        FILE_HEADER.pack(MAGIC_LE, 2, 4, 0, 0, snaplen, linktype)
    )
    record = struct.Struct("=IIII")
    for timestamp, data in packets:
        sec = int(timestamp)
        usec = int(round((timestamp - sec) * 1_000_000))
        out += record.pack(sec, usec, len(data), len(data))
        out += data
    Path(path).write_bytes(bytes(out))
