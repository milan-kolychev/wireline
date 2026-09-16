"""Layer-by-layer dissection of a capture, ending at the Wireline layer.

The function is written as a sequence of layers on purpose. It is the practical answer to
"what does the OSI model give you": each step strips one header and hands the rest to the
next, and a failure at any step tells you which layer to look at.

    L2 Ethernet -> L3 IP -> L4 TCP/UDP -> L7 Wireline

The analyser is an observer and does not hold the shared key, so it parses Wireline
headers without verifying the MAC. That is a real property of the position, not a
shortcut: anyone who can read your traffic still cannot forge it.
"""

from __future__ import annotations

import socket
import struct
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from wireline.protocol.codec import HEADER, MAC_SIZE, Frame, MsgType, decode_header
from wireline.protocol.errors import ProtocolError
from wireline.sniff.pcap import (
    LINKTYPE_ETHERNET,
    LINKTYPE_LOOPBACK,
    LINKTYPE_RAW_IP,
    Packet,
    read_packets,
)
from wireline.transport.framing import FrameBuffer

ETH_HEADER = struct.Struct("!6s6sH")
ETHERTYPE_IPV4 = 0x0800
PROTO_TCP = 6
PROTO_UDP = 17

TCP_FLAG_NAMES = [
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
]


@dataclass(slots=True)
class WirelineInfo:
    msg_type: str
    seq: int
    length: int
    flags: int


@dataclass(slots=True)
class Row:
    """One packet, decomposed. Deliberately flat: it prints and it serialises."""

    ts: float
    l2_src: str = ""
    l2_dst: str = ""
    l3_src: str = ""
    l3_dst: str = ""
    l4_proto: str = ""
    l4_sport: int = 0
    l4_dport: int = 0
    l4_flags: str = ""
    payload_len: int = 0
    payload: bytes = b""
    l7: list[WirelineInfo] = field(default_factory=list)
    note: str = ""


def mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def ip_str(raw: bytes) -> str:
    return socket.inet_ntoa(raw)


def tcp_flags(flags: int) -> str:
    return "|".join(name for bit, name in TCP_FLAG_NAMES if flags & bit) or "-"


def try_parse_wireline(data: bytes) -> list[WirelineInfo]:
    """Scan a payload for Wireline frames, without the key and without reassembly.

    Only frames whose body is fully present in this payload are reported. A header
    followed by a body that continues in the next segment is not a frame the observer can
    see, and claiming otherwise would be a false positive; that case belongs to
    `reassemble_flows`. Anything that does not start with the magic is skipped rather than
    reported as an error, because a capture contains other people's traffic.
    """
    found: list[WirelineInfo] = []
    offset = 0
    while offset + HEADER.size <= len(data):
        try:
            header = decode_header(data[offset : offset + HEADER.size])
        except ProtocolError:
            break
        end = offset + HEADER.size + header.length + MAC_SIZE
        if end > len(data):
            break  # the body continues in another segment
        found.append(
            WirelineInfo(header.msg_type.name, header.seq, header.length, header.flags)
        )
        offset = end
    return found


def _dissect_packet(linktype: int, packet: Packet) -> Row | None:
    row = Row(ts=packet.timestamp)
    data = packet.data

    # -- L2 ---------------------------------------------------------------
    if linktype == LINKTYPE_ETHERNET:
        if len(data) < ETH_HEADER.size:
            return None
        dst, src, ethertype = ETH_HEADER.unpack(data[: ETH_HEADER.size])
        row.l2_dst, row.l2_src = mac(dst), mac(src)
        if ethertype != ETHERTYPE_IPV4:
            row.note = f"non-ipv4 ethertype {ethertype:#06x}"
            return row
        data = data[ETH_HEADER.size :]
    elif linktype == LINKTYPE_LOOPBACK:
        data = data[4:]  # BSD loopback family header
    elif linktype != LINKTYPE_RAW_IP:
        row.note = f"unsupported linktype {linktype}"
        return row

    # -- L3 ---------------------------------------------------------------
    if len(data) < 20 or (data[0] >> 4) != 4:
        row.note = "not an ipv4 packet"
        return row
    ihl = (data[0] & 0x0F) * 4
    total_length = struct.unpack("!H", data[2:4])[0]
    proto = data[9]
    row.l3_src, row.l3_dst = ip_str(data[12:16]), ip_str(data[16:20])
    data = data[ihl:total_length] if total_length else data[ihl:]

    # -- L4 ---------------------------------------------------------------
    if proto == PROTO_TCP:
        if len(data) < 20:
            return row
        sport, dport = struct.unpack("!HH", data[:4])
        data_offset = (data[12] >> 4) * 4
        row.l4_proto = "TCP"
        row.l4_sport, row.l4_dport = sport, dport
        row.l4_flags = tcp_flags(data[13])
        data = data[data_offset:]
    elif proto == PROTO_UDP:
        if len(data) < 8:
            return row
        sport, dport, udp_len, _ = struct.unpack("!HHHH", data[:8])
        row.l4_proto = "UDP"
        row.l4_sport, row.l4_dport = sport, dport
        data = data[8:udp_len] if udp_len >= 8 else data[8:]
    else:
        row.note = f"ip protocol {proto}"
        return row

    # -- L7 ---------------------------------------------------------------
    row.payload_len = len(data)
    row.payload = bytes(data)
    row.l7 = try_parse_wireline(data)
    return row


def dissect(pcap_path: str | Path) -> list[Row]:
    """Decompose every packet in a capture. Returns one row per packet."""
    rows: list[Row] = []
    for linktype, packet in read_packets(pcap_path):
        row = _dissect_packet(linktype, packet)
        if row is not None:
            rows.append(row)
    return rows


def flow_key(row: Row) -> str:
    return f"{row.l3_src}:{row.l4_sport} -> {row.l3_dst}:{row.l4_dport}"


def reassemble_flows(rows: Iterable[Row]) -> dict[str, list[Frame]]:
    """Rebuild Wireline messages per direction of each connection.

    Packet-level parsing misses any frame that crossed a segment boundary. Feeding each
    direction into the same FrameBuffer the server uses recovers them, which is the
    capture-side proof that framing and reassembly agree.

    Frames are parsed without the key (observer mode), so the MAC is not verified.
    """
    buffers: dict[str, FrameBuffer] = {}
    frames: dict[str, list[Frame]] = {}
    for row in rows:
        if not row.payload or not row.l4_proto:
            continue
        key = flow_key(row)
        buffer = buffers.setdefault(key, FrameBuffer(None))
        buffer.feed(row.payload)
        try:
            frames.setdefault(key, []).extend(buffer.drain())
        except ProtocolError:
            # Not our traffic, or a capture that starts mid-stream. Stop following this
            # direction instead of reporting a false positive.
            buffers[key] = FrameBuffer(None)
    return frames


def summarise(rows: Iterable[Row]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        for info in row.l7:
            counts[info.msg_type] = counts.get(info.msg_type, 0) + 1
    return counts


def format_rows(rows: Iterable[Row]) -> Iterator[str]:
    """Human-readable output, one line per packet, layers left to right."""
    for row in rows:
        parts = [f"{row.ts:.6f}"]
        if row.l2_src:
            parts.append(f"L2 {row.l2_src} -> {row.l2_dst}")
        if row.l3_src:
            parts.append(f"L3 {row.l3_src} -> {row.l3_dst}")
        if row.l4_proto:
            parts.append(
                f"L4 {row.l4_proto} {row.l4_sport} -> {row.l4_dport} [{row.l4_flags}]"
                if row.l4_flags
                else f"L4 {row.l4_proto} {row.l4_sport} -> {row.l4_dport}"
            )
        if row.payload_len:
            parts.append(f"len {row.payload_len}")
        if row.l7:
            parts.append(
                "L7 "
                + ", ".join(
                    f"{i.msg_type} seq={i.seq} len={i.length}" for i in row.l7
                )
            )
        if row.note:
            parts.append(f"({row.note})")
        yield "  ".join(parts)


def known_message_types() -> list[str]:
    return [t.name for t in MsgType]
