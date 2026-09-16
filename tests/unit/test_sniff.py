"""Analyser tests.

They run on recorded fixtures instead of live traffic, which gives determinism without a
network and without privileges. The fixtures are built by tools/make_pcap_fixture.py and
committed, so a failure here is a change in the parser, never a change in the weather.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from wireline.protocol.codec import MsgType
from wireline.sniff.dissect import (
    dissect,
    format_rows,
    reassemble_flows,
    summarise,
    try_parse_wireline,
)
from wireline.sniff.pcap import PcapError, read_packets, write_packets

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
TCP_CAPTURE = FIXTURES / "tcp-session.pcap"
UDP_CAPTURE = FIXTURES / "udp-session.pcap"


def test_reads_every_packet_in_the_capture() -> None:
    packets = list(read_packets(TCP_CAPTURE))
    assert len(packets) == 11
    assert all(linktype == 1 for linktype, _ in packets)
    assert packets[0][1].timestamp == pytest.approx(1757000000.0, abs=1e-3)


def test_rejects_a_file_that_is_not_a_pcap(tmp_path: Path) -> None:
    bad = tmp_path / "not.pcap"
    bad.write_bytes(b"this is not a capture file at all")
    with pytest.raises(PcapError, match="magic"):
        list(read_packets(bad))


def test_rejects_a_truncated_capture(tmp_path: Path) -> None:
    truncated = tmp_path / "cut.pcap"
    truncated.write_bytes(TCP_CAPTURE.read_bytes()[:-20])
    with pytest.raises(PcapError, match="truncated"):
        list(read_packets(truncated))


def test_roundtrip_through_the_writer(tmp_path: Path) -> None:
    out = tmp_path / "round.pcap"
    write_packets(out, [(1.5, b"\x00" * 40), (2.25, b"\xff" * 10)])
    packets = [packet for _, packet in read_packets(out)]
    assert [p.original_length for p in packets] == [40, 10]
    assert packets[1].timestamp == pytest.approx(2.25, abs=1e-6)


def test_dissects_all_four_layers() -> None:
    rows = dissect(TCP_CAPTURE)
    handshake = rows[0]
    assert handshake.l2_src == "02:00:00:00:00:01"
    assert (handshake.l3_src, handshake.l3_dst) == ("10.0.0.10", "10.0.0.20")
    assert handshake.l4_proto == "TCP"
    assert handshake.l4_flags == "SYN"
    assert (handshake.l4_sport, handshake.l4_dport) == (51234, 9000)
    assert handshake.l7 == []  # a SYN carries no application data


def test_finds_wireline_messages_at_l7() -> None:
    counts = summarise(dissect(TCP_CAPTURE))
    assert counts["HELLO"] == 1
    assert counts["HELLO_ACK"] == 1
    assert counts["BYE"] == 1


def test_udp_capture_is_dissected_too() -> None:
    rows = dissect(UDP_CAPTURE)
    assert [row.l4_proto for row in rows] == ["UDP", "UDP"]
    assert summarise(rows) == {"PING": 1, "PONG": 1}
    assert rows[0].l7[0].flags == 0x01  # FLAG_REQUIRE_ACK, as the UDP client sets it


def test_split_frame_is_invisible_per_packet_but_visible_after_reassembly() -> None:
    """The point of the analyser, in one test.

    The DATA frame in the fixture is cut across two segments. Scanning packets one by one
    finds only one DATA (the server's reply); following the flow finds both.
    """
    rows = dissect(TCP_CAPTURE)
    per_packet = summarise(rows)
    assert per_packet.get("DATA", 0) == 1

    flows = reassemble_flows(rows)
    client_flow = flows["10.0.0.10:51234 -> 10.0.0.20:9000"]
    types = [frame.msg_type for frame in client_flow]
    assert types == [MsgType.HELLO, MsgType.DATA, MsgType.BYE]
    assert client_flow[1].payload == b"payload that crosses a segment boundary"


def test_reassembly_covers_both_directions() -> None:
    flows = reassemble_flows(dissect(TCP_CAPTURE))
    assert set(flows) == {
        "10.0.0.10:51234 -> 10.0.0.20:9000",
        "10.0.0.20:9000 -> 10.0.0.10:51234",
    }


def test_foreign_traffic_is_skipped_not_reported() -> None:
    """A capture contains other people's packets. They must not become findings."""
    assert try_parse_wireline(b"GET / HTTP/1.1\r\nHost: lab.local\r\n\r\n") == []
    assert try_parse_wireline(b"") == []


def test_output_lines_show_the_layers_left_to_right() -> None:
    lines = list(format_rows(dissect(TCP_CAPTURE)))
    assert any("L2" in line and "L3" in line and "L4 TCP" in line for line in lines)
    assert any("L7 HELLO" in line for line in lines)
