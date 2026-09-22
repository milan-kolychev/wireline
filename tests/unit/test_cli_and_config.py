from __future__ import annotations

import argparse
import logging
from pathlib import Path

import pytest

from tests.conftest import SECRET
from wireline.__main__ import _ping, _send, build_parser
from wireline.config import DEV_SECRET, SECRET_ENV, load_secret, setup_logging
from wireline.server import WirelineServer


def test_parser_requires_a_subcommand() -> None:
    with pytest.raises(SystemExit):
        build_parser().parse_args([])


def test_parser_reads_ping_options() -> None:
    args = build_parser().parse_args(["--port", "9100", "ping", "--count", "7"])
    assert (args.command, args.port, args.count) == ("ping", 9100, 7)


def test_parser_reads_send_options() -> None:
    args = build_parser().parse_args(["send", "--text", "hi"])
    assert (args.command, args.text) == ("send", "hi")


def test_explicit_secret_wins_over_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(SECRET_ENV, "from-env")
    assert load_secret("explicit") == b"explicit"


def test_secret_comes_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(SECRET_ENV, "from-env")
    assert load_secret() == b"from-env"


def test_missing_secret_falls_back_loudly(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The development fallback must never be silent."""
    monkeypatch.delenv(SECRET_ENV, raising=False)
    with caplog.at_level(logging.WARNING):
        assert load_secret() == DEV_SECRET
    assert SECRET_ENV in caplog.text


def test_setup_logging_is_idempotent() -> None:
    setup_logging("DEBUG")
    setup_logging("nonsense-level")  # falls back to INFO instead of raising


async def test_ping_command_against_a_live_server(
    server: WirelineServer, capsys: pytest.CaptureFixture[str]
) -> None:
    host, port = server.address
    args = argparse.Namespace(host=host, port=port, secret=SECRET.decode(), count=2)
    assert await _ping(args) == 0
    out = capsys.readouterr().out
    assert "session" in out and out.count("pong") == 2


async def test_send_command_prints_the_echo(
    server: WirelineServer, capsys: pytest.CaptureFixture[str]
) -> None:
    host, port = server.address
    args = argparse.Namespace(host=host, port=port, secret=SECRET.decode(), text="echo me")
    assert await _send(args) == 0
    assert "echo me" in capsys.readouterr().out


def test_parser_reads_sniff_options() -> None:
    args = build_parser().parse_args(["sniff", "capture.pcap", "--flows"])
    assert (args.command, args.path, args.flows) == ("sniff", "capture.pcap", True)


def test_sniff_command_prints_layers_and_flows(capsys: pytest.CaptureFixture[str]) -> None:
    from wireline.__main__ import sniff

    capture = Path(__file__).resolve().parents[1] / "fixtures" / "tcp-session.pcap"
    args = argparse.Namespace(path=str(capture), flows=True)
    assert sniff(args) == 0
    out = capsys.readouterr().out
    assert "L4 TCP" in out and "L7 HELLO" in out
    assert "reassembled per direction" in out


def test_expected_failures_print_one_line_and_exit_1(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A wrong key or a dead server is an operator error, not a traceback."""
    import socket

    from wireline.__main__ import main

    with socket.socket() as probe:  # a port that was free a moment ago, so nothing listens
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    assert main(["--port", str(port), "ping"]) == 1
    assert main(["sniff", str(tmp_path / "missing.pcap")]) == 1
    (tmp_path / "junk.pcap").write_bytes(b"not a capture at all, just text")
    assert main(["sniff", str(tmp_path / "junk.pcap")]) == 1
    err = capsys.readouterr().err
    assert "ConnectionRefusedError" in err and "FileNotFoundError" in err
    assert "PcapError" in err and "Traceback" not in err
