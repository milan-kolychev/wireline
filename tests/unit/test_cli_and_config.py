from __future__ import annotations

import argparse
import logging

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
