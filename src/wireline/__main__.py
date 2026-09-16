"""Command line entry point.

    python -m wireline serve --port 9000
    python -m wireline ping --count 5
    python -m wireline send --text "hello"
    python -m wireline sniff capture.pcap
"""

from __future__ import annotations

import argparse
import asyncio
import time

from wireline.client import WirelineClient
from wireline.config import load_secret, setup_logging
from wireline.server import WirelineServer
from wireline.sniff.dissect import dissect, format_rows, reassemble_flows, summarise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="wireline", description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--secret", default=None, help="dev only, prefer WIRELINE_SECRET")
    parser.add_argument("--log-level", default="INFO")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("serve", help="run the TCP server")

    ping = sub.add_parser("ping", help="handshake and send PING frames")
    ping.add_argument("--count", type=int, default=3)

    send = sub.add_parser("send", help="send one DATA frame and print the echo")
    send.add_argument("--text", required=True)

    sniff = sub.add_parser("sniff", help="dissect a pcap file layer by layer")
    sniff.add_argument("path")
    sniff.add_argument(
        "--flows", action="store_true", help="also reassemble messages per direction"
    )
    return parser


async def _serve(args: argparse.Namespace) -> int:
    server = WirelineServer(load_secret(args.secret), args.host, args.port)
    await server.serve_forever()
    return 0


async def _ping(args: argparse.Namespace) -> int:
    async with WirelineClient(load_secret(args.secret), args.host, args.port) as client:
        print(f"session {client.session_id}")
        for i in range(args.count):
            started = time.perf_counter()
            await client.ping(b"probe")
            elapsed = (time.perf_counter() - started) * 1000
            print(f"pong {i + 1}/{args.count}  rtt={elapsed:.2f} ms")
    return 0


async def _send(args: argparse.Namespace) -> int:
    async with WirelineClient(load_secret(args.secret), args.host, args.port) as client:
        echo = await client.send_data(args.text.encode("utf-8"))
        print(echo.decode("utf-8", errors="replace"))
    return 0


def sniff(args: argparse.Namespace) -> int:
    rows = dissect(args.path)
    for line in format_rows(rows):
        print(line)
    counts = summarise(rows)
    print(f"\n{len(rows)} packets, wireline messages seen per packet: {counts or 'none'}")
    if args.flows:
        print("\nreassembled per direction:")
        for key, frames in reassemble_flows(rows).items():
            names = ", ".join(f"{f.msg_type.name}(seq={f.seq})" for f in frames)
            print(f"  {key}: {names or 'no complete messages'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging(args.log_level)
    if args.command == "sniff":  # the only command that needs no event loop
        return sniff(args)
    handlers = {"serve": _serve, "ping": _ping, "send": _send}
    try:
        return asyncio.run(handlers[args.command](args))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
