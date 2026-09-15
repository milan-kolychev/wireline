"""Measure three numbers: request/response latency, throughput, behaviour under load.

    python benchmarks/bench_tcp.py --requests 2000 --payload 1024 --clients 100

Method matters more than the numbers, so the script prints the parameters it used.
Everything runs on loopback: this measures the protocol implementation, not a network.
"""

from __future__ import annotations

import argparse
import asyncio
import platform
import statistics
import sys
import time

from wireline.client import WirelineClient
from wireline.server import WirelineServer

SECRET = b"benchmark-secret"


def percentile(values: list[float], p: float) -> float:
    ordered = sorted(values)
    index = min(int(round(p / 100 * (len(ordered) - 1))), len(ordered) - 1)
    return ordered[index]


async def measure_latency(address: tuple[str, int], requests: int, payload: int) -> dict:
    body = b"x" * payload
    samples: list[float] = []
    async with WirelineClient(SECRET, *address, client_id="bench-latency") as client:
        for _ in range(requests):
            started = time.perf_counter()
            await client.send_data(body)
            samples.append((time.perf_counter() - started) * 1000)
    total_bytes = requests * payload * 2  # request and echo
    wall = sum(samples) / 1000
    return {
        "requests": requests,
        "payload_bytes": payload,
        "p50_ms": percentile(samples, 50),
        "p95_ms": percentile(samples, 95),
        "p99_ms": percentile(samples, 99),
        "mean_ms": statistics.fmean(samples),
        "max_ms": max(samples),
        "throughput_mb_s": total_bytes / wall / 1024 / 1024,
        "messages_s": requests / wall,
    }


async def measure_concurrency(
    address: tuple[str, int], clients: int, requests_each: int, payload: int
) -> dict:
    body = b"x" * payload
    samples: list[float] = []
    errors = 0

    async def worker(index: int) -> None:
        nonlocal errors
        try:
            async with WirelineClient(
                SECRET, *address, client_id=f"bench-{index}", timeout=10.0
            ) as client:
                for _ in range(requests_each):
                    started = time.perf_counter()
                    await client.send_data(body)
                    samples.append((time.perf_counter() - started) * 1000)
        except Exception:
            errors += 1

    started = time.perf_counter()
    await asyncio.gather(*(worker(i) for i in range(clients)))
    wall = time.perf_counter() - started
    return {
        "clients": clients,
        "requests_each": requests_each,
        "wall_s": wall,
        "rps": len(samples) / wall if wall else 0.0,
        "p50_ms": percentile(samples, 50) if samples else 0.0,
        "p95_ms": percentile(samples, 95) if samples else 0.0,
        "p99_ms": percentile(samples, 99) if samples else 0.0,
        "errors": errors,
    }


def table(title: str, data: dict) -> str:
    lines = [f"### {title}", "", "| metric | value |", "|---|---|"]
    for key, value in data.items():
        rendered = f"{value:.3f}" if isinstance(value, float) else str(value)
        lines.append(f"| {key} | {rendered} |")
    return "\n".join(lines) + "\n"


async def main(args: argparse.Namespace) -> int:
    async with WirelineServer(SECRET, "127.0.0.1", 0, idle_timeout=60.0) as server:
        address = server.address
        print("## Wireline TCP benchmark\n")
        print(f"- host: {platform.platform()}")
        print(f"- python: {sys.version.split()[0]}")
        print("- transport: TCP over loopback, TCP_NODELAY on, no TLS")
        print("- reference application: echo\n")
        latency = await measure_latency(address, args.requests, args.payload)
        print(table("Sequential request/response", latency))
        load = await measure_concurrency(
            address, args.clients, args.requests_each, args.payload
        )
        print(table(f"{args.clients} concurrent clients", load))
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--requests", type=int, default=2000)
    parser.add_argument("--payload", type=int, default=1024)
    parser.add_argument("--clients", type=int, default=100)
    parser.add_argument("--requests-each", type=int, default=20)
    raise SystemExit(asyncio.run(main(parser.parse_args())))
