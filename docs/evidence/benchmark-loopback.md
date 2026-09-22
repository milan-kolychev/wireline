# Wireline TCP benchmark

Command, run twice on the same machine:

```powershell
python benchmarks/bench_tcp.py --requests 2000 --payload 1024 --clients 100
```

Method notes:

- Sequential latency is measured per request on one connection with `time.perf_counter()`.
- `messages_s` and `throughput_mb_s` in the sequential part are divided by the sum of
  request latencies, not by wall-clock time, so they exclude the client's own gaps between
  requests and are somewhat inflated.
- In the concurrent part `rps` is total requests divided by wall-clock time.
- The two runs differ by 20-35% on p95 and on rps. README.md quotes the range, not the
  better run.

## Run 1

- host: Windows-11-10.0.26200-SP0
- python: 3.13.3
- transport: TCP over loopback, TCP_NODELAY on, no TLS
- reference application: echo

### Sequential request/response

| metric | value |
|---|---|
| requests | 2000 |
| payload_bytes | 1024 |
| p50_ms | 0.152 |
| p95_ms | 0.262 |
| p99_ms | 0.449 |
| mean_ms | 0.166 |
| max_ms | 1.121 |
| throughput_mb_s | 11.797 |
| messages_s | 6040.181 |

### 100 concurrent clients

| metric | value |
|---|---|
| clients | 100 |
| requests_each | 20 |
| wall_s | 0.512 |
| rps | 3909.704 |
| p50_ms | 11.350 |
| p95_ms | 22.692 |
| p99_ms | 24.971 |
| errors | 0 |

## Run 2

- host: Windows-11-10.0.26200-SP0
- python: 3.13.3
- transport: TCP over loopback, TCP_NODELAY on, no TLS
- reference application: echo

### Sequential request/response

| metric | value |
|---|---|
| requests | 2000 |
| payload_bytes | 1024 |
| p50_ms | 0.166 |
| p95_ms | 0.353 |
| p99_ms | 0.547 |
| mean_ms | 0.193 |
| max_ms | 1.618 |
| throughput_mb_s | 10.123 |
| messages_s | 5183.223 |

### 100 concurrent clients

| metric | value |
|---|---|
| clients | 100 |
| requests_each | 20 |
| wall_s | 0.418 |
| rps | 4784.324 |
| p50_ms | 9.649 |
| p95_ms | 18.667 |
| p99_ms | 19.371 |
| errors | 0 |
