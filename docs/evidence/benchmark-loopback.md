## Wireline TCP benchmark

- host: Linux-6.18.44-fc-v24-x86_64-with-glibc2.39
- python: 3.12.3
- transport: TCP over loopback, TCP_NODELAY on, no TLS
- reference application: echo

### Sequential request/response

| metric | value |
|---|---|
| requests | 2000 |
| payload_bytes | 1024 |
| p50_ms | 0.131 |
| p95_ms | 0.178 |
| p99_ms | 0.202 |
| mean_ms | 0.139 |
| max_ms | 1.388 |
| throughput_mb_s | 14.030 |
| messages_s | 7183.551 |

### 100 concurrent clients

| metric | value |
|---|---|
| clients | 100 |
| requests_each | 20 |
| wall_s | 0.227 |
| rps | 8805.145 |
| p50_ms | 9.580 |
| p95_ms | 9.949 |
| p99_ms | 10.723 |
| errors | 0 |

