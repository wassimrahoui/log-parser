# PERFORMANCE REVIEW (build plan §57)

Measured: 2026-09-09, Python 3.14.4, Windows, single thread, mixed-format corpus
(rfc5424, rfc3164+ASA, CEF, LEEF, FortiGate KV, JSON, KV, unknown) — evidence:
`bench.py` (run during build; reproducible).

## Results

| Metric | Value |
|---|---|
| Throughput (mixed formats, 1 thread) | ~9,600 events/sec |
| Latency per event (median-path) | ~0.10 ms |
| 60 KB message | parsed + fully preserved in ~2.7 ms |
| Peak memory (1600 events + bounded history) | ~4.6 MiB |
| Queue bound | 10,000 events (configurable) |
| Delivery batch bound | 500 events (configurable) |

## Design points that bound resources

- All limits from `ResourceLimits` enforced before allocation-heavy work
  (message size, field count, nesting depth, connections, queue size).
- TCP framer rejects buffers exceeding max_message_bytes + count-prefix headroom.
- Queues are bounded (`queue.Queue(maxsize=...)`) with explicit overflow
  accounting; delivery overflow routes to bounded spool, never silent loss.
- Event history (API inspection) is a bounded deque (1000).
- Batching for `_bulk` with per-batch cap; retry backoff capped at 30 s.

## Outages / delays behavior (tested)

- SIEM target refused/down ⇒ retry with backoff ⇒ spool fallback; events never
  silently discarded (tests/test_delivery.py::TestDeliveryManager).
- Oversized datagram on Windows (WSAEMSGSIZE) and pre-check path both counted
  as explicit LIMIT_EXCEEDED outcomes (tests/test_limits.py).

## Not optimized (honesty note)

- Regex-based parsers are not the fastest possible design (a hand-rolled
  state machine would be faster); chosen for correctness/determinism first.
  No telemetry is removed or degraded by this choice (Skill 09 rule 6).
- Multi-worker parallelism intentionally out of scope of the first build;
  bounded design keeps behavior predictable. Extension point documented.
