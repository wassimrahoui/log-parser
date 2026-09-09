# SKILL 09 — PERFORMANCE & RESOURCE ENGINEERING

## Purpose
Efficient, predictable processing with bounded memory and queues — without ever silently
discarding telemetry to achieve performance.

## Rules
1. Bounded everything (§39, configurable): max message size (default 64 KiB), max field size
   (8 KiB), max nested depth (32), max field count (512), max connections per listener (config),
   max queued events (config), max parse time, max memory pressure triggers backpressure.
2. Backpressure over loss: bounded queues with `put(block=True)`-style producer throttling and
   explicit `QUEUE_OVERFLOW_*` states when configured policies are exceeded; drops only via
   explicit, configured policy and always counted + reported.
3. Parse time limits: a parser that exceeds its budget stops, records `parse.status=PARTIAL` with
   the reason, and preserves everything extracted so far — the event is never lost.
4. Streaming/line-oriented processing; no unbounded file loads; file reading is chunked.
5. Batching where the SIEM protocol supports it, with bounded batch size.
6. Optimizations must never remove, merge, or degrade telemetry information (Skill 03 wins over
   performance when they conflict).
7. Large-message and flood scenarios are covered by tests (oversized datagram, many rapid
   connections, queue-full) and must end in counted, observable outcomes.
