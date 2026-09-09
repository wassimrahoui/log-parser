# ARCHITECTURE

Build plan §9 conceptual model, as implemented (stdlib-only Python).

## Stage flow

```text
TELEMETRY SOURCES
        │
        ▼
COLLECTORS (ulstp/collectors.py)
  UdpCollector   — one datagram = one message (OS-framed); size pre-check;
                   Windows WSAEMSGSIZE classified as oversized-input event
  TcpCollector   — RFC 6587: per-connection TcpFramer auto-detects octet
                   counting vs newline framing (style locked per connection);
                   connection cap; loopback-safe
  FileCollector  — line-oriented; deterministic start-to-end (+follow)
  ReplayCollector— deterministic replay of saved raw strings OR raw bytes
        │  (CollectorStage.emit → bounded queue, counters)
        ▼
PIPELINE WORKER (ulstp/pipeline.py) — one thread, event-at-a-time
  1. format detection  (ulstp/format_detection.py)
     deterministic ordered detectors: rfc5424 → cef → leef → json →
     rfc3164 → kv → csv → xml → plain → unknown; ordered candidate list
     for syslog-envelope inner chains
  2. parser resolution (ulstp/registry.py)
     candidates × registry order × parser signature ⇒ first hit; no
     probability anywhere
  3. parsing (ulstp/parsers/*) — Skill 02 contract
     parse result layers: fields / vendor_fields / unknown_fields /
     originals / decoded / protocol_metadata / status / notes
     syslog envelopes chain ONE inner parse (rfc3164+cef etc.); envelope
     format stays the event format
  4. source identification (ulstp/source_id.py) — Skill 04
     configured source → signature table → protocol ids → transport only;
     result KNOWN/INFERRED/UNKNOWN + ordered evidence chain
  5. type handling (ulstp/normalize.py)
     known-type checks (ip/port/ISO-timestamp) are ANNOTATIVE: problems are
     recorded, values are never removed or replaced
  6. validation (event-level, §28)
     structural checks; invalid ⇒ INVALID + problems + preserved values
  7. outcome metrics (ulstp/metrics.py, §40)
        │
        ▼
DELIVERY (ulstp/delivery.py)
  DeliveryManager: bounded queue → batch → target.deliver() → retry with
  capped backoff → spool fallback. Targets:
    SpoolTarget   JSONL file (full lossless event) — verification + fallback
    SyslogTarget  RFC3164 envelope + JSON payload (Wazuh-compatible path)
    QradarTarget  LEEF:1.0 over syslog
    ElasticTarget _bulk NDJSON with per-item error checking
        │
        ▼
API / EVENT INSPECTOR (ulstp/api.py) — stdlib http, loopback default
  / (inspector UI) /health /metrics /api/events /api/events/{id} /api/parse
```

## Lossless event model

`LosslessEvent` (ulstp/event.py) is append-only in practice: no stage removes
information. Normalization is a mapping ON TOP of preserved originals
(`original.*`), vendor fields (`vendor.*`) and unknown fields (`unknown.*`).
Raw bytes are retained (b64) whenever transport provides bytes that are not
valid UTF-8. See README "Lossless event model" for the layer table.

## Concurrency model

- One pipeline worker thread (deterministic ordering per input stream).
- Collector threads per listener; per-connection threads for TCP (capped).
- Delivery worker thread with bounded batch; pipeline.sink = delivery.submit.
- All shared counters/gauges lock-protected (Metrics).

## Determinism guarantees

- No randomness, no time-of-execution dependence in parsing decisions
  (timestamps normalized only with explicit policy, recorded as notes).
- Parser resolution order fixed (candidates → registry order → signature).
- Same input + registry + config ⇒ identical event output (tested).

## Extension points (§48)

- New parser: subclass `Parser`, add to `DEFAULT_REGISTRY_ORDER` (or register
  at runtime), add corpus + golden case + docs/parsers page.
- New SIEM: subclass `DeliveryTarget`, wire in `runtime.build_delivery`.
- New source signature: one row in `source_id._SIGNATURES` (research-gated).
- New CEF/LEEF/KV key: one entry in the respective *_KEY_MAP.
