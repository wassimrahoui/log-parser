# ULSTP — Universal Lossless SIEM Telemetry Platform

Deterministic, **AI-free** telemetry collection, parsing, normalization and SIEM
delivery with **lossless preservation** of original telemetry. Python 3 stdlib
only — no third-party runtime dependencies, no LLM/ML/AI anywhere in the product.

> The platform is NOT a SIEM. It solves one problem: how can arbitrary telemetry
> be collected, identified, parsed, normalized, and delivered to a SIEM while
> losing as little information as technically possible?

## Pipeline

```text
collect → frame/decode → detect format → identify source → resolve parser
        → parse/extract → normalize → preserve (lossless) → validate
        → queue → SIEM adapter
```

Unknown or unparsable telemetry is **never dropped**: it is preserved raw with
explicit `UNKNOWN_FORMAT`/`SOURCE_UNKNOWN` status and still delivered (§12).

## Quick start

```bash
# parse one message (full lossless event JSON)
python -m ulstp.cli parse "<134>1 2026-09-09T12:00:00Z h sshd 1 ID - msg"

# inspect which parser accepts an input
python -m ulstp.cli test-parser cef --input "CEF:0|V|P|1|s|n|5|src=1.2.3.4"

# run with collectors + SIEM delivery + API/UI
python -m ulstp.cli run --config config.json

# replay saved raw telemetry through the real pipeline (deterministic)
python -m ulstp.cli replay samples.txt --summary

# API/UI inspection sandbox (POST /api/parse)
python -m ulstp.cli serve --api-port 8080

# tests
python -m pytest tests/ -q
```

## Lossless event model

Every event carries all layers (see `ulstp/event.py`):

| Layer | Contents |
|---|---|
| `ingestion` | event id, ingest time |
| `transport` | udp/tcp/file/replay, peer, port, file path/line |
| `raw` | **exact original telemetry** (+ raw bytes b64 when non-UTF-8) |
| `protocol_metadata` | syslog facility/severity, Cisco msgid, ... |
| `decoded` | format-level view (syslog header, CEF header, ...) |
| `source` | KNOWN/INFERRED/UNKNOWN + explainable evidence chain |
| `parser` | name, version, PARSED/PARTIAL/FAILED/UNKNOWN_FORMAT + notes |
| `normalized` | standardized names, known types (IP/port/timestamp validated) |
| `vendor` | vendor-specific fields (all FortiGate keys, syslog SD, ...) |
| `unknown` | unmapped fields — preserved, never discarded |
| `original` | original string representations of every converted value |
| `validation` | VALID/INVALID + per-field problems (values preserved) |
| `delivery` | DELIVERED/FAILED/SPOOLED + target + attempts |

## Supported inputs

| Format | Parser | Notes |
|---|---|---|
| RFC 5424 | `rfc5424` | structured-data parsing, PRI validation, deviations noted |
| RFC 3164 (BSD) | `rfc3164` | missing PRI/hostname/tag tolerated; explicit year policy |
| CEF | `cef` | full extension extraction, escapes decoded, unknown keys preserved |
| LEEF 1.x/2.x | `leef` | tab/custom/hex delimiters, space-separator deviation tolerated |
| key=value / logfmt | `key_value` | quoting, duplicate keys preserved (`k#2`) |
| FortiGate | `fortigate` | researched field mapping; every key also kept in vendor layer |
| Cisco ASA/PIX/FWSM | `cisco_asa` | token grammar + researched sub-grammars (302013/302014/302015); other IDs → PARTIAL with body preserved |
| JSON Lines | `json` | duplicate keys preserved, arrays intact, depth-bounded |
| CSV/TSV | `csv` | config-driven schema; auto delimiter (comma/tab/semicolon, most frequent wins, deterministic) or configured; no-schema ⇒ columns as `col_N` + PARTIAL |
| anything else | `plain_text` | lossless fallback carrier, status UNKNOWN_FORMAT |

Syslog envelopes chain to inner formats (`rfc3164+cef`, `rfc3164+cisco_asa`).

## SIEM targets

| Target | Protocol | Status |
|---|---|---|
| Local spool | JSONL file, full lossless event | tested end-to-end |
| Wazuh(-compatible) | syslog UDP/TCP, JSON payload in MSG | tested against local receivers |
| QRadar | LEEF 1.0 over syslog TCP/UDP | tested against local receivers |
| Elasticsearch/OpenSearch | `_bulk` NDJSON, per-item error checking | tested against local HTTP server |

Delivery failure ⇒ bounded retry with backoff ⇒ **disk spool fallback** — events
are never silently discarded. Adapters are honest: per-item failures are never
reported as success. Live-SIEM verification (real Wazuh/QRadar/Elastic
instances) is the documented remaining external dependency (§60 procedure).

## API / Event Inspector

`GET /` inspector UI · `GET /health` · `GET /metrics` · `GET /api/events`
· `GET /api/events/{id}` · `POST /api/parse`. Binds loopback by default.

## Configuration

See `config.example.json`. Collectors (udp/tcp/file), source definitions
(peer/file → KNOWN identity), resource limits, SIEM target, API. Secrets come
from environment variables (`api_key_env`), never from config values.

## Determinism & AI prohibition

Same input + same config + same parser version ⇒ byte-identical structured
output (enforced by tests). No ML/LLM/embeddings/fuzzy matching at runtime —
parsing is grammar-, signature-, and configuration-based only.

## Documentation

Start at [docs/INDEX.md](docs/INDEX.md) — it maps every document by audience
(understand / operate / extend / audit). Highlights: architecture with diagrams
(`docs/ARCHITECTURE.md`), the lossless event model (`docs/EVENT_MODEL.md`),
per-format grammar reference (`docs/FORMATS.md`), operations guide
(`docs/OPERATIONS.md`), SIEM delivery semantics (`docs/DELIVERY.md`), and a full
end-to-end walkthrough (`docs/PIPELINE_WALKTHROUGH.md`).

## Layout

```text
ulstp/            core package (event, pipeline, parsers/, delivery, api, cli, ...)
skills/           ten mandatory project skills (loading protocol in INDEX.md)
docs/research/    telemetry research records (per-source)
docs/parsers/     parser contracts
docs/*.md         build status, repository analysis, reviews, gap analysis
tests/            unit / golden / lossless / unknown-source / E2E / delivery
tests/telemetry/  corpus incl. malformed samples per family
```

## Blockers & resolution status

### Blockers — reason and suggested solutions

| Blocker | Reason | Suggested solution |
|---|---|---|
| **Live-SIEM delivery unverified** | No Wazuh / QRadar / Elasticsearch instance exists in this environment; adapters are protocol-tested only against real local receivers (sockets + HTTP) | Spin up targets (docker-compose Wazuh + Elasticsearch, or QRadar CE), point `siem` config at them, run `ulstp run --config`, confirm events land, record the result in `docs/BUILD_STATUS.md` (§60) |
| CSV schema/delimiter not configurable at runtime | Registry builds `CsvParser()` with defaults; `config.py` has no parser-parameters section | Add a `parsers.csv` config section (`schema`, `delimiter`, `has_header`) and pass it through `runtime` into registry construction |
| API unauthenticated | Inspection surface designed for loopback; authentication adds credential handling beyond current scope | Keep loopback-only (default) or front with an authenticating reverse proxy; native API keys if ever exposed beyond loopback |
| UDP transport loss | UDP has no ack/retry by protocol definition | Use the TCP listener (RFC 6587) for guaranteed delivery; recover gaps via source-side `ulstp replay` |
| Parse budget recorded, not preemptively enforced | Parsing is synchronous in one worker thread; mid-parse kill needs watchdog machinery | Isolate parsing (subprocess or signal-based timeout) if pathological inputs are ever observed; budget is configurable and overruns are noted per event today |
| Delivery backpressure is dual-queue | Pipeline→delivery handoff is a second bounded queue; a target outage fills the spool path instead of slowing collectors | Bounded + counted by design; for strict end-to-end backpressure, sink events directly from the pipeline worker (single-queue variant) |
| Vendor coverage research-gated | Anti-hallucination rule: no parser without researched documentation/samples | Extend on demand per `docs/RESEARCH_GAP_ANALYSIS.md`: research record → parser → corpus → docs |

### What was done vs. what remains per blocker

| Blocker | What was done | What is to be done if the blocker is resolved |
|---|---|---|
| Live-SIEM verification | Wazuh (syslog, JSON-in-MSG), QRadar (LEEF 1.0), Elasticsearch `_bulk` (per-item error checking) adapters implemented; bounded retry → spool fallback; honest per-item/per-attempt statuses; all delivery tests green against real local receivers | Run against live instances; confirm events appear in each target (Wazuh alerts index / Elastic index / QRadar DSM); mark §60 verified in `docs/BUILD_STATUS.md` |
| CSV config wiring | `CsvParser` supports `schema`/`delimiter`/`has_header` parameters plus deterministic auto-delimiter (comma/tab/semicolon); fully unit + pipeline tested | Wire config → registry, add tests for config-supplied schemas, update `docs/OPERATIONS.md` §2 |
| API auth | Read-only inspection API + `POST /api/parse`, loopback default, secrets-from-env pattern already established | Choose mechanism (proxy or token), implement, update `docs/SECURITY_REVIEW.md` |
| UDP loss | TCP listener fully implemented (octet-count + newline framing, auto-detected) as the reliable alternative | Nothing to build — operational choice; optionally add a spool-replay recovery runbook |
| Parse budget | Overrun recorded per event (`PARSE_BUDGET_EXCEEDED`), budget configurable | Implement watchdog/preemption, re-benchmark, update Skill 09 notes |
| Delivery backpressure | Both queues bounded; overflow explicitly counted (`delivery_queue_overflow`), spool never discards | Decide per deployment whether single-queue strict backpressure is wanted; implement behind config flag |
| Vendor coverage | 6 research records, 10 deterministic parsers with researched deviations, published gap analysis | Per source, on demand: research → parser → golden corpus → docs (§48 extension contract) |
