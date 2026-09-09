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
| CSV/TSV | `csv` | config-driven schema; no-schema ⇒ columns as `col_N` + PARTIAL |
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

## Known limitations

- Live-SIEM delivery verification pending external instances (adapters are
  protocol-tested against real local receivers).
- UDP is lossy by nature (transport-level); no transport-level ack/replay.
- API has no authentication (loopback default; operator decision to expose).
- Parser budget is recorded, not preemptively enforced (synchronous parse).
- Vendor coverage is research-gated — see `docs/RESEARCH_GAP_ANALYSIS.md`.
