# TESTING STRATEGY & RESULTS (Skill 07/10)

## Test layout

| File | Covers |
|---|---|
| tests/test_parsers.py | every parser: acceptance, extraction, types, deviations, failures |
| tests/test_framing.py | RFC6587 octet + newline framing, fragmentation, style lock, decode fallbacks, limits |
| tests/test_golden.py | golden corpus (§49), lossless (§50), unknown-source (§51), partial-parse (§52), no-silent-loss (§53), E2E UDP/TCP/replay (§54) |
| tests/test_delivery.py | spool/syslog-UDP/syslog-TCP/LEEF/_bulk with REAL local receivers; per-item errors; retry→spool |
| tests/test_limits.py | oversized input, abuse corpus, validation, determinism (Skill 02) |
| tests/test_api_cli.py | config validation, runtime E2E (UDP→pipeline→delivery→API), API endpoints, CLI commands |
| tests/telemetry/ | corpora incl. malformed per family + golden corpus |

## Current results (final gate)

```text
python -m pytest tests/ -q
106 passed
```

## Required test classes — mapping to build plan

- §49 golden: TestGolden (complete-output comparison per case)
- §50 lossless: TestLossless (raw recoverable after pipeline, JSON serialization,
  LEEF serialization, syslog-JSON serialization; byte-exact for non-UTF-8)
- §51 unknown-source: TestUnknownSource
- §52 partial-parse: TestPartialParse
- §53 no-silent-loss: TestNoSilentLoss (every event retains raw + explicit status)
- §54 E2E: TestEndToEnd + TestRuntime (real UDP/TCP transports, real spool/API)
- §26 malformed: TestNoSilentLoss corpora + TestMalformedRobustness abuse set
- §39 limits: TestOversizedInput
- §16/§29/§30 delivery: TestDelivery* (honest status incl. refusal + per-item errors)
- Skill 02 determinism: TestDeterminism (two fresh pipelines ⇒ identical output)

## Live-SIEM verification status (honesty, §60)

Adapters are protocol-verified against real local receivers (sockets/HTTP).
Verification against live Wazuh/QRadar/Elasticsearch instances remains PENDING
an external dependency; documented in BUILD_STATUS.md. No claim of live-SIEM
success is made anywhere.
