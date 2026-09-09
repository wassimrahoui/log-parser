# SKILL 07 — TESTING & VERIFICATION ENGINEERING

## Purpose
Every meaningful change is proven by tests. No checklist theater: a requirement is complete only
with CODE + TEST + PASSING TEST RESULT.

## Required loop per task
IMPLEMENT → TEST → INSPECT → FIX → TEST AGAIN → VERIFY → UPDATE BUILD_STATUS.md.

## Required test classes
- Unit tests (every module)
- Parser tests: representative samples per parser, per format
- Malformed input tests (§26 list: empty, truncated, invalid UTF-8/JSON, broken delimiters,
  missing/extra/duplicate fields, invalid timestamps/IPs/ports/numbers, oversized)
- Unknown-source tests, partial-parse tests
- Lossless preservation tests (raw recoverable after every stage and after SIEM serialization)
- Normalization tests (alias mapping, type handling, original preservation)
- Transport tests (UDP, TCP incl. octet-count framing, file tailing)
- SIEM delivery tests (adapter serialization correctness; live delivery where a real SIEM is
  available — spool target counts as the local real delivery path)
- Integration / end-to-end tests (§54 pipeline)
- Regression tests: every fixed bug gains a test
- Golden tests (§49): raw input → expected source/format/parser/fields/normalized/preserved map,
  compared completely

## Discipline
- `python -m pytest` must pass at every phase gate; failures block progression.
- Test telemetry corpus lives in `tests/telemetry/<family>/...` including `malformed/` variants.
- A test that only asserts "no exception" is not sufficient for parsing behavior — assert fields.
