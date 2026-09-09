# SKILL 02 — DETERMINISTIC PARSER ENGINEERING

## Purpose
Every parser in this platform is deterministic. Same input + same configuration + same parser
version ⇒ same structured output. Byte-for-byte reproducible.

## Absolute prohibitions (runtime)
- No LLM, no ML, no neural network, no embeddings, no vector search.
- No AI-based parsing, classification, or source identification.
- No probabilistic parser selection, no fuzzy scoring that changes outcomes.
- No semantic guessing ("looks like a Cisco message") as a decision mechanism.
- No hidden fallback interpretation: every fallback must be an explicit, configured, documented rule.

## Allowed mechanisms
- Explicit grammars: regexes with named groups, position/token splitting.
- Explicit framing rules (RFC 5424 octet counting, newline, RFC 3164 header grammar).
- Explicit key-value conventions (CEF, LEEF, logfmt) with documented escaping/decoding.
- Configuration-driven field maps (alias → normalized name).
- Signature tables (exact literal or regex prefixes, resolved in defined priority order).

## Parser contract — every parser MUST define and document
1. What input it accepts (format, constraints) and how it is recognized (signature).
2. What fields it extracts (every one, not just "important" ones).
3. How types are determined (explicit conversion rules, never blind coercion).
4. Which fields are vendor-specific (land in `vendor.*`) and which are optional.
5. What happens on failure: what is preserved, what status is recorded (never a throwaway).
6. What remains raw (always: the full original message).
7. How it is tested (samples + malformed variants + partial-parse cases).
8. Which product/version it covers — and which it explicitly does not.

## Failure behavior
- Partial success is a first-class outcome: extract what matched, preserve the rest, mark
  `parse.status = PARTIAL` with per-field notes.
- Full failure preserves raw + metadata with `parse.status = FAILED|UNKNOWN_FORMAT`.
- A parser never raises an unhandled exception through the pipeline; errors become status.

## Versioning
Parser version is recorded on every event (`parse.parser_version`). Changing extraction behavior
requires bumping the parser version and updating golden tests.
