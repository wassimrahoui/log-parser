# Research — Key-value, JSON Lines, CSV/TSV, plain text telemetry

Family: generic structured-text formats
Sources researched: ManageEngine "Analyzing FortiGate syslog" (KVP structure), vector GitHub
issue #20886 (FortiGate proprietary KV over syslog), Graylog syslog guide, OpenSearch/Elastic
bulk NDJSON docs (for adapter, cross-referenced), common logfmt conventions (heroku logfmt),
Apache/nginx combined access log format definitions (positional format).

## key=value / logfmt

- Space-separated `key=value`; values may be quoted (`"..."`) when containing spaces; escapes
  `\"` inside quotes. logfmt convention: keys are bare tokens; empty values allowed.
- FortiGate (FortiOS ≥5) emits `<PRI>timestamp host date=... time=... logid=... type=event
  subtype=... level=... vd="root" srcip=... dstip=... action=...` — keys are stable, values
  occasionally quoted (vd, msg, hostname). FortiOS 8 adds custom templates but default remains
  RFC3164+KV (Reddit/fortinet observation 2025).
- SonicWall: `<PRI> id=firewall sn=... time="2024-01-01 12:00:00" fw=1.2.3.4 ...` — id= prefix
  family, quoted time.
- Deviations: duplicate keys, unquoted spaces in msg, mixed KV inside other formats (CEF
  extension), keys with hyphens/dots, values containing `=`.

## JSON / JSON Lines

- NDJSON: one JSON object per line; each independent; trailing whitespace tolerated. Nested
  objects/arrays possible. JSON logs commonly from applications (Python/Node logging), containers,
  cloud services.
- Parsing: stdlib `json` (safe, no code execution); size/depth/field-count limits enforced
  (Skill 08). Duplicate keys: Python keeps last — to preserve duplicates we must detect via
  object_pairs_hook and record all occurrences (lossless requirement).
- Non-object top-level (array, scalar) is valid JSON but unusual for telemetry: preserve decoded
  value under `unknown` layer rather than force object shape.

## CSV/TSV

- Positional: meaning depends on column order — column schema MUST come from configuration per
  source (deterministic; no guessing). RFC 4180 quoting: `"a,b"` quoting, `""` escape, headers
  optional (config flag). Delimiters: comma, tab, semicolon, pipe (config).
- Without configured schema: format detected as CSV, columns extracted as `col_N`, status notes
  missing schema (partial by design, never fabricated semantics).

## Plain text / positional

- Apache/nginx combined: `host ident authuser [date] "request" status bytes "referer" "ua"`.
- Windows event forwarding renders: `Level Date Time Source EventID TaskCategory ...` — brittle;
  out of day-one scope except generic positional passthrough preservation.
- Rule: plain text always parseable at least to raw preservation; line metadata (line number)
  recorded for file sources.

## Parser implications
- KV parser: anchor on `key=` (or `key: value` via config), respect quotes, preserve duplicates
  and malformed pairs; FortiGate/SonicWall recognized via signature keys (logid+type+subtype /
  id=+sn=+fw=) for source INFERRED identification.
- JSON parser: duplicate-key-preserving, depth/size bounded; arrays/scalars preserved.
- CSV parser: config-driven schema; delimiter/quoting deterministic; header rows optional.
- All: raw preserved verbatim; extraction failures degrade to PARTIAL, never drop (Skill 03).
