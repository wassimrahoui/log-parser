# SKILL 03 — LOSSLESS DATA ENGINEERING

## Purpose
Prevent information loss. Normalization is never a replacement for the original.

## Rules
1. RAW TELEMETRY IS SACRED (§11): the original bytes, exactly as collected, always ride with the
   event (`raw_message`, plus `raw_bytes` when transport supplies them).
2. Never delete data because the normalized schema lacks a field (Rule 9). Unmapped fields go to
   `vendor` (mapped vendor-specific) or `unknown` (unmapped) — both are preserved and delivered.
3. Never replace unknown data with guessed data (Rule 8). Absence of evidence = absence of field,
   never a fabricated placeholder value.
4. Type conversion may not destroy representation: `"00123"` normalizes to integer `123` only if a
   normalized `original.src` of the literal `"00123"` also survives. Values that lose information
   under conversion keep their original string in `original.*` / `vendor.*`.
5. Partial parse preserves everything: extracted fields + unparsed remainder + raw + status.
6. Unknown sources are valid events, not errors: collected, framed, decoded, preserved, delivered.
7. Truncation only happens when explicitly configured, is recorded as a status flag, and preserves
   as much original information as possible.
8. SIEM serialization must carry raw + vendor + unknown fields wherever the destination format
   permits (JSON-based targets: always; LEEF: raw in extension or as documented).
9. The lossless test (build plan §50) must be able to reconstruct `raw_message` after every stage:
   framing → parsing → extraction → normalization → validation → SIEM serialization.

## Event layers (information model, build plan §10)
ingestion metadata · transport metadata · source identity · protocol metadata · original raw event ·
decoded representation · normalized fields · vendor-specific fields · unknown fields ·
parser metadata · validation metadata.

## Test discipline
Any change that reduces recovered information must fail the lossless/no-silent-loss tests.
