# Parsers: syslog (rfc5424, rfc3164)

Contracts per Skill 02. Research: `docs/research/protocols-syslog-rfc3164-5424-6587.md`.

## rfc5424 (1.0.0)

| Property | Value |
|---|---|
| Accepts | `<PRI>VERSION TS HOST APP PROCID MSGID [SD] MSG` — VERSION digit is the deterministic trigger |
| Extracts | pri, facility, severity, version, timestamp (RFC3339→UTC), hostname, appname, procid, msgid, structured-data elements+params, message |
| Types | facility/severity/pri int; timestamp ISO-8601 UTC |
| Deviations tolerated | PRI out of range (PARTIAL + note), invalid RFC3339 (note + preserved), SD omitted (note), SD unbalanced (preserved as text), duplicate SD params (kept, `#n`) |
| Failure | header mismatch ⇒ FAILED (caller falls back) |
| Remains raw | `original.{pri,timestamp,hostname,appname,procid,msgid,sd.*}` |
| Tests | unit + golden + malformed corpus |

## rfc3164 (1.0.0)

| Property | Value |
|---|---|
| Accepts | `[PRI]Mmm dd hh:mm:ss [HOST] [TAG[pid]:] MSG` — day space/zero-padded |
| Extracts | pri, facility, severity, timestamp, hostname, tag, pid, message |
| Year policy | explicit reference-year provider (default: ingestion year); ALWAYS noted as inference |
| Deviations tolerated | PRI absent (note), trailing-colon host (normalized+note), CEF/LEEF content not treated as tag, invalid month/time (note + preserved) |
| Failure | timestamp grammar mismatch ⇒ FAILED |
| Remains raw | `original.{pri,timestamp,hostname,tag,message}` |
| Tests | unit + golden + malformed corpus |

# Parsers: cef / leef

Research: `docs/research/formats-cef-leef.md`.

## cef (1.0.0)

| Property | Value |
|---|---|
| Accepts | `CEF:N|...|` (regex `CEF:\d+\|`), optional RFC3164 prefix |
| Header handling | split on UNESCAPED pipes first (Name may contain spaces — real-world case); <7 fields ⇒ FAILED with partial decode preserved |
| Extension | key-anchored scan; value boundaries = unescaped space before `key=`; escapes `\= \\ \n \r` decoded for normalized copy (originals raw) |
| Severity | 0–10 int or Unknown/Low/Medium/High/Very-High strings → mapped int (raw kept) |
| Unknown keys | preserved (`cef.ext.<key>`); duplicates (`key#2`) preserved; unpaired tokens preserved + noted |
| Tests | unit (escapes, spaces-in-name, severity strings, unpaired, duplicates) + golden + malformed |

## leef (1.0.0)

| Property | Value |
|---|---|
| Accepts | `LEEF:x.y|V|P|Ver|EventID[|delim]|attrs` (regex), optional syslog prefix |
| Delimiter | LEEF 2.x field: single char or 0x/x hex; default tab; absent-tab deviation → space key-anchor fallback (noted) |
| Attributes | every key extracted; duplicates `key#n` → unknown layer; unpaired preserved; first delimiter after EventID separates header |
| Unknown keys | preserved (`leef.attr.<key>`) |
| Tests | unit (tab/custom/hex/duplicates/deviation) + golden |

# Parsers: key_value / json / csv / plain_text

Research: `docs/research/formats-kv-json-csv-plaintext.md`.

| Parser | Accept trigger | Notes |
|---|---|---|
| `key_value` | ≥2 `key=value` tokens | quoting + escapes; duplicates `k#n`; unpaired tokens preserved; generic alias map |
| `json` | leading `{`/`[` | duplicate keys preserved via object_pairs_hook; arrays intact; non-object top-level → unknown layer; depth cap preserves remainder |
| `csv` | delimiter present, single record | schema from config only; column mismatch or no schema ⇒ PARTIAL with `col_N` columns |
| `plain_text` | always (fallback carrier) | lossless preservation; pipeline reports UNKNOWN_FORMAT status when used as fallback |
