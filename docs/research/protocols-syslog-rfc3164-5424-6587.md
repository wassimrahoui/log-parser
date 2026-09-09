# Research — Syslog protocol family (RFC 3164, RFC 5424, RFC 6587)

Family: Syslog transport+format
Sources researched: RFC 5424 (rfc-editor.org/rfc/rfc5424), RFC 6587 (rfc-editor.org/info/rfc6587),
RFC 3164 (rfc-editor.org/rfc/rfc3164), Graylog "Syslog Protocol: A Reference Guide" (2025),
NXLog "What is syslog?" (2026), Check Point community threads on RFC3164-vs-5424 detection.

## RFC 5424 (IETF syslog)

- Grammar: `SYSLOG-MSG = HEADER SP STRUCTURED-DATA [SP MSG]`
- HEADER = `PRI VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID`
- PRI: 1–3 digits in angle brackets, `PRI = FACILITY*8 + SEVERITY`; severity 0–7
  (0=emerg,1=alert,2=crit,3=err,4=warning,5=notice,6=info,7=debug), facility 0–23.
- VERSION: must be non-zero digit sequence (in practice "1").
- TIMESTAMP: RFC 3339 microsecond-precision, e.g. `2019-01-18T11:07:53.520Z`, `-00:00` offsets
  permitted; NILVALUE `-` allowed.
- HOSTNAME / APP-NAME / PROCID / MSGID: printable ASCII up to 255; NILVALUE `-` allowed.
- STRUCTURED-DATA: zero or more `[ID (PARAM-NAME="PARAM-VALUE")...]`; escaped `\"` and `\\`
  inside param values; NILVALUE `-` when none.
- MSG: any content; BOM permitted; everything after the single SP following STRUCTURED-DATA.
- Key detection fact (Check Point community): presence of VERSION immediately after PRI
  distinguishes 5424 from 3164 in the wild.

## RFC 3164 (BSD syslog)

- Format: `<PRI>TIMESTAMP HOSTNAME TAG[PID]: MSG` — TIMESTAMP `Mmm dd hh:mm:ss` (RFC 3164
  actually has day padded with space, real devices often use zero-padding — accept both).
- Common real-world deviations (observed in reference samples, e.g. Cisco ASA via MARS guide):
  `<PRI>Jan 12 10:22:11 host message` with no TAG, `<PRI>timestamp host: %ASA-...` with colon
  after host, missing hostname, extra spaces, non-gregorian quirks, messages without PRI
  (rare, must be handled as plain-text/unknown-pri events, not dropped).
- TIMESTAMP has no year and no timezone ⇒ year must be inferred deterministically (configurable
  reference clock at ingestion; recorded as inference, never fabricated silently).

## RFC 6587 (syslog over TCP)

- Two framings: **octet counting** (transparent): ASCII decimal byte count + SP + message;
  **non-transparent**: message terminated by LF (CR-LF tolerated).
- Sender may not switch styles mid-connection; receiver must auto-detect per connection
  deterministically: digits then SP at frame start ⇒ octet counting, else newline framing.
- Octet count includes the entire syslog message only (not the count itself).
- TLS syslog (RFC 5425) is octet-counted framing over TLS; out of initial implementation scope,
  documented as extension point.

## Known malformed examples / ambiguities (corpus: tests/telemetry/generic/syslog/)
- `_PRI_` >3 digits, version `0`, missing STRUCTURED-DATA SP, trailing spaces, NILVALUE misuse
  (empty strings instead of `-`), 5424 envelope with 3164 body, embedded newlines inside MSG via
  octet counting (must be preserved), invalid UTF-8 bytes.

## Parser implications
- Frame first (transport concern), then detect 5424 vs 3164 by grammar (VERSION digit after PRI).
- Extract: pri, facility, severity, version, timestamp, hostname, app-name, procid, msgid,
  structured-data (as parsed object + original text), message.
- All header fields preserved verbatim in `original.*`; normalized timestamp requires explicit
  reference-year policy for 3164 (no silent year guessing: status notes the inference source).
- Never reject messages for PRI/header deviations — degrade to PARTIAL/UNKNOWN_FORMAT with
  preservation (Skill 03).
