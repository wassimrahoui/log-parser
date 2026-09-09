# SKILL 05 — LOG FORMAT & PROTOCOL ENGINEERING

## Purpose
Deterministic handling of telemetry transport and formats, based on how real devices actually
behave — including their RFC deviations.

## Formats / transports in scope
Syslog (RFC 3164, RFC 5424, bsd-style deviations) · UDP/TCP/TLS syslog framing (datagram,
newline-delimited, RFC 6587 octet counting) · JSON / JSON Lines · CEF · LEEF · key=value (logfmt) ·
CSV/TSV · XML · plain text · multiline application logs · Windows Event Log rendering ·
file-based telemetry.

## Rules
1. TRANSPORT ≠ FORMAT (§22): a UDP datagram, a TCP stream frame, and a file line are carriers.
   Framing/decoding happens first and separately from format detection and parsing.
2. Do not assume every syslog message is RFC 5424. Real devices emit: broken PRI, missing or
   malformed timestamps, RFC 3164 bodies inside 5424 envelopes, 5424 with no STRUCTURED-DATA
   variations (nil `-` vs omitted), wrong hostname/appname content, trailing garbage.
   The framing/decoding layer must survive all of these.
3. RFC 6587/TCP: support both octet-counted frames (`123 <5>...`) and newline-delimited frames;
   auto-detect per connection deterministically (first byte is a digit followed by a space →
   octet count), never switch styles mid-frame.
4. Encoding: UTF-8 is the default; invalid UTF-8 is preserved losslessly (latin-1 fallback for
   decoding views, raw bytes retained) — never dropped or replaced with placeholder text.
5. Format detection is ordered and deterministic (§23): RFC5424 grammar → CEF/LEEF signatures →
   JSON → RFC3164 grammar → key=value → CSV/TSV → XML → plain text → unknown. Each detector is a
   pure function of the decoded message.
6. Multiline: file sources support explicit continuation rules from configuration only; without
   configuration, every line is its own event (no guessing merges).
7. Every format handler documents its acceptance grammar and its known real-world deviations in
   `docs/research/`.
