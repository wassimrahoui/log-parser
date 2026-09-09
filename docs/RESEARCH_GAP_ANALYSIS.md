# FINAL RESEARCH GAP ANALYSIS (build plan §55)

Honest accounting of researched coverage vs. remaining gaps. The platform is
research-driven and extensible — it does NOT claim universal vendor coverage
(Rule 12, §47).

## Researched and implemented (with corpus + tests)

| Family | Formats | Research record | Parsers |
|---|---|---|---|
| Syslog protocols | RFC 3164, RFC 5424, RFC 6587 framing | protocols-syslog-rfc3164-5424-6587.md | rfc5424, rfc3164 |
| SIEM interchange | CEF, LEEF 1.x/2.x (hex delimiters) | formats-cef-leef.md | cef, leef |
| Generic structured | KV/logfmt, JSON Lines, CSV/TSV | formats-kv-json-csv-plaintext.md | key_value, json, csv |
| Vendor appliances | Cisco ASA/PIX/FWSM/ASDM (302013/302014/302015), FortiGate KV | vendors-cisco-asa-fortigate.md | cisco_asa, fortigate |
| SIEM delivery | Wazuh syslog, Elasticsearch/OpenSearch _bulk, QRadar LEEF, spool | siem-targets-wazuh-elastic-qradar.md | delivery.py adapters |

## Researched but not yet implemented as parsers (documented, extension-ready)

- SonicWall KV (signature exists in source identification; full field
  dictionary not yet transcribed — Rule 4 blocks a field mapping without it).
- Windows Event Forwarding rendering (brittle positional format; needs corpus).
- Apache/nginx combined access log (positional grammar documented in research).

## Not yet researched (gaps — deliberately not guessed at)

- Palo Alto LEEF specifics, Juniper, Check Point native formats.
- IDS/IPS: Snort/Suricata fast.log, Zeek TSV logs.
- Cloud exports: AWS CloudWatch/GuardDuty JSON shapes, Azure Event Hub payloads,
  GCP export formats.
- Legacy Unix: Solaris/BSD syslogd emit quirks, MIT syslog variants.
- Databases/middleware: PostgreSQL/MySQL/Oracle audit formats, IIS W3C.
- Industrial/legacy protocols where documentation is scarce (Rule 1 applies:
  no parser without documentation or samples).

## Unknown-source behavior (verified, not a gap)

Telemetry from any unresearched source is: collected → framed → decoded →
format-detected (best-effort, deterministic) → preserved losslessly with
explicit UNKNOWN status → delivered. Verified by tests/test_golden.py
(TestUnknownSource, TestNoSilentLoss).

## Expansion path

New vendor = research record + parser class (registry entry + optional source
signature) + corpus + golden case. No core redesign required (§48). The KV/CEF
extension-dictionary pattern makes most vendor additions mapping-only.
