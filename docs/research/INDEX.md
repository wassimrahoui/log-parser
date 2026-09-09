# Research Index — Universal Lossless SIEM Telemetry Platform

Research per Skill 01 (records in `docs/research/`). Each record documents variants, deviations,
ambiguities, references, and parser implications. Research is iterative (§45): findings discovered
during implementation/testing are appended to these records and feed parser updates.

| Record | Family | Covers |
|---|---|---|
| `protocols-syslog-rfc3164-5424-6587.md` | Syslog transport+format | RFC 3164 grammar + deviations, RFC 5424 grammar + structured data, RFC 6587 TCP framing (octet counting vs newline), malformed corpus plan |
| `formats-cef-leef.md` | SIEM interchange formats | CEF header/extension/escaping + real deviations, LEEF 1.0/2.0 incl. hex delimiters, predefined keys |
| `formats-kv-json-csv-plaintext.md` | Generic structured text | KV/logfmt (FortiGate/SonicWall signatures), JSON Lines (duplicate-key preservation), CSV/TSV config-driven schemas, positional plain text |
| `vendors-cisco-asa-fortigate.md` | Vendor telemetry | Cisco ASA/PIX/FWSM `%ASA-sev-id` structure + researched message sub-grammars, FortiGate KV field dictionary + version deltas |
| `siem-targets-wazuh-elastic-qradar.md` | SIEM integration | Wazuh syslog reception semantics, Elasticsearch `_bulk` NDJSON + per-item error checking, QRadar LEEF delivery, local spool target |

## Research status

- Researched: syslog family, CEF, LEEF, KV/logfmt, JSON Lines, CSV, plain text, Cisco ASA,
  FortiGate, Wazuh/Elastic/QRadar delivery protocols.
- Known gaps (tracked for §55 gap analysis, researched on demand when corpus requires):
  Palo Alto LEEF details, SonicWall full field dictionary, Linux syslog daemons (rsyslog/
  syslog-ng emit-side quirks), Windows Event Forwarding rendering, reverse DNS/DHCP server
  formats, legacy formats (MIT syslog, Sun Solaris), cloud-service export formats (AWS/GCP/Azure
  export JSON shapes), IDS/IPS (Snort/Suricata fast.log, Zeek TSV).

## Confidence notes

- Syslog/CEF/LEEF/Wazuh/Elastic/QRadar: corroborated across ≥2 independent references each.
- FortiGate fields: official Log Reference + ManageEngine + captured-line report (3 sources).
- Cisco ASA message sub-grammars: Cisco FAQ/MARS samples (2 sources); only researched IDs get
  sub-parsers (Rule 4: no invented fields for un-researched IDs).
