# Research — CEF (ArcSight) and LEEF (IBM QRadar) event formats

Family: SIEM interchange formats over syslog
Sources researched: Micro Focus/ArcSight CEF implementation standard (cef-implementation-standard),
Delinea "ArcSight CEF format" docs (sample messages), CEF 2007 spec PDF (raffy.ch mirror),
IBM Docs "LEEF event components" + "Predefined LEEF event attributes", NXLog LEEF docs,
Check Point Log Exporter LEEF field mappings, Ubiquiti community report of malformed CEF
(missing Name field — real-world deviation), Microsoft Sentinel CEF field mapping page.

## CEF

- Structure (with syslog transport): `<syslog prefix>CEF:Version|Device Vendor|Device Product|
  Device Version|Device Event Class ID|Name|Severity|Extension`
- Extension: space-separated `key=value` pairs; predefined ArcSight dictionary keys (src, dst,
  spt, dpt, suser, duser, msg, rt, cs1/cs1Label, ...); vendor custom keys allowed.
- Escaping (per spec): `\=` escapes `=`, `\\` escapes `\`, `\n` newline, `\r`; header pipe fields
  escaped with `\|`. Real devices frequently under-escape; parser must be tolerant and preserve
  raw. Values may contain spaces (extension parsing is key-anchored, not space-split).
- Severity in header may be 0–10 integer or string (Unknown/Low/Medium/High/Very-High); both
  preserved; numeric mapping normalized, string kept verbatim too.
- Known real-world deviations: missing Name field (Ubiquiti UniFi), unescaped pipes in Name,
  missing Extension entirely, duplicate keys (later occurrences preserved with index), empty
  values, keys without `=` (preserve as unpaired token), syslog prefix present or absent.
- Timestamps: `rt` is epoch millis; `rt=1525844566655` style observed (Delinea sample).

## LEEF

- Structure: `[syslog header SP] LEEF:Version|Vendor|Product|Version|EventID[|DelimiterChar]|attributes`
- LEEF 1.0: attributes tab-separated `key=value`. LEEF 2.0: custom delimiter char in header,
  possibly hex `0xNN`/`xNN` form (e.g. `x5E` = caret, `x7c` = broken bar).
- Predefined attributes (IBM): src, dst, sev, cat, srcPort, dstPort, usrName, identic/identSrc,
  moduleName, ... (subset used for normalization mapping; full list kept in parser mapping).
- Syslog header optional; RFC 3164 or 5424 header per IBM examples.
- Deviations: spaces instead of tabs (seen in exported logs), LEEF:1.0 with non-tab delimiters,
  hex delimiter case variations, EventID textual or numeric (≤255 chars).

## Parser implications
- Both formats may ride inside syslog envelopes: syslog parsing first, format detection on MSG.
- CEF: header split on unescaped pipes only; extension scan by `key=` anchors with escape
  decoding; every key extracted (§16: every field, not just known ones); unknown keys preserved.
- LEEF: delimiter resolved from header (tab default; LEEF 2.x custom incl. hex); keys case-
  sensitive as emitted; duplicates preserved with ordinal suffix in unknown layer.
- Severity/delimiter/escaping rules documented per parser in docs/parsers/.
- Both deliver losslessly: raw_message always retained; extension/attributes also kept as
  `vendor.*`/`unknown.*` in addition to normalized fields.
