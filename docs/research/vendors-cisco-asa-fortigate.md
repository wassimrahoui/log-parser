# Research — Vendor telemetry: Cisco ASA/FPIX and Fortinet FortiGate

Family: network/security appliance syslog
Sources researched: Cisco "ASA FAQ: How do you interpret the syslogs" (cisco.com, %ASA-6-302013
samples), Cisco Security Manager user guides (message structure `%ASA-severity-messageID: text`),
Cisco MARS guide (timestamp + host + colon prefix), Fortinet FortiOS 7.4.7 Log Reference (PDF,
field dictionary), Fortinet docs "Log message fields" (FortiOS 8.0.0), ManageEngine FortiGate
syslog analysis page, vector issue #20886 (real captured FortiGate lines), Fortinet community
RFC6587 troubleshooting note.

## Cisco ASA / FWSM

- Structure: `%ASA-Severity-MessageID: Message text` (also `%PIX-`, `%FWSM-`, `%ASDM-`).
- Often inside 3164 envelope: `<163>Mar 19 2007 21:05:59 2.168.154.2 : %ASA-2-302013: Built
  outbound TCP connection 42210 for outside:9.1.154.12/23 (...) to inside:.../... (...)`.
  Variants: year present or absent; ` : ` before %ASA sometimes absent; hostname may be IP.
- Message text grammar varies per message ID (302013/302014 built/teardown, 302015 built UDP,
  106023 deny, 733100 threat, etc.) — positional with interface:ip/port tuples and parens
  duplication. Parser: extract ID/severity/daemon from %token (deterministic); message-text
  sub-parsers for a researched subset (302013/302014/302015/106023/302020), remaining text kept
  raw + `unknown`. No invented fields for un-researched IDs (Rule 4).
- Facility mapping: PRI severity redundant with token severity; both preserved; discrepancy
  recorded in validation notes (observed when devices misconfigure).

## Fortinet FortiGate

- Structure (default KV over RFC3164 or 5424): `date=2024-01-12 time=10:22:11 logid="0000000013"
  type=event subtype=system level=information vd="root" ... eventtime=1705048931... logdesc="..."
  msg="..."`.
- Fields per Log Reference: date, time, logid, type (event/traffic/utm/ani/virus/web/attack...),
  subtype, level (emergency..debug / information/notice/warning/error/critical/alert), vd, srcip,
  dstip, srcport, dstport, proto, action, policyid, service, sessionid, duration, sentbyte,
  rcvdbyte, user, group, dstcountry, srccountry, hostname, url, msg, logdesc, eventtime, ui, action.
- Version deltas: FortiOS 7.4 Log Reference field sets vs 8.0 custom templates; `logid` format
  `0000000013` (10 digits: 3+4+3 structure); CEF mode exists but default remains KV (2025
  community report).
- Transport: UDP/514 default; TCP with RFC6587 framing supported (Fortinet doc note).
- Quirks: quoted values contain spaces (msg, logdesc, hostname); fields order varies by type;
  eventtime epoch-millis (ms since epoch, may exceed 2^53 — keep string + parsed int on 64-bit).

## Parser implications
- ASA: `%token` regex `%(ASA|PIX|FWSM|ASDM)-([0-7])-(\d{5,6})` → daemon/severity/msgid; message
  sub-grammar per researched ID; everything else preserved.
- FortiGate: KV parse → map researched keys to normalized (srcip→source.ip, dstip→destination.ip,
  etc.); ALL keys also kept in vendor layer; logid/type/subtype/level → event metadata; quoted
  values unquoted for normalized copy, original quoting noted when significant.
- Source INFERRED evidence: `%ASA-` prefix signature; `logid=`+`type=`+`subtype=` signature.
- Malformed corpus: truncated KV, unbalanced quotes, missing date/time, unknown logids.
