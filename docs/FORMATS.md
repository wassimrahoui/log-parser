# FORMAT REFERENCE

What each parser accepts, extracts, and tolerates — with real before/after
examples. Grammars are deterministic; where a "known deviation" is listed, the
parser tolerates it and records a note rather than failing.

Legend: ✓ = extracted · ◻ = tolerated+noted · raw = preserved verbatim.

---

## RFC 5424 — `rfc5424` (ulstp/parsers/rfc5424.py)

Grammar (RFC 5424 §6): `<PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA [MSG]`

```text
input:
<134>1 2026-09-09T12:00:00.000Z fw01.corp sshd 1234 ID313 - Accepted publickey

┌─────┬───────┬──────────────────────────┬──────────┬──────┬──────┬──────┬─────────────────┐
│ pri │ ver   │ timestamp                │ hostname │ app  │ proc │ msgid│ message         │
│ 134 │ 1     │ 2026-09-09T12:00:00.000Z │ fw01.corp│ sshd │ 1234 │ ID313│ Accepted pubkey │
└─────┴───────┴──────────────────────────┴──────────┴──────┴──────┴──────┴─────────────────┘
   PRI 134 → facility 16 (local0) · severity 6 (info)
```

| Item | Behavior |
|---|---|
| Structured-data `[id@p k="v"]` | ✓ parsed → `vendor: log.syslog.structure.<id>`, escaped `\"`/`\\` decoded; per-element raw in `original.sd.<id>` |
| NILVALUE `-` fields | ✓ → explicit `None` (absence preserved, not silently dropped) |
| PRI > 191 | ◻ `PRI_OUT_OF_RANGE`, status PARTIAL |
| Invalid RFC3339 | ◻ `INVALID_TIMESTAMP`, value kept in `original.timestamp` |
| SD omitted entirely (non-conformant, seen in the wild) | ◻ `SD_OMITTED`, text kept as message |
| Unbalanced SD brackets | ◻ preserved as SD text + noted |
| Duplicate SD params | ✓ kept as `k#2` (Rule 9) |

---

## RFC 3164 (BSD) — `rfc3164` (ulstp/parsers/rfc3164.py)

Grammar: `[<PRI>]Mmm dd hh:mm:ss [HOST] [TAG[pid]:] MESSAGE`

```text
input:  <134>Jan 12 10:22:11 FW01 sshd[123]: hello world
        └pri┘└─ timestamp ─┘ └─host─┘ └tag─┘└pid┘ └─ message ──┘
```

| Item | Behavior |
|---|---|
| Zero-padded OR space-padded day | ✓ both (real devices do both) |
| Missing PRI | ◻ `PRI_ABSENT` — priority fields explicit None |
| Missing year / timezone | ✓ normalized via reference-year policy; ◻ `TIMESTAMP_YEAR_INFERRED` always noted |
| Host with trailing colon (`FW01 :`) | ✓ normalized; ◻ `HOSTNAME_TRAILING_COLON` |
| CEF/LEEF content after header | ✓ NOT treated as a tag (`TAG_SKIPPED` note) — enables the `rfc3164+cef` chain |
| Invalid month/time | ◻ `INVALID_TIMESTAMP`, rest parses, values preserved |

---

## CEF — `cef` (ulstp/parsers/cef.py)

Grammar: `CEF:V\|DV\|DP\|DVer\|SigID\|Name\|Sev\|extension` (optional RFC3164 prefix)

```text
CEF:0│Security│threat-manager│1.0│100│Web login failure│10│src=10.0.0.5 dst=8.8.8.8 spt=1111 msg=Trojan activity WeirdField=abc
  │      │            │         │    │          │          │      └──────── extension (key=value) ────────┘
  │      │            │         │    │          │          └ severity (int 0-10 or word)
  │      │            │         │    │          └ name (may contain SPACES)
  └ version                     sigid ┘│ device version
```

| Item | Behavior |
|---|---|
| Header split | on **unescaped pipes** first — Name may contain spaces (real-world case; space-partitioning would break) |
| Extension scan | key-anchored: value boundary = unescaped space before next `key=` — values may contain spaces (`msg=Trojan activity` ✓) |
| Escapes `\= \\ \n \r` | ✓ decoded in normalized copy; raw kept in `original.cef.<key>` |
| Severity `Unknown/Low/Medium/High/Very-High` | ✓ mapped 0/1/4/8/10; raw string kept too |
| Unknown keys (`WeirdField=abc`) | ✓ → `unknown: cef.ext.WeirdField` |
| Duplicate keys | ✓ `key#2` in unknown layer |
| Unpaired tokens | ✓ → `unknown: cef.ext.unpaired_N` + noted |
| <7 header fields | FAILED, partial decode preserved (nothing lost) |
| Escaped `\|` in Name | ✓ header kept raw (`original.cef.header`) |

---

## LEEF 1.x / 2.x — `leef` (ulstp/parsers/leef.py)

Grammar: `LEEF:V\|Vendor\|Product\|Ver\|EventID[\|Delim]attributes`

```text
LEEF:2.0│Lancope│StealthWatch│1.0│41│^│src=1.2.3.4^dst=2.2.2.2^sev=7
  │        │          │         │   │   └ custom delimiter (char or hex: x5E=^, x7c=¦)
  └ format │        product    │ eventID
        vendor               └ product version
```

| Item | Behavior |
|---|---|
| LEEF 1.x | tab-separated attributes |
| LEEF 2.x delimiter field | single char or `0xNN`/`xNN` hex (IBM spec) |
| Space-separated attributes (common export deviation) | ◻ `LEEF_SPACE_SEPARATOR_DEVIATION` + key-anchor fallback scan |
| Duplicates | ✓ `key#n` → unknown layer |
| Unpaired tokens | ✓ preserved + noted |
| Predefined keys (`src`,`dst`,`sev`,`cat`,`usrName`,…) | ✓ mapped (see `LEEF_KEY_MAP`) |

---

## key=value / logfmt — `key_value` (ulstp/parsers/kv.py)

| Item | Behavior |
|---|---|
| Quoted values (`msg="hello world"`) | ✓ unquoted for normalized; raw (with quotes) in originals |
| Escaped quotes `\"` | ✓ |
| Duplicates (`k=1 k=2`) | ✓ `k`, `k#2` (normalized keeps both visible) |
| Unpaired tokens | ✓ → `unknown: kv.unpaired_N` + noted |
| Values containing `=` | ✓ (tokenizer splits on first `=`) |
| Generic aliases (`src_ip`, `srcport`, `user`, `proto`, …) | ✓ mapped (see `KV_KEY_MAP`) |

---

## FortiGate — `fortigate` (ulstp/parsers/fortigate.py)

Signature: 10-digit `logid=` + `type=` + `subtype=` (researched; no invented
signatures).

| Item | Behavior |
|---|---|
| Timestamp | explicit: `date=`+`time=` (preferred) or `eventtime=` epoch-ms — no year guessing |
| Every key | ✓ in `vendor` layer verbatim (including quoting) — the complete field set is preserved even when unmapped |
| Mapped keys | `srcip`→`source.ip`, `dstip`→`destination.ip`, `srcport/dstport` (int), `proto`, `action`, `user`, `sentbyte/rcvdbyte`, `url`, `hostname`→`url.domain`, … |
| Structure keys | `logid`, `type`, `subtype`, `vd`→`fortigate.vdom`, `devid`→`observer.serial_number`, `policyid` (int), `sessionid`, `logdesc` |
| Missing timestamp fields | ◻ noted (never guessed) |

---

## Cisco ASA / PIX / FWSM / ASDM — `cisco_asa` (ulstp/parsers/cisco_asa.py)

Token grammar (researched): `%DAEMON-SEVERITY-MSGID: body`

```text
%ASA-6-302013: Built outbound TCP connection 9 for outside:10.1.2.1/22 (10.1.2.1/22) to inside:10.1.1.2/53496 (10.1.1.2/53496)
  │  │    │                          └── interface:ip/port tuple (… optional parens dup …)
  │  │    └ message id                                first tuple → source, second → destination
  │  └ severity (0-7)                                 duration/bytes on teardown (302014)
  └ daemon
```

| MsgID | Sub-grammar (research-corroborated samples only) | Extracts |
|---|---|---|
| 302013 / 302015 | Built (outbound\|inbound) TCP/UDP connection N for T1 to T2 | direction, proto, conn id, tuples → source/destination ip+port (int), interfaces |
| 302014 | Teardown TCP/UDP … duration h:mm:ss bytes N [reason] | + `event.duration_seconds`, `network.bytes`, reason preserved in body |
| any other | **no sub-grammar** (Rule 4: no invented fields) | token fields + body verbatim, status PARTIAL, note `ASA_BODY_NOT_SUBPARSED` |

---

## JSON — `json` (ulstp/parsers/json_parser.py)

| Item | Behavior |
|---|---|
| Duplicate keys (`"dup":1,"dup":2`) | ✓ preserved as `dup`, `dup#2` (stdlib `json` alone would silently keep the last — we hook `object_pairs_hook`) |
| Nested objects | ✓ flattened to dotted paths (`json.nested.a.b`) |
| Arrays | ✓ kept as arrays, never joined/lost |
| Non-object top level (`[1,2,3]`, `"str"`, `null`) | ✓ → `unknown: json.value`, noted |
| Depth > `max_nested_depth` (32) | ◻ remainder preserved as-is + `JSON_MAX_DEPTH_EXCEEDED` note |
| Invalid JSON | FAILED + `JSON_INVALID:<detail>`; raw preserved |

---

## CSV / TSV — `csv` (ulstp/parsers/csv_parser.py)

| Item | Behavior |
|---|---|
| Schema | **configuration only** (`schema=[...]`, `delimiter`, `has_header`) — semantics are never guessed |
| No schema configured | ✓ columns as `col_1..col_N`, status PARTIAL (`CSV_NO_SCHEMA`), full data preserved |
| Column-count mismatch | ◻ `CSV_COLUMN_COUNT_MISMATCH` + PARTIAL |
| RFC 4180 quoting (`"x,y"`) | ✓ |
| Delimiter selection | deterministic per message: configured delimiter wins; otherwise comma/tab/semicolon by frequency, ties in that order — recorded in `decoded.csv_delimiter` |

---

## Plain text — `plain_text` (ulstp/parsers/plain.py)

The lossless fallback carrier: everything is kept (`message` + `original.message`
+ line stats), status reported as `UNKNOWN_FORMAT` by the pipeline when used as
fallback. Guaranteed: unknown telemetry is an event, never an error (§12).
