# Parser: cisco_asa

Contract per Skill 02. Research: `docs/research/vendors-cisco-asa-fortigate.md`.

| Property | Value |
|---|---|
| Name / version | `cisco_asa` 1.0.0 |
| Accepts | `%ASA-`, `%PIX-`, `%FWSM-`, `%ASDM-` tokens (regex, deterministic) |
| Formats | plain_text, rfc3164 (as inner chain under syslog envelopes) |
| Extracts | daemon, severity, message_id, body; researched sub-grammars add: connection id, interface, source/destination ip+port, duration, bytes, transport, direction |
| Types | severity int 0–7; ports int; duration → seconds; bytes int |
| Vendor-specific | `cisco.*` namespace |
| Optional | duration/bytes (teardown only), direction (built only) |
| Failure | no token ⇒ FAILED (caller falls back); unresearched msgid ⇒ PARTIAL with body preserved verbatim |
| Remains raw | everything; `original.cisco.token/body/*_tuple/duration/bytes` |
| Tests | unit (302013/302014/unresearched), golden, E2E via pipeline |
| Covers | message IDs 302013, 302014, 302015 (sub-grammars, corroborated samples); all other IDs: token fields only |
| Does NOT cover | other message-ID grammars (research-gated; no invented fields) |
