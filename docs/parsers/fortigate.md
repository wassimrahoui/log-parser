# Parser: fortigate

Contract per Skill 02. Research: `docs/research/vendors-cisco-asa-fortigate.md`.

| Property | Value |
|---|---|
| Name / version | `fortigate` 1.0.0 |
| Accepts | `logid=` + `type=` + `subtype=` KV signature (10-digit logid regex) |
| Formats | key_value (as inner chain under syslog envelopes, or bare) |
| Extracts | every key present: mapped keys → normalized, ALL keys → vendor layer |
| Types | ports/bytes/duration int; policyid int; timestamps explicit (date=+time=, or eventtime epoch-ms) |
| Vendor-specific | `fortigate.*` namespace (complete), plus `vd`→vdom, `devid`→observer.serial_number |
| Optional | timestamp fields (absence noted, never guessed) |
| Failure | no logid ⇒ FAILED (caller falls back); invalid timestamp noted, preserved |
| Remains raw | everything; `original.fortigate.<key>` for every key incl. quoting |
| Tests | unit (basic/eventtime/vendor-layer), golden, malformed corpus |
| Covers | FortiOS ≥5 default KV telemetry (logid/type/subtype/level structure) |
| Does NOT cover | CEF mode, FortiOS 8 custom templates (extension point: template config) |
