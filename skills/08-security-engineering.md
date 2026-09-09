# SKILL 08 — SECURITY ENGINEERING

## Purpose
Every incoming telemetry message is hostile input. The platform must survive abuse without data
loss beyond explicitly configured, recorded truncation.

## Hard rules
1. Never execute telemetry as code. Never eval/exec, never interpret log content as commands,
   never trust fields because they came from a "known" device.
2. All external data passes through: size limit → frame validation → decode → parse →
   normalize → validate → output (§38 boundary order).
3. Size/limits enforced BEFORE allocation-heavy work: max message size, max field size, max
   nested depth, max field count, max connections, max queue size, max parse time (§39).
4. No unsafe deserialization: stdlib `json` only for JSON (no pickle/yaml.load-on-untrusted);
   XML parsing limited (defusedxml if available, else no external entity resolution via stdlib
   safe settings).
5. Log injection: control characters from telemetry are escaped/preserved as escapes in emitted
   diagnostics; telemetry content never becomes shell/system input. No shell-outs with telemetry
   data; no path construction from telemetry content (path traversal guard for file/paths).
6. Credential handling: SIEM tokens/passwords from config/env only; never logged, never echoed in
   errors, never serialized into events.
7. Network listeners bind per configuration, default loopback for API/UI; documented exposure.
8. Resource exhaustion (connection flood, oversized messages, queue flood) must end in explicit
   error states (§37), counters, and safe rejection — never a crash that loses buffered telemetry
   silently; spool preserves what it can within configured bounds.
