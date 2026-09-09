# SECURITY REVIEW (build plan §56; Skill 08)

Scope: the telemetry platform itself (collector, parser, API, delivery).
Every incoming message is treated as hostile.

## Checklist and status

| Area | Status | Evidence |
|---|---|---|
| Size limits before allocation | DONE | limits.py; framing buffer cap; collectors (tests/test_limits.py) |
| Frame validation | DONE | TcpFramer (invalid/oversized octet counts → FRAME_ERROR, connection-scoped) |
| Safe decoding | DONE | stdlib bytes→str only; invalid UTF-8 preserved via latin-1 mapping + raw b64 |
| No code execution from telemetry | DONE | no eval/exec/pyeval anywhere in ulstp; json.loads only (no pickle/yaml) |
| XML handling | N/A (deferred) | XML detector exists; no XML parser implemented ⇒ no XXE surface. Deferred until needed; when added, must use defusedxml or stdlib with entity resolution disabled. |
| JSON depth/size abuse | DONE | depth cap preserves remainder verbatim; abuse corpus covered (tests/test_limits.py) |
| Log injection | MITIGATED | telemetry never rendered to shell/logs as commands; API escapes HTML (<, &); control chars JSON-escaped in serialization (asserted in tests) |
| Command injection | DONE | no subprocess/shell use anywhere in the runtime path |
| Path traversal | DONE | file collector path comes from configuration only (operator-controlled), never from telemetry content |
| Credential handling | DONE | secrets from env vars referenced by `*_env` config keys; never logged, never serialized into events; API/Delivery never echo Authorization material |
| Network exposure | DONE (config responsibility) | API binds 127.0.0.1 by default; listeners bind per config; documented operator decision |
| Connection exhaustion | DONE | max_connections per listener; over-limit connections counted + closed |
| Queue exhaustion | DONE | bounded queues; overflow counted; delivery overflow → spool; spool bound configurable |
| Oversized messages | DONE | UDP (pre-check + WSAEMSGSIZE classification), TCP (buffer cap), file (line cap) |
| DoS via parser abuse | TESTED | abuse corpus (huge tokens/fields, 500 header fields, 300 KV pairs, deep JSON, control chars) all survive with preservation |
| Unsafe deserialization | DONE | none used |

## Residual risks (documented, accepted for scope)

1. The API has no authentication (operator-facing, loopback default). Exposing
   it beyond loopback is an operator decision; auth is an extension point.
2. Resource limits are per-process; a coordinated flood can fill the bounded
   queue — the outcome is explicit backpressure + counted rejection (never
   silent loss, but loss is possible under extreme flood by design; §39).
3. Parsers do not enforce per-field size for every normalized copy (field-size
   cap applies at collector layer; extreme single fields are preserved whole).

All findings above are recorded; no unhandled high-severity issues remain open.
