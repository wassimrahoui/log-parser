# Research — SIEM delivery targets: Wazuh, Elasticsearch, QRadar, spool

Family: SIEM integration endpoints
Sources researched: Wazuh documentation "Configuring syslog on the Wazuh server" (UDP/TCP 514
reception, `<location>facility:program` tagging semantics), Wazuh blog rsyslog client guide,
Elastic/OpenSearch bulk API docs (NDJSON action lines `{"index":{"_index":"..."}}` + source,
Content-Type application/x-ndjson), IBM QRadar LEEF docs (LEEF over syslog TCP/UDP to port 514,
tab-delimited attributes), NXLog LEEF integration page.

## Wazuh

- Manager receives syslog from firewalls/switches/etc. via wazuh-remoted: UDP or TCP port 514
  (config `<remote><connection>syslog</connection><port>514</port><protocol>udp|tcp</protocol>`).
- Delivery format: any syslog; recommended RFC3164-style `<PRI>TIMESTAMP HOSTNAME TAG: MSG`.
  Wazuh decoders key on program name (TAG) and message content. TCP transport: newline-framed
  (non-transparent framing) is the safe default for wazuh-remoted.
- Our adapter: serialize lossless event to a deterministic JSON payload carried in the syslog
  MSG portion, TAG fixed by config (default `ulstp`); raw_message embedded as JSON string field
  (safe escaping); keep PRI configurable (default `<134>` local4.info). This preserves full
  event fidelity inside a syslog envelope Wazuh natively accepts.

## Elasticsearch / OpenSearch (ELK)

- `_bulk` endpoint: NDJSON body — action line `{"index": {"_index": "name"}}` then source line;
  final newline required. Content-Type `application/x-ndjson`. Response `errors:true` + per-item
  error objects must be checked per item; HTTP-level 200 can still contain item failures
  (never claim delivered without checking `errors` per item — Rule 10 honesty).
- Index naming: time-based (`ulstp-YYYY.MM.dd`) computed from event timestamp (configurable).
- Auth: none / API key / basic — from config/env only (Skill 08). TLS optional via https URL.

## QRadar

- LEEF over syslog (TCP or UDP) to port 514; LEEF:1.0 tab-delimited attributes;
  syslog header prefix (RFC3164 style) recommended. EventID/vendor/product from header map.
- Our adapter: LEEF serialization — header fields from source identity; extension = normalized
  key subset + `cat=...` + raw preserved in `raw<tab>` pair? IBM permits arbitrary key=value
  attributes; we emit all unknown/vendor fields as `u_`-prefixed safe keys + `raw=` full raw
  message with tab/newline escaped. Deterministic mapping documented in adapter doc.

## Local spool (delivery verification target)

- JSONL append-only file target implementing the same DeliveryTarget interface: used for
  E2E/golden tests, replay verification, and as guaranteed-lossless fallback destination.
  Each line: the full lossless event JSON (all layers) — proves raw recovery after SIEM
  serialization for JSON-capable targets.

## Parser/adapter implications
- Delivery statuses: DELIVERED / FAILED (transient, retried) / REJECTED (permanent; event then
  routed to spool — never silently discarded, §29/§30).
- Batch behavior: Elasticsearch batches (bounded), syslog adapters line-per-message.
- All adapters: no fabricated success; explicit error taxonomy SIEM_DELIVERY_ERROR.
