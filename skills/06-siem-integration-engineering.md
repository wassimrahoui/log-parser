# SKILL 06 — SIEM INTEGRATION ENGINEERING

## Purpose
Deterministic, honest delivery of lossless events to the configured SIEM. The platform is NOT a
SIEM; it is a lossless collection/normalization/delivery pipeline.

## Rules
1. Only the configured target receives events. Adapters exist for: Wazuh (TCP syslog with
   optional per-target formatter), Elasticsearch/Elasticsearch-free file fallback (JSON Lines over
   HTTP _bulk), QRadar (LEEF over TCP syslog), generic syslog, and a local JSONL spool target
   used for delivery verification and testing.
2. Serialization must preserve: raw_message, source identity, normalized fields, vendor fields,
   unknown fields, parser metadata, validation status. JSON-based targets carry all layers.
3. NEVER claim delivery success that did not happen. Delivery result is deterministic:
   delivered / failed / rejected with reason. No silent discard on failure (Rule 27).
4. Failed deliveries go to a bounded retry queue, then a bounded disk spool; exhaustion is
   reported, never silently absorbed (§30).
5. Adapter behavior is configuration-driven; credentials come from configuration/environment, are
   never logged, never embedded in code, never placed in serialized events (Skill 08).
6. An adapter integration is "supported" only after a real delivery test against the real target
   (Rule 10). Until then it is documented as "implemented, delivery-verification pending".
7. Batch where the target protocol supports it (Elasticsearch `_bulk` NDJSON), with bounded batch
   size and deterministic ordering per worker.
