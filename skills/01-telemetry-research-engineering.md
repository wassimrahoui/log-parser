# SKILL 01 — TELEMETRY RESEARCH ENGINEERING

## Purpose
Systematically discover how real-world telemetry is generated and structured BEFORE writing
parsers. Parsers are written from research, never from memory-assumption.

## Rules
1. Never assume a vendor's telemetry format from memory — research it (anti-hallucination Rule 1).
2. Never assume one version represents all versions (Rule 2). Research version deltas.
3. Never assume RFC compliance in the wild (Rule 3). Find real samples and documented deviations.
4. Research must cover: common, uncommon, obscure, legacy, proprietary, malformed,
   version-specific, vendor-specific and platform-specific telemetry variants.
5. Never invent fields (Rule 4). A field enters a parser only if documentation or a real sample
   shows the source emits it.
6. Document every researched source in `docs/research/` using the template below.

## Research sources (in priority order)
Vendor message reference guides and event catalogs → product configuration guides → RFCs and
protocol specs → sample logs/datasets → open-source deterministic parser implementations
(e.g. syslog-ng/rsyslog pattern DBs, Logstash filters, Wazuh decoders, Elastic integrations
packages) → legacy documentation → version-specific release notes.

## Per-source research record (docs/research/<vendor>-<product>.md)
Must document: Vendor; Product; Product family; Platform; Firmware/OS version; Transport;
Protocol; Framing; Encoding; Message format; Header structure; Timestamp format; Hostname
representation; Facility; Severity; Message body structure; Key-value fields; Positional fields;
Nested fields; Arrays; Repeated fields; Identifiers; Network fields; Authentication fields;
Process fields; Application fields; Error fields; Vendor-specific fields; Optional fields;
Version-specific fields; Known variations; Known malformed examples; Known ambiguities; Reference
sources (URLs); Parser implications.

## Method
- Ask "what telemetry variants actually exist for this source?" not "what do most logs look like".
- One sample is not research. Corroborate across at least two independent references when possible;
  when only one source exists, record that as a research-confidence note.
- When a parser reveals a new real-world pattern during testing, loop back: research → adjust
  parser → test (research loop, build plan §45).
