# SKILL 04 — SOURCE IDENTIFICATION ENGINEERING

## Purpose
Determine telemetry origin using deterministic evidence, with an explainable result.

## Rules
1. Every identification result carries `evidence`: an ordered list of (key, value) facts such as
   `transport=syslog/UDP`, `peer=192.0.2.7`, `port=514`, `configured_source=firewall-a`,
   `rfc5424.appname=sshd`, `signature=<CEF:0|Arcsight|...>`, `parser=<name>`.
2. Prohibited: probabilistic scoring, majority-vote heuristics, "looked like Cisco" reasoning.
3. Evidence is applied in a fixed, documented priority order (build plan §20):
   configured source definition → structured-data/protocol identifiers → message signature →
   transport metadata. First deterministic hit wins; the evidence chain is recorded.
4. Result status is one of: `KNOWN` (explicit rule matched), `INFERRED` (deterministic evidence
   such as vendor signature matched a vendor/product mapping), `UNKNOWN` (no rule matched).
   Never upgrade INFERRED to KNOWN, never invent certainty.
5. Unknown sources remain valid inputs (Skill 03 rules apply).
6. Never fabricate vendor/product fields. An INFERRED result cites the exact signature matched.
7. Configuration can pin a source (listener+peer or file path → known device); explicit config
   always outranks signatures, and the evidence records that.

## Data model
```python
SourceIdentification(status, source_id, vendor, product, parser_hint, confidence_source, evidence)
# confidence_source ∈ {"configured", "signature", "transport", "none"} — deterministic origin tag,
# never a probability.
```
