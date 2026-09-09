# Project Skills — Universal Lossless SIEM Telemetry Platform

Freebuff (this environment) exposes **no native skill-registration API** to the agent. Per the
build plan §3, the project-local equivalent lives here: ten skill files that are **mandatory
reading** at session start.

## How skills are loaded (loading protocol)

1. At the start of every session, read `docs/BUILD_STATUS.md` → "Current Phase".
2. Read `skills/INDEX.md` (this file) and re-read all ten skill files below.
3. Apply every skill rule for the phase being executed. Skill rules override convenience.
4. Before any phase gate, re-check the skill checklist in §5 of the build plan.

## Mandatory skills

| #  | File                                        | Skill                                    |
|----|---------------------------------------------|------------------------------------------|
| 01 | `skills/01-telemetry-research-engineering.md`   | Telemetry Research Engineering           |
| 02 | `skills/02-deterministic-parser-engineering.md` | Deterministic Parser Engineering         |
| 03 | `skills/03-lossless-data-engineering.md`        | Lossless Data Engineering                |
| 04 | `skills/04-source-identification-engineering.md`| Source Identification Engineering        |
| 05 | `skills/05-format-protocol-engineering.md`      | Log Format & Protocol Engineering        |
| 06 | `skills/06-siem-integration-engineering.md`     | SIEM Integration Engineering             |
| 07 | `skills/07-testing-verification-engineering.md` | Testing & Verification Engineering       |
| 08 | `skills/08-security-engineering.md`             | Security Engineering                     |
| 09 | `skills/09-performance-resource-engineering.md` | Performance & Resource Engineering       |
| 10 | `skills/10-documentation-traceability.md`       | Documentation & Traceability Engineering |

## Activation checklist (build plan §5)

```text
[x] Telemetry Research Engineering        skills/01-telemetry-research-engineering.md
[x] Deterministic Parser Engineering      skills/02-deterministic-parser-engineering.md
[x] Lossless Data Engineering             skills/03-lossless-data-engineering.md
[x] Source Identification Engineering     skills/04-source-identification-engineering.md
[x] Log Format & Protocol Engineering     skills/05-format-protocol-engineering.md
[x] SIEM Integration Engineering          skills/06-siem-integration-engineering.md
[x] Testing & Verification Engineering    skills/07-testing-verification-engineering.md
[x] Security Engineering                  skills/08-security-engineering.md
[x] Performance & Resource Engineering    skills/09-performance-resource-engineering.md
[x] Documentation & Traceability          skills/10-documentation-traceability.md
```

All skills are plain files read directly by the agent at session start (loading protocol above).
There is no external skill runner in this environment; this index is the activation record.
