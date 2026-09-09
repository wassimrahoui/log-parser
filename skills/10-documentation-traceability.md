# SKILL 10 — DOCUMENTATION & TRACEABILITY ENGINEERING

## Purpose
Every major implementation decision is traceable: Requirement → Research → Design →
Implementation → Test → Verification.

## Structure maintained
```text
docs/
  BUILD_STATUS.md          ← always current (see below)
  REPOSITORY_ANALYSIS.md   ← Phase 1
  RESEARCH_GAP_ANALYSIS.md ← final research gap analysis (§55)
  research/<vendor>-<product>.md   ← per-source research records (Skill 01 template)
  architecture/            ← ARCHITECTURE.md + stage-specific notes
  parsers/                 ← per-parser contracts (accept grammar, fields, deviations, tests)
  testing/                 ← test strategy + results records
```

## BUILD_STATUS.md must always contain
Current phase · Current step · Current objective · Completed requirements · Tests completed ·
Tests failing · Known limitations · Research completed · Research still required · Current
blockers · Next exact action.

## Rules
1. Documentation corresponds to the actual implementation — never document functionality that
   does not exist (§58).
2. Limitations are documented, never hidden (Rule 7). "Implemented, delivery-verification pending
   external SIEM" is an acceptable, honest state (§60).
3. Update BUILD_STATUS.md after every phase gate, recording test counts and next action.
4. Every parser has a doc page in `docs/parsers/` matching the Skill 02 contract.
5. Traceability: parser doc pages cite research records; tests cite samples.
