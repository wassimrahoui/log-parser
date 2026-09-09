"""Parser base contract (build plan §15; Skill 02).

Every parser:
- is deterministic (same input + config + parser version => same output),
- declares its name/version/accepted formats/signature,
- returns a ParseResult; never raises through the pipeline (errors become
  status), partial success is a first-class outcome (§13),
- always leaves raw_message intact; extraction adds, never removes.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

PARSER_VERSION = "1.0.0"


@dataclass
class ParseResult:
    fields: Dict[str, Any] = field(default_factory=dict)      # normalized-namespace candidates
    vendor_fields: Dict[str, Any] = field(default_factory=dict)  # vendor-specific (preserved)
    unknown_fields: Dict[str, Any] = field(default_factory=dict) # unmapped (preserved, Rule 9)
    originals: Dict[str, str] = field(default_factory=dict)   # original string reps (Skill 03)
    decoded: Dict[str, Any] = field(default_factory=dict)     # format-level decode view
    protocol_metadata: Dict[str, Any] = field(default_factory=dict)
    status: str = "PARSED"                                     # PARSED | PARTIAL | FAILED
    notes: list = field(default_factory=list)


class Parser:
    """Base class. Subclasses implement _parse(msg) returning ParseResult."""

    name: str = "base"
    version: str = PARSER_VERSION
    formats: tuple = ()            # formats this parser accepts (from format_detection)
    signature: Optional["re.Pattern[str]"] = None  # deterministic accept signature on MSG text

    def accept(self, msg: str) -> bool:
        """Deterministic acceptance: signature must match (when defined)."""
        if self.signature is None:
            return True
        return self.signature.search(msg) is not None

    def parse(self, msg: str) -> ParseResult:
        start = time.perf_counter()
        try:
            result = self._parse(msg)
        except Exception as exc:  # parser must never break the pipeline (Skill 02)
            result = ParseResult(status="FAILED")
            result.notes.append(f"PARSE_ERROR:{type(exc).__name__}:{exc}")
        result.notes.append(f"parser={self.name}@{self.version}")
        return result

    def _parse(self, msg: str) -> ParseResult:  # pragma: no cover - abstract
        raise NotImplementedError
