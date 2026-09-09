"""Type handling + normalization merge (build plan §12/§13/§17–19; Skill 03).

- Merges ParseResult layers into the LosslessEvent without removing anything.
- Deterministic type checks where the type is KNOWN:
    *.ip       → ipaddress validation (invalid ⇒ kept as string + problem note)
    *.port     → int (parsers guarantee int or None)
    @timestamp → ISO-8601 parse check
- Originals ALWAYS preserved (Skill 03 rule 4): a typed conversion never
  replaces the last copy of the original representation.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Any, Dict, Optional

from .event import LosslessEvent, ParseStatus
from .parsers.base import ParseResult


def _parse_iso8601(value: str) -> Optional[datetime]:
    """ISO-8601 check; naive timestamps are rejected (must carry offset)."""
    try:
        v = value.replace("Z", "+00:00") if isinstance(value, str) else None
        if v is None:
            return None
        dt = datetime.fromisoformat(v)
        return dt if dt.tzinfo is not None else None
    except (ValueError, TypeError):
        return None


def check_types(normalized: Dict[str, Any], problems_out: list) -> Dict[str, Any]:
    """Validate known-type fields; never delete values. Returns the dict
    (same object) possibly annotated via problems_out."""
    for key in list(normalized.keys()):
        val = normalized[key]
        if val is None:
            continue
        if key.endswith(".ip") or key.endswith(".address"):
            try:
                ipaddress.ip_address(str(val))
            except ValueError:
                problems_out.append(
                    {"field": key, "problem": "not a valid IP address; original value preserved",
                     "value": val}
                )
        elif key.endswith(".port"):
            if not isinstance(val, int) or not (0 <= val <= 65535):
                problems_out.append(
                    {"field": key, "problem": "port out of range or not integer; value preserved",
                     "value": val}
                )
        elif key == "@timestamp":
            if _parse_iso8601(val) is None:
                problems_out.append(
                    {"field": key, "problem": "timestamp not ISO-8601; value preserved",
                     "value": val}
                )
    return normalized


def merge_parse_result(event: LosslessEvent, result: ParseResult,
                       parser_name: str, parser_version: str,
                       format_detected: str, chain: Optional[str] = None) -> None:
    """Merge parser output into the event. Additive only (Skill 03)."""
    event.parser_name = parser_name if chain is None else chain
    event.parser_version = parser_version
    event.format_detected = format_detected
    event.parse_status = result.status
    for note in result.notes:
        event.add_parse_note(note)
    event.decoded.update(result.decoded)
    event.protocol_metadata.update(result.protocol_metadata)
    # normalized candidates that are None (absent fields) are recorded as
    # explicit None: presence-without-value must not be silently lost either.
    event.normalized.update(result.fields)
    event.vendor_fields.update(result.vendor_fields)
    event.unknown_fields.update(result.unknown_fields)
    event.original_fields.update(result.originals)

    # top-level source identity convenience fields
    hostname = result.fields.get("event.hostname") or result.decoded.get("hostname")
    if hostname and not event.hostname:
        event.hostname = str(hostname)

    if result.status == "PARTIAL":
        event.parse_status = ParseStatus.PARTIAL.value
    elif result.status == "FAILED":
        event.parse_status = ParseStatus.FAILED.value
    else:
        event.parse_status = ParseStatus.PARSED.value


def finalize_types(event: LosslessEvent) -> None:
    problems = []
    check_types(event.normalized, problems)
    for p in problems:
        event.add_validation_problem(p["field"], p["problem"], p["value"])
