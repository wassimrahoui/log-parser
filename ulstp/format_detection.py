"""Format detection (build plan §23; Skill 05).

Deterministic, ordered detection. Each detector is a pure function of the
decoded message text. The FIRST matching rule wins; ties are impossible by
construction. Detection never mutates or discards the message.

Order (documented in Skill 05):
  RFC5424 -> CEF -> LEEF -> JSON -> RFC3164 -> key=value -> CSV/TSV -> XML ->
  plain text -> unknown
"""

from __future__ import annotations

import re
from typing import List, Optional

# RFC 5424: <PRI>VERSION SP ...  (VERSION is non-zero digit per RFC; accept 1-9 lead)
_RFC5424_RE = re.compile(r"^<(\d{1,3})>([1-9]\d*) \S")
# RFC 3164: <PRI>Mmm dd hh:mm:ss ...  (space- or zero-padded day both accepted in the wild)
_RFC3164_RE = re.compile(
    r"^(?:<(\d{1,3})>)?([A-Z][a-z]{2}) {1,2}\d{1,2} \d{2}:\d{2}:\d{2} \S"
)
_CEF_RE = re.compile(r"(?:^|\s)CEF:(\d+)\|")
_LEEF_RE = re.compile(r"(?:^|\s)LEEF:(\d+)\.(\d+)\|")
_KV_TOKEN_RE = re.compile(r"(?:^|\s)([A-Za-z][A-Za-z0-9_.-]*)=")
_XML_RE = re.compile(r"^\s*<\?xml|^\s*<[A-Za-z_][\w.-]*[\s>]")

FORMAT_RFC5424 = "rfc5424"
FORMAT_RFC3164 = "rfc3164"
FORMAT_CEF = "cef"
FORMAT_LEEF = "leef"
FORMAT_JSON = "json"
FORMAT_KV = "key_value"
FORMAT_CSV = "csv"
FORMAT_XML = "xml"
FORMAT_PLAIN = "plain_text"
FORMAT_UNKNOWN = "unknown"


def detect_format(text: str) -> str:
    """Return the detected format for a decoded message (deterministic)."""
    if not text:
        return FORMAT_UNKNOWN

    if _RFC5424_RE.match(text):
        return FORMAT_RFC5424

    if _CEF_RE.search(text):
        return FORMAT_CEF

    if _LEEF_RE.search(text):
        return FORMAT_LEEF

    stripped = text.lstrip()
    if stripped.startswith("{"):
        return FORMAT_JSON

    if _RFC3164_RE.match(text):
        return FORMAT_RFC3164

    # key=value: at least two distinct key= anchors
    keys = _KV_TOKEN_RE.findall(text)
    if len(keys) >= 2:
        return FORMAT_KV

    if _XML_RE.match(text):
        return FORMAT_XML

    # CSV/TSV: >=2 fields split by tab (high confidence) or comma/semicolon
    # without KV structure. Comma alone is weak (plain sentences contain
    # commas) so require no-space-after-delimiter heuristic for comma only.
    if "\t" in text:
        return FORMAT_CSV
    for delim in (";", ","):
        if delim in text:
            parts = text.split(delim)
            if len(parts) >= 2 and all(p.strip() != "" for p in parts):
                if delim == ";" or " " not in text:
                    return FORMAT_CSV

    return FORMAT_PLAIN


def detect_formats_multi(text: str) -> List[str]:
    """Ordered candidate list (primary first) for resolver fallback chains."""
    primary = detect_format(text)
    candidates = [primary]
    # A CEF/LEEF message may carry a syslog prefix; syslog parser runs first
    # in the chain when the prefix grammar matches, then the inner format.
    if primary in (FORMAT_CEF, FORMAT_LEEF):
        if _RFC5424_RE.match(text) or _RFC3164_RE.match(text):
            candidates.insert(0, FORMAT_RFC3164 if _RFC3164_RE.match(text) else FORMAT_RFC5424)
    if primary == FORMAT_RFC5424 or primary == FORMAT_RFC3164:
        # inner content may be CEF/LEEF/KV/JSON
        msg_start = _msg_start(text)
        if msg_start is not None:
            inner = text[msg_start:]
            for fmt in (FORMAT_CEF, FORMAT_LEEF, FORMAT_JSON, FORMAT_KV):
                if detect_format(inner) == fmt:
                    candidates.append(fmt)
                    break
    return candidates


def _msg_start(text: str) -> Optional[int]:
    """Index where the syslog MSG portion begins, if this looks like syslog."""
    m = _RFC5424_RE.match(text)
    if m:
        # find end of structured data ("] " or end) — handled by syslog parser;
        # approximate here for detection only.
        idx = text.find("] ")
        return idx + 2 if idx != -1 else None
    m = _RFC3164_RE.match(text)
    if m:
        # skip timestamp + hostname token
        rest = text[m.end() - 1:]
        parts = rest.split(" ", 2)
        if len(parts) >= 3:
            return len(text) - len(parts[2])
        return None
    return None
