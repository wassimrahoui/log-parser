"""RFC 3164 (BSD) syslog parser (research:
docs/research/protocols-syslog-rfc3164-5424-6587.md).

Accepts the classic grammar plus documented real-world deviations:
- PRI optional (messages without PRI are valid input, noted as deviation).
- Day may be space- or zero-padded.
- Optional hostname; optional 'TAG[pid]:' prefix; 'host :' colon variants
  (Cisco style) tolerated and recorded.
- No year/timezone in timestamp: normalization uses an explicit, configured
  reference year policy (default: ingestion year), recorded as a note —
  never a silent guess (Skill 03 rule 3).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from .base import Parser, ParseResult
from .rfc5424 import parse_rfc3339  # re-export convenience for other modules

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

_RFC3164_RE = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?"
    r"(?P<ts>(?P<mon>[A-Z][a-z]{2}) {1,2}(?P<day>\d{1,2}) (?P<hh>\d{2}):(?P<mm>\d{2}):(?P<ss>\d{2})) "
    r"(?:(?P<host>\S+) )?"
    r"(?P<rest>.*)$",
    re.S,
)
_TAG_RE = re.compile(r"^(?P<tag>[^\s:\[\]]{1,32})(?:\[(?P<pid>\d{1,10})\])?: ?")
_COLON_HOST_RE = re.compile(r"^(?P<host>\S+): (?P<rest>.*)$", re.S)


class Rfc3164Parser(Parser):
    name = "rfc3164"
    version = "1.0.0"
    formats = ("rfc3164",)

    def __init__(self, reference_year_provider=None) -> None:
        """reference_year_provider: optional callable returning the year to
        use for year-less timestamps (deterministic policy injection)."""
        self._ref_year = reference_year_provider

    def _parse(self, msg: str) -> ParseResult:
        res = ParseResult(status="FAILED")
        m = _RFC3164_RE.match(msg)
        if not m:
            res.notes.append("no RFC3164 header match")
            return res
        gd = m.groupdict()
        pri_raw = gd["pri"]
        notes: list = []
        if pri_raw is not None:
            pri = int(pri_raw)
            facility, severity = divmod(pri, 8)
        else:
            pri = None
            facility = severity = None
            notes.append("PRI_ABSENT:noted; field preserved as absent")

        rest = gd["rest"] or ""
        host = gd["host"]
        tag = pid = None
        # SIEM-format content (CEF:/LEEF:) is not a BSD tag; the tag grammar
        # would otherwise eat 'CEF:'/'LEEF:' as tag (documented deviation).
        if rest.startswith("CEF:") or rest.startswith("LEEF:"):
            notes.append("TAG_SKIPPED:SIEM-format content, not a syslog tag")
        else:
            tag_m = _TAG_RE.match(rest)
            if tag_m:
                tag = tag_m.group("tag")
                pid = tag_m.group("pid")
                rest = rest[tag_m.end():]
            colon_host = _COLON_HOST_RE.match(rest)
            # Cisco-style 'host :' handled by host group already; a second
            # token + colon here means hostname carried a trailing colon.
            if colon_host and host and host.endswith(":"):
                pass  # already captured
        if host and host.endswith(":"):
            host = host[:-1]
            notes.append("HOSTNAME_TRAILING_COLON:deviation normalized")

        # timestamp normalization with explicit year policy
        iso_ts: Optional[str] = None
        mon = _MONTHS.get(gd["mon"])
        if mon is None:
            notes.append("INVALID_TIMESTAMP:unknown month")
        else:
            year = self._ref_year() if self._ref_year else datetime.now(timezone.utc).year
            try:
                dt = datetime(year, mon, int(gd["day"]), int(gd["hh"]), int(gd["mm"]), int(gd["ss"]),
                              tzinfo=timezone.utc)
                iso_ts = dt.isoformat().replace("+00:00", "Z")
                notes.append("TIMESTAMP_YEAR_INFERRED:from reference-year policy")
            except ValueError as exc:
                notes.append(f"INVALID_TIMESTAMP:{exc}")

        decoded: Dict[str, Any] = {
            "rfc": "3164",
            "pri": pri,
            "facility": facility,
            "severity": severity,
            "timestamp": gd["ts"],
            "hostname": host,
            "tag": tag,
            "pid": pid,
            "message": rest,
        }
        fields: Dict[str, Any] = {
            "log.syslog.facility": facility,
            "log.syslog.severity": severity,
            "log.syslog.priority": pri,
        }
        if host:
            fields["event.hostname"] = host
        if tag:
            fields["log.syslog.appname"] = tag
        if pid:
            fields["log.syslog.procid"] = pid
        if iso_ts:
            fields["@timestamp"] = iso_ts
        if rest:
            fields["message"] = rest

        originals: Dict[str, str] = {
            "original.timestamp": gd["ts"],
            "original.message": rest,
        }
        if pri_raw is not None:
            originals["original.pri"] = f"<{pri_raw}>"
        if host:
            originals["original.hostname"] = host
        if tag:
            originals["original.tag"] = tag

        res.fields = fields
        res.originals = originals
        res.decoded = decoded
        res.protocol_metadata = {
            "syslog.rfc": "3164",
            "syslog.facility": facility,
            "syslog.severity": severity,
            "syslog.pri": pri,
        }
        res.notes.extend(notes)
        res.status = "PARSED"
        return res
