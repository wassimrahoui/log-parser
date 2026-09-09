"""RFC 5424 syslog parser (research: docs/research/protocols-syslog-rfc3164-5424-6587.md).

Grammar per RFC 5424 §6, with documented real-world tolerance:
- PRI 1-3 digits; VERSION non-zero digit sequence (detect trigger).
- TIMESTAMP: RFC3339 or NILVALUE; trailing fractional seconds optional.
- STRUCTURED-DATA: nil '-' or 1+ elements [ID param="value"...] with \\\" and
  \\\\ escapes; malformed SD is preserved as text and noted (never dropped).
- MSG: everything after the SP following SD (may be empty).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .base import Parser, ParseResult

_TS = r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})|-)"
_SD_ELEMENT = re.compile(r"\[([^\]\[\"]+)(?: ([^\]]*))?\]")
_SD_PARAM = re.compile(r'(\S+?)="((?:[^"\\]|\\.)*)"')
_PRI_TS_HOST_APP = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ver>[1-9]\d*) " + _TS + r" "
    r"(?P<host>-|[!-~]{1,255}) (?P<app>-|[!-~]{1,255}) "
    r"(?P<proc>-|[!-~]{1,128}) (?P<msgid>-|[!-~]{1,128})"
)


def parse_rfc3339(value: str) -> Optional[datetime]:
    """Deterministic RFC3339 → aware UTC datetime; None if invalid."""
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


class Rfc5424Parser(Parser):
    name = "rfc5424"
    version = "1.0.0"
    formats = ("rfc5424",)

    def _parse(self, msg: str) -> ParseResult:
        res = ParseResult(status="FAILED")
        m = _PRI_TS_HOST_APP.match(msg)
        if not m:
            res.notes.append("no RFC5424 header match")
            return res

        gd = m.groupdict()
        pri_raw = gd["pri"]
        pri = int(pri_raw)
        facility, severity = divmod(pri, 8)
        valid_pri = pri <= 191

        decoded: Dict[str, Any] = {
            "rfc": "5424",
            "pri": pri,
            "pri_raw": pri_raw,
            "facility": facility,
            "severity": severity,
            "is_valid_pri": valid_pri,
            "version": gd["ver"],
            "timestamp": gd["ts"],
            "hostname": gd["host"],
            "appname": gd["app"],
            "procid": gd["proc"],
            "msgid": gd["msgid"],
        }

        # split SD vs MSG on the raw text after the header (bracket-depth
        # based; RFC5424 cannot be regex-split reliably when MSG contains
        # brackets). Tolerates documented deviations (SD omitted, unbalanced).
        header_end = m.end()
        remainder = msg[header_end:]
        sd_text, message, split_notes = self._split_sd(remainder)
        for note in split_notes:
            res.notes.append(note)

        sd_parsed: Dict[str, Any] = {}
        if sd_text == "-":
            sd_parsed = {}
            decoded["structured_data_nil"] = True
        elif sd_text:
            sd_parsed, sd_errors = self._parse_sd(sd_text)
            for err in sd_errors:
                res.notes.append(err)

        ts_dt = parse_rfc3339(gd["ts"]) if gd["ts"] != "-" else None
        if gd["ts"] != "-" and ts_dt is None:
            res.notes.append("INVALID_TIMESTAMP:rfc3339 parse failed; value preserved")

        decoded["structured_data"] = sd_parsed
        decoded["message"] = message
        res.decoded = decoded
        res.protocol_metadata = {
            "syslog.rfc": "5424",
            "syslog.facility": facility,
            "syslog.severity": severity,
            "syslog.pri": pri,
        }

        # --- extraction: every header field, originals preserved verbatim ----
        fields: Dict[str, Any] = {
            "event.hostname": None if gd["host"] == "-" else gd["host"],
            "log.syslog.appname": None if gd["app"] == "-" else gd["app"],
            "log.syslog.procid": None if gd["proc"] == "-" else gd["proc"],
            "log.syslog.msgid": None if gd["msgid"] == "-" else gd["msgid"],
            "log.syslog.facility": facility,
            "log.syslog.severity": severity,
            "log.syslog.priority": pri,
            "log.syslog.version": gd["ver"],
        }
        originals: Dict[str, str] = {
            "original.hostname": gd["host"],
            "original.appname": gd["app"],
            "original.procid": gd["proc"],
            "original.msgid": gd["msgid"],
            "original.pri": f"<{pri_raw}>",
            "original.timestamp": gd["ts"],
        }
        if ts_dt is not None:
            fields["@timestamp"] = ts_dt.isoformat().replace("+00:00", "Z")
        else:
            res.notes.append("timestamp not normalized (nil or invalid)")
        if message:
            fields["message"] = message
        res.fields = fields
        res.originals = originals

        # structured data → normalized log.syslog.structure.* + originals
        for elem_id, params in (sd_parsed or {}).items():
            res.vendor_fields[f"log.syslog.structure.{elem_id}"] = params
            res.originals[f"original.sd.{elem_id}"] = self._sd_original_text(sd_text, elem_id)

        if not valid_pri:
            res.status = "PARTIAL"
            res.notes.append(f"PRI_OUT_OF_RANGE:{pri}")
        if res.status == "FAILED":
            res.status = "PARSED"
        return res

    @staticmethod
    def _split_sd(remainder: str) -> Tuple[str, str, List[str]]:
        """Split STRUCTURED-DATA text from MSG. ``remainder`` starts right
        after MSGID. Returns (sd_text, message, notes). Deterministic."""
        notes: List[str] = []
        if remainder == "":
            return "", "", []
        if not remainder.startswith(" "):
            notes.append("SD_MALFORMED:no space after MSGID; text kept as message")
            return "", remainder, notes
        rest = remainder[1:]
        if rest.startswith("-"):
            after = rest[1:]
            if after.startswith(" "):
                return "-", after[1:], notes
            return "-", "", notes
        if rest.startswith("["):
            depth = 0
            for i, ch in enumerate(rest):
                if ch == "[":
                    depth += 1
                elif ch == "]":
                    depth -= 1
                    if depth == 0:
                        after = rest[i + 1:]
                        if after.startswith(" "):
                            return rest[:i + 1], after[1:], notes
                        return rest[:i + 1], "", notes
            notes.append("SD_UNBALANCED:preserved as structured-data text")
            return rest, "", notes
        # SD omitted entirely (real-world deviation, not RFC-conformant)
        notes.append("SD_OMITTED:deviation tolerated; text kept as message")
        return "", rest, notes

    @staticmethod
    def _parse_sd(sd_text: str) -> Tuple[Dict[str, Dict[str, str]], List[str]]:
        errors: List[str] = []
        out: Dict[str, Dict[str, str]] = {}
        for em in _SD_ELEMENT.finditer(sd_text):
            elem_id = em.group(1)
            params_text = em.group(2) or ""
            params: Dict[str, str] = {}
            for pm in _SD_PARAM.finditer(params_text):
                params[pm.group(1)] = pm.group(2).replace('\\"', '"').replace("\\\\", "\\")
            if params_text and not params:
                errors.append(f"SD_UNPARSED:{elem_id}")
            out[elem_id] = params
        if sd_text and not sd_text.startswith("[") and sd_text != "-":
            errors.append("SD_MALFORMED:no leading '['")
        return out, errors

    @staticmethod
    def _sd_original_text(sd_text: str, elem_id: str) -> str:
        marker = "[" + elem_id
        idx = sd_text.find(marker)
        if idx == -1:
            return sd_text
        depth = 0
        for j in range(idx, len(sd_text)):
            if sd_text[j] == "[":
                depth += 1
            elif sd_text[j] == "]":
                depth -= 1
                if depth == 0:
                    return sd_text[idx:j + 1]
        return sd_text[idx:]
