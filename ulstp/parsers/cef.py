"""ArcSight CEF parser (research: docs/research/formats-cef-leef.md).

Accepts `CEF:0|...` with optional RFC3164 syslog prefix. Header split on
unescaped pipes; extension parsed key-anchored: value boundaries are
unescaped spaces followed by a `key=` pattern, so values may contain spaces.
CEF escapes (\\=, \\n, \\r, \\\\) are decoded for normalized values while
originals keep the raw text. Every extension key is extracted (§16).
Unknown keys preserved (Rule 9). Deviations (missing Name, unpaired tokens,
extra header fields) tolerated and recorded — never dropped (Skill 03).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from .base import Parser, ParseResult

_SYSLOG_PREFIX_RE = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?"
    r"(?:[A-Z][a-z]{2} {1,2}\d{1,2} \d{2}:\d{2}:\d{2} )"
    r"(?:(?P<host>\S+) )?"
    r"(?P<cef>CEF:.*)$",
    re.S,
)
_CEF_ACCEPT_RE = re.compile(r"CEF:\d+\|")
_KEY_EQ_RE = re.compile(r"[A-Za-z0-9_.]+=")
_PAIR_RE = re.compile(r"([A-Za-z0-9_.]+)=(.*)", re.S)

# CEF extension dictionary → normalized names (researched subset; new keys
# are a one-line addition here).
CEF_KEY_MAP = {
    "src": "source.ip", "dst": "destination.ip", "spt": "source.port",
    "dpt": "destination.port", "suser": "source.user.name",
    "duser": "destination.user.name", "shost": "source.hostname",
    "dhost": "destination.hostname", "msg": "message",
    "rt": "event.cef.receipt_time", "act": "event.action", "cat": "event.category",
    "request": "url.original", "requestMethod": "http.request.method",
    "requestContext": "user_agent.original",
    "spid": "source.process.pid", "dpid": "destination.process.pid",
    "spriv": "source.user.roles", "dpriv": "destination.user.roles",
    "ahost": "observer.hostname", "dvchost": "observer.hostname",
    "aghost": "observer.address", "art": "event.cef.agent_receipt_time",
    "dtz": "event.cef.device_timezone", "deviceProcessName": "process.name",
    "fname": "file.name",
    "fsize": "file.size", "fileHash": "file.hash",
    "externalId": "cef.externalId", "suid": "cef.suid",
    "outcome": "event.outcome", "reason": "event.reason",
    "proto": "network.transport",
    "cs1": "cef.cs1", "cs2": "cef.cs2", "cs3": "cef.cs3",
    "cs4": "cef.cs4", "cs5": "cef.cs5", "cs6": "cef.cs6",
    "cs1Label": "cef.cs1Label", "cs2Label": "cef.cs2Label", "cs3Label": "cef.cs3Label",
    "cs4Label": "cef.cs4Label", "cs5Label": "cef.cs5Label", "cs6Label": "cef.cs6Label",
    "cn1": "cef.cn1", "cn2": "cef.cn2", "cn3": "cef.cn3",
    "cfp1": "cef.cfp1", "cfp2": "cef.cfp2", "cfp3": "cef.cfp3", "cfp4": "cef.cfp4",
    "atv": "cef.atv",
}

_HEADER_NAMES = ["version", "device_vendor", "device_product", "device_version",
                 "device_event_class_id", "name", "severity"]


def _split_unescaped(text: str, sep: str) -> List[str]:
    parts: List[str] = []
    cur: List[str] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 1 < len(text):
            cur.append(ch)
            cur.append(text[i + 1])
            i += 2
            continue
        if ch == sep:
            parts.append("".join(cur))
            cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    parts.append("".join(cur))
    return parts


def cef_unescape(value: str) -> str:
    """Decode CEF-defined escapes; unknown escapes stay literal."""
    out: List[str] = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value):
            nxt = value[i + 1]
            if nxt == "=":
                out.append("=")
            elif nxt == "\\":
                out.append("\\")
            elif nxt == "n":
                out.append("\n")
            elif nxt == "r":
                out.append("\r")
            else:
                out.append(ch)
                out.append(nxt)
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _severity_to_int(sev: str) -> Optional[int]:
    s = (sev or "").strip()
    if s.isdigit():
        return max(0, min(10, int(s)))
    mapping = {"unknown": 0, "low": 1, "medium": 4, "high": 8, "very-high": 10}
    return mapping.get(s.lower())


def _parse_extension(ext: str) -> Tuple[Dict[str, str], List[str]]:
    """Key-anchored extension scan. Returns (pairs, unpaired_tokens)."""
    boundaries: List[int] = [0]
    i = 0
    n = len(ext)
    while i < n:
        ch = ext[i]
        if ch == "\\":
            i += 2  # skip escaped character
            continue
        if ch == " " and i + 1 < n:
            m = _KEY_EQ_RE.match(ext, i + 1)
            if m:
                boundaries.append(i + 1)
        i += 1
    boundaries.append(n)
    pairs: Dict[str, str] = {}
    dup_count: Dict[str, int] = {}
    unpaired: List[str] = []
    last_idx = len(boundaries) - 1
    for idx, (s, e) in enumerate(zip(boundaries, boundaries[1:])):
        if s >= e:
            continue
        seg = ext[s:e]
        # The single space before the next pair is a DELIMITER, not part of
        # the value: strip exactly one trailing space on non-final segments
        # (values genuinely ending in a space before a pair are
        # indistinguishable per spec; documented ambiguity).
        if idx != last_idx - 1 and seg.endswith(" "):
            seg = seg[:-1]
        m = _PAIR_RE.match(seg)
        if m:
            key, val = m.group(1), m.group(2)
            if key in pairs or any(k.split("#", 1)[0] == key for k in pairs):
                dup_count[key] = dup_count.get(key, 1) + 1
                pairs[f"{key}#{dup_count[key]}"] = val
            else:
                pairs[key] = val
        else:
            unpaired.append(seg)
    return pairs, unpaired


class CefParser(Parser):
    name = "cef"
    version = "1.0.0"
    formats = ("cef",)

    def accept(self, msg: str) -> bool:
        return _CEF_ACCEPT_RE.search(msg) is not None

    def _parse(self, msg: str) -> ParseResult:
        res = ParseResult()
        m = _SYSLOG_PREFIX_RE.match(msg)
        prefix_pri = prefix_host = None
        if m:
            prefix_pri = m.group("pri")
            prefix_host = m.group("host")
            cef_text = m.group("cef")
        else:
            cef_text = msg.strip()
            if not cef_text.startswith("CEF:"):
                res.status = "FAILED"
                res.notes.append("no CEF: marker after optional syslog prefix")
                return res

        # Split on UNESCAPED PIPES FIRST: the Name field may contain spaces
        # (documented real-world case), so space-partitioning is wrong. The
        # extension is everything after the 7th unescaped pipe.
        header_fields = _split_unescaped(cef_text, "|")
        if len(header_fields) < 8:
            res.status = "FAILED"
            res.notes.append(f"CEF_HEADER_INCOMPLETE:{len(header_fields)}/7 fields")
            for i, name in enumerate(_HEADER_NAMES[:min(len(header_fields), 7)]):
                val = header_fields[i]
                if i == 0:
                    val = val.replace("CEF:", "", 1)
                res.decoded[f"cef_{name}"] = val
            return res

        header = dict(zip(_HEADER_NAMES, header_fields[:7]))
        header["version"] = header["version"].replace("CEF:", "", 1)
        ext_part = "|".join(header_fields[7:])

        decoded: Dict[str, Any] = {f"cef_{k}": v for k, v in header.items()}
        if prefix_pri is not None:
            decoded["syslog_prefix_pri"] = int(prefix_pri)
        if prefix_host:
            decoded["syslog_prefix_host"] = prefix_host

        ext: Dict[str, str] = {}
        unpaired: List[str] = []
        if ext_part:
            ext, unpaired = _parse_extension(ext_part)
        else:
            res.notes.append("CEF_NO_EXTENSION")

        severity_raw = header["severity"]
        fields: Dict[str, Any] = {
            "cef.version": header["version"],
            "cef.device_vendor": header["device_vendor"],
            "cef.device_product": header["device_product"],
            "cef.device_version": header["device_version"],
            "cef.device_event_class_id": header["device_event_class_id"],
            "cef.name": header["name"],
            "cef.severity": severity_raw,
            "event.severity": _severity_to_int(severity_raw),
        }
        if prefix_host:
            fields["event.hostname"] = prefix_host

        originals: Dict[str, str] = {"original.cef.header":
                                     "|".join(header_fields[:7])}
        for key, raw_val in ext.items():
            originals[f"original.cef.{key}"] = raw_val
            if "#" in key:
                # duplicate occurrence marker: preserve in unknown layer,
                # never overwrite the first mapped value (Rule 9)
                res.unknown_fields[f"cef.ext.{key}"] = cef_unescape(raw_val)
                continue
            mapped = CEF_KEY_MAP.get(key)
            val = cef_unescape(raw_val)
            if mapped in ("source.port", "destination.port"):
                fields[mapped] = int(val) if val.isdigit() else None
                if not val.isdigit():
                    res.notes.append(f"CEF_INVALID_PORT:{key}={val[:20]}")
            elif mapped:
                fields[mapped] = val
            else:
                res.unknown_fields[f"cef.ext.{key}"] = val
        for idx, token in enumerate(unpaired):
            res.unknown_fields[f"cef.ext.unpaired_{idx}"] = token
            res.notes.append(f"CEF_UNPAIRED_TOKEN:{token[:40]}")

        res.fields = fields
        res.originals = originals
        res.decoded = decoded
        res.status = "PARSED"
        return res
