"""IBM QRadar LEEF parser (research: docs/research/formats-cef-leef.md).

LEEF:Version|Vendor|Product|Version|EventID[|DelimiterChar]|attributes
- LEEF 1.x: attributes tab-separated.
- LEEF 2.x: custom delimiter char from header; hex forms 0xNN/xNN decoded.
- Optional RFC3164/5424 syslog prefix (space separated) tolerated.
All attributes extracted; unknown keys preserved (Rule 9).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from .base import Parser, ParseResult

_SYSLOG_PREFIX_RE = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?"
    r"(?:[A-Z][a-z]{2} {1,2}\d{1,2} \d{2}:\d{2}:\d{2} )"
    r"(?:(?P<host>\S+) )?"
    r"(?P<leef>LEEF:.*)$",
    re.S,
)
_LEEF_ACCEPT_RE = re.compile(r"LEEF:\d+\.\d+\|")
_LEEF_HEADER_RE = re.compile(
    r"^LEEF:(?P<fmtver>\d+\.\d+)\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|"
    r"(?P<prodver>[^|]*)\|(?P<eventid>[^|]*)"
)

# Predefined LEEF attributes → normalized (researched subset; IBM predefined list).
LEEF_KEY_MAP = {
    "src": "source.ip", "dst": "destination.ip", "srcPort": "source.port",
    "dstPort": "destination.port", "sev": "event.severity", "cat": "event.category",
    "usrName": "source.user.name", "userName": "source.user.name",
    "identic": "leef.identity_ip", "identSrc": "leef.identity_src_ip",
    "identHostName": "leef.identity_hostname", "moduleName": "leef.module_name",
    "proc": "process.name", "svc": "service.name", "domain": "dns.domain",
    "proto": "network.transport", "msg": "message", "action": "event.action",
    "resource": "url.original", "auth": "leef.auth",
    "hostname": "observer.hostname", "LEEF_Header_EventID": "leef.event_id",
}


def _decode_delimiter(raw: Optional[str]) -> Optional[str]:
    if raw is None or raw == "":
        return None
    if raw in ("0x", "x"):
        return None
    m = re.fullmatch(r"(?:0x|x)([0-9A-Fa-f]{1,4})", raw)
    if m:
        try:
            return chr(int(m.group(1), 16))
        except ValueError:
            return None
    return raw[0] if len(raw) >= 1 else None


_LEEF_KEY_EQ_RE = re.compile(r"[A-Za-z0-9_.-]+=")
_LEEF_PAIR_RE = re.compile(r"([A-Za-z0-9_.-]+)=(.*)", re.S)


def _split_attrs(attrs_text: str, delim: str) -> List[str]:
    """Deterministic attribute segmentation.

    Canonical path: when the primary delimiter (tab / custom) is present,
    it is THE separator (values may then contain spaces). Deviation path
    (documented, real-world space-separated LEEF): when no primary delimiter
    exists, fall back to CEF-style key-anchored boundary scanning.
    """
    if delim in attrs_text:
        return attrs_text.split(delim)
    boundaries = [0]
    i = 0
    n = len(attrs_text)
    while i < n:
        if attrs_text[i] == " " and i + 1 < n:
            if _LEEF_KEY_EQ_RE.match(attrs_text, i + 1):
                boundaries.append(i + 1)
        i += 1
    boundaries.append(n)
    segs = [attrs_text[s:e] for s, e in zip(boundaries, boundaries[1:]) if s < e]
    # in the fallback path the space before the next key is a DELIMITER,
    # not part of the value: strip one trailing space on non-final segments
    return [seg[:-1] if i < len(segs) - 1 and seg.endswith(" ") else seg
            for i, seg in enumerate(segs)]


class LeefParser(Parser):
    name = "leef"
    version = "1.0.0"
    formats = ("leef",)

    def accept(self, msg: str) -> bool:
        return _LEEF_ACCEPT_RE.search(msg) is not None

    def _parse(self, msg: str) -> ParseResult:
        res = ParseResult()
        m = _SYSLOG_PREFIX_RE.match(msg)
        prefix_pri = prefix_host = None
        if m:
            prefix_pri, prefix_host, leef_text = m.group("pri"), m.group("host"), m.group("leef")
        else:
            leef_text = msg.strip()
            if not leef_text.startswith("LEEF:"):
                res.status = "FAILED"
                res.notes.append("no LEEF: marker after optional syslog prefix")
                return res

        hm = _LEEF_HEADER_RE.match(leef_text)
        if not hm:
            res.status = "FAILED"
            res.notes.append("LEEF_HEADER_UNPARSEABLE")
            return res

        gd = hm.groupdict()
        remainder = leef_text[hm.end():]
        # Delimiter field (LEEF 2.x feature, also seen on 1.x in the wild):
        # only when a pipe follows EventID AND the next segment is a single
        # character or a 0x/x hex form (research: IBM LEEF docs).
        delim = "\t"
        attrs_text = remainder
        if remainder.startswith("|"):
            seg = remainder[1:].split("|", 1)[0]
            if len(seg) == 1 or re.fullmatch(r"(?:0x|x)[0-9A-Fa-f]{1,4}", seg):
                decoded_delim = _decode_delimiter(seg)
                if decoded_delim is not None:
                    delim = decoded_delim
                    attrs_text = remainder[1 + len(seg) + 1:]
                else:
                    attrs_text = remainder[1:]
            else:
                attrs_text = remainder[1:]

        decoded: Dict[str, Any] = {
            "leef_version": gd["fmtver"],
            "leef_vendor": gd["vendor"],
            "leef_product": gd["product"],
            "leef_product_version": gd["prodver"],
            "leef_event_id": gd["eventid"],
            "leef_delimiter": delim,
        }
        if prefix_pri is not None:
            decoded["syslog_prefix_pri"] = int(prefix_pri)
        if prefix_host:
            decoded["syslog_prefix_host"] = prefix_host

        fields: Dict[str, Any] = {
            "leef.version": gd["fmtver"],
            "leef.vendor": gd["vendor"],
            "leef.product": gd["product"],
            "leef.product_version": gd["prodver"],
            "leef.event_id": gd["eventid"],
        }
        if prefix_host:
            fields["event.hostname"] = prefix_host

        attrs: Dict[str, str] = {}
        dup_count: Dict[str, int] = {}
        unpaired: List[str] = []
        if attrs_text.startswith(delim):
            # the FIRST delimiter separates header from attributes; only
            # subsequent occurrences separate attributes from each other
            attrs_text = attrs_text[len(delim):]
        if attrs_text:
            if delim not in attrs_text:
                res.notes.append("LEEF_SPACE_SEPARATOR_DEVIATION:tab delimiter absent")
            for seg in _split_attrs(attrs_text, delim):
                if not seg:
                    continue
                pm = _LEEF_PAIR_RE.match(seg)
                if not pm:
                    unpaired.append(seg)
                    continue
                key, val = pm.group(1), pm.group(2)
                if key in attrs or f"{key}#2" in attrs:
                    dup_count[key] = dup_count.get(key, 1) + 1
                    attrs[f"{key}#{dup_count[key]}"] = val
                else:
                    attrs[key] = val
        else:
            res.notes.append("LEEF_NO_ATTRIBUTES")

        originals: Dict[str, str] = {"original.leef.header":
                                     leef_text[: hm.end()]}
        for key, val in attrs.items():
            originals[f"original.leef.{key}"] = val
            base_key = key.split("#", 1)[0]
            if key != base_key:
                # duplicate occurrence: normalized mapping never overwrites;
                # preserved in unknown layer (Rule 9)
                res.unknown_fields[f"leef.attr.{key}"] = val
                continue
            mapped = LEEF_KEY_MAP.get(base_key)
            if mapped == "source.port" or mapped == "destination.port":
                fields[mapped] = int(val) if val.isdigit() else None
                if not val.isdigit():
                    res.notes.append(f"LEEF_INVALID_PORT:{key}={val[:20]}")
            elif mapped == "event.severity":
                fields[mapped] = int(val) if val.isdigit() else val
            elif mapped:
                fields[mapped] = val
            else:
                res.unknown_fields[f"leef.attr.{key}"] = val
        for idx, token in enumerate(unpaired):
            res.unknown_fields[f"leef.attr.unpaired_{idx}"] = token
            res.notes.append(f"LEEF_UNPAIRED_TOKEN:{token[:40]}")

        res.fields = fields
        res.originals = originals
        res.decoded = decoded
        res.status = "PARSED"
        return res
