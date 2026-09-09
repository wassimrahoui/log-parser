"""Fortinet FortiGate parser (research: docs/research/vendors-cisco-asa-fortigate.md).

FortiOS default KV telemetry over RFC3164/5424 envelopes. Signature:
10-digit logid + type + subtype (researched). All keys extracted; mapped
keys normalized; every FortiGate field also preserved in vendor layer.
date=+time= are explicit (year included) — no timestamp inference needed.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from .base import Parser, ParseResult
from .kv import tokenize_kv, _unquote

_SIG_RE = re.compile(r"\blogid=\d{10}\b")

# FortiOS Log Reference keys → normalized (researched subset).
_FG_MAP = {
    "srcip": "source.ip", "dstip": "destination.ip",
    "srcport": "source.port", "dstport": "destination.port",
    "proto": "network.iana_number", "action": "event.action",
    "service": "network.protocol", "user": "source.user.name",
    "group": "source.user.group.name", "msg": "message",
    "level": "log.level", "hostname": "url.domain", "url": "url.original",
    "sentbyte": "source.bytes", "rcvdbyte": "destination.bytes",
    "duration": "event.duration",
}
_FG_NUMERIC = {"srcport", "dstport", "sentbyte", "rcvdbyte", "duration"}


class FortiGateParser(Parser):
    name = "fortigate"
    version = "1.0.0"
    formats = ("key_value",)

    def accept(self, msg: str) -> bool:
        return _SIG_RE.search(msg) is not None

    def _parse(self, msg: str) -> ParseResult:
        res = ParseResult()
        pairs, unpaired, raw_values = tokenize_kv(msg)
        if "logid" not in pairs:
            res.status = "FAILED"
            res.notes.append("FORTIGATE_NO_LOGID")
            return res

        fields: Dict[str, Any] = {}
        originals: Dict[str, str] = {}
        vendor: Dict[str, Any] = {}

        # timestamp: date=YYYY-MM-DD time=HH:MM:SS (explicit, researched)
        d = pairs.get("date")
        t = pairs.get("time")
        if d and t:
            try:
                dt = datetime.strptime(f"{_unquote(d)} {_unquote(t)}", "%Y-%m-%d %H:%M:%S")
                fields["@timestamp"] = (
                    dt.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
                )
                originals["original.fortigate.timestamp"] = f"{d} {t}"
            except ValueError as exc:
                res.notes.append(f"FORTIGATE_INVALID_TIMESTAMP:{exc}")
        elif "eventtime" in pairs:
            et = pairs["eventtime"]
            if et.isdigit() and len(et) >= 13:
                ms = int(et)
                dt = datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)
                fields["@timestamp"] = dt.isoformat().replace("+00:00", "Z")
                originals["original.fortigate.eventtime"] = et
            else:
                res.notes.append("FORTIGATE_EVENTTIME_UNPARSED")
        else:
            res.notes.append("FORTIGATE_NO_TIMESTAMP_FIELDS")

        for key, val in pairs.items():
            base = key.split("#", 1)[0]
            raw = raw_values.get(key, val)
            originals[f"original.fortigate.{key}"] = raw
            vendor[f"fortigate.{key}"] = val
            if base == "logid":
                fields["fortigate.logid"] = val
            elif base == "type":
                fields["fortigate.type"] = val
            elif base == "subtype":
                fields["fortigate.subtype"] = val
            elif base == "vd":
                fields["fortigate.vdom"] = val
            elif base == "policyid":
                fields["fortigate.policyid"] = int(val) if val.isdigit() else val
            elif base == "sessionid":
                fields["fortigate.session_id"] = val
            elif base == "logdesc":
                fields["fortigate.logdesc"] = val
            elif base == "devid":
                fields["observer.serial_number"] = val
            elif base in _FG_MAP:
                mapped = _FG_MAP[base]
                if base in _FG_NUMERIC:
                    fields[mapped] = int(val) if val.isdigit() else None
                    if not val.isdigit():
                        res.notes.append(f"FORTIGATE_INVALID_NUMERIC:{key}={val[:20]}")
                else:
                    fields[mapped] = val
            # unmapped keys remain in vendor layer only (Rule 9: preserved)
        for idx, token in enumerate(unpaired):
            res.unknown_fields[f"fortigate.unpaired_{idx}"] = token

        res.fields = fields
        res.vendor_fields = vendor
        res.originals = originals
        res.decoded = {"kv_pairs": pairs}
        res.status = "PARSED"
        return res
