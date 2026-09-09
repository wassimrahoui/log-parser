"""Cisco ASA/PIX/FWSM/ASDM parser (research:
docs/research/vendors-cisco-asa-fortigate.md).

Token grammar: %DAEMON-severity-msgid: message text (researched, Cisco docs
+ MARS samples). Sub-grammars implemented ONLY for researched message IDs:
302013 (Built TCP), 302014 (Teardown TCP), 302015 (Built UDP) — each with
corroborated real samples. Other message IDs: token fields extracted, body
preserved verbatim, status PARTIAL (no invented fields, Rule 4).

Tuple→source/destination mapping: first positional tuple → source, second →
destination, following the device's emission order (same normalization as
Elastic filebeat ciscoasa); documented in the research record.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

from .base import Parser, ParseResult

_DAEMON_RE = re.compile(
    r"%(?P<daemon>ASA|PIX|FWSM|ASDM)-(?P<sev>[0-7])-(?P<msgid>\d{5,6}): (?P<body>.*)$",
    re.S,
)
_TUPLE_RE = re.compile(r"(?P<iface>[^:\s]+):(?P<ip>[0-9.]+|\[?[0-9A-Fa-f:]+\]?)/(?P<port>\d+)")

# Sub-grammars: (msgid, compiled regex) — only researched IDs (Rule 1/4).
# Real messages carry optional parenthesized tuple duplicates:
#   ... for outside:10.1.2.1/22 (10.1.2.1/22) to inside:10.1.1.2/53496 (...)  [Cisco FAQ/MARS]
#   ... for outside:192.0.2.222/1234 to dmz:192.168.1.34/5678                 [Elastic samples]
_DUP = r"(?: \([^)]*\))?"
_BUILT_TCP = re.compile(
    r"Built (?P<dir>outbound|inbound) (?P<proto>TCP) connection (?P<conn>\d+) "
    r"for (?P<one>\S+)" + _DUP + r" to (?P<two>\S+)" + _DUP +
    r"(?: duration (?P<dur>\d+:\d{2}:\d{2}) bytes (?P<bytes>\d+))?"
)
_BUILT_UDP = re.compile(
    r"Built UDP connection (?P<conn>\d+) for (?P<one>\S+)" + _DUP +
    r" to (?P<two>\S+)" + _DUP
)
# 302014 Teardown TCP ... duration h:mm:ss bytes N [reason]
_TEARDOWN_TCP = re.compile(
    r"Teardown (?P<proto>TCP|UDP) connection (?P<conn>\d+) "
    r"for (?P<one>\S+)" + _DUP + r" to (?P<two>\S+)" + _DUP +
    r" duration (?P<dur>\d+:\d{2}:\d{2}) bytes (?P<bytes>\d+)"
    r"(?: (?P<reason>[A-Za-z _-]+))?$"
)


class CiscoAsaParser(Parser):
    name = "cisco_asa"
    version = "1.0.0"
    formats = ("plain_text", "rfc3164")

    def accept(self, msg: str) -> bool:
        return _DAEMON_RE.search(msg) is not None

    def _parse(self, msg: str) -> ParseResult:
        res = ParseResult()
        m = _DAEMON_RE.search(msg)
        if not m:
            res.status = "FAILED"
            res.notes.append("ASA_NO_TOKEN")
            return res
        gd = m.groupdict()
        daemon, sev, msgid, body = gd["daemon"], int(gd["sev"]), gd["msgid"], gd["body"]

        fields: Dict[str, Any] = {
            "cisco.daemon": daemon,
            "cisco.message_id": msgid,
            "event.severity": sev,
            "message": body,
        }
        originals: Dict[str, str] = {
            "original.cisco.token": f"%{daemon}-{sev}-{msgid}",
            "original.cisco.body": body,
        }
        res.protocol_metadata = {"cisco.msgid": msgid, "cisco.daemon": daemon}
        res.decoded = {"cisco_token": gd["daemon"], "cisco_severity": sev,
                       "cisco_msgid": msgid, "cisco_body": body}

        parsed_body = False
        if msgid == "302013" or msgid == "302014":
            bm = _BUILT_TCP.match(body) or _TEARDOWN_TCP.match(body)
            if bm:
                self._extract_conn(bm.groupdict(), fields, originals, res)
                parsed_body = True
        elif msgid == "302015":
            bm = _BUILT_UDP.match(body)
            if bm:
                self._extract_conn(bm.groupdict(), fields, originals, res)
                parsed_body = True
        if not parsed_body:
            res.notes.append(f"ASA_BODY_NOT_SUBPARSED:no researched grammar for msgid {msgid}")
            res.status = "PARTIAL"
        else:
            res.status = "PARSED"
        res.fields = fields
        res.originals = originals
        return res

    @staticmethod
    def _extract_conn(gd: Dict[str, Optional[str]], fields, originals, res) -> None:
        fields["cisco.connection_id"] = gd.get("conn")
        for pos, key in (("one", "first"), ("two", "second")):
            tm = _TUPLE_RE.fullmatch(gd.get(pos) or "")
            if tm:
                fields[f"cisco.{key}_interface"] = tm.group("iface")
                fields[f"{'source' if key == 'first' else 'destination'}.ip"] = tm.group("ip")
                port = tm.group("port")
                fields[f"{'source' if key == 'first' else 'destination'}.port"] = int(port)
                originals[f"original.cisco.{key}_tuple"] = gd.get(pos) or ""
            else:
                res.notes.append(f"ASA_TUPLE_UNPARSED:{key}")
                res.unknown_fields[f"cisco.{key}_tuple_raw"] = gd.get(pos)
        dur = gd.get("dur")
        if dur:
            parts = dur.split(":")
            if len(parts) == 3 and all(p.isdigit() for p in parts):
                fields["event.duration_seconds"] = (
                    int(parts[0]) * 3600 + int(parts[1]) * 60 + int(parts[2])
                )
                originals["original.cisco.duration"] = dur
        if gd.get("bytes"):
            fields["network.bytes"] = int(gd["bytes"])
            originals["original.cisco.bytes"] = gd["bytes"]
        if gd.get("proto"):
            fields["network.transport"] = gd["proto"].lower()
