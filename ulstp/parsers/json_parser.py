"""JSON parser (research: docs/research/formats-kv-json-csv-plaintext.md).

stdlib json with object_pairs_hook so DUPLICATE KEYS ARE PRESERVED (`key`,
`key#2`, ... — Rule 9). Non-object top-level values (array/scalar) are
preserved under unknown layer instead of being forced into object shape.
Depth/size bounded per Skill 08. Flattens nested objects with dotted paths
for normalized candidates; arrays preserved as arrays (never joined/lost).
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple

from .base import Parser, ParseResult
from ..limits import ResourceLimits

_DEFAULT_LIMITS = ResourceLimits()

# Common generic JSON alias keys → normalized.
_JSON_KEY_MAP = {
    "src": "source.ip", "src_ip": "source.ip", "source": "source.ip",
    "dst": "destination.ip", "dst_ip": "destination.ip", "destination": "destination.ip",
    "src_port": "source.port", "srcport": "source.port",
    "dst_port": "destination.port", "dstport": "destination.port",
    "user": "source.user.name", "username": "source.user.name",
    "action": "event.action", "message": "message", "msg": "message",
    "level": "log.level", "severity": "log.level",
    "hostname": "observer.hostname", "host": "observer.hostname",
    "pid": "process.pid", "process": "process.name",
    "timestamp": "@timestamp", "time": "@timestamp", "@timestamp": "@timestamp",
    "proto": "network.transport", "protocol": "network.transport",
}


def _flatten(obj: Any, prefix: str, depth: int, max_depth: int,
             out: Dict[str, Any], notes: List[str]) -> None:
    if depth > max_depth:
        notes.append(f"JSON_MAX_DEPTH_EXCEEDED:{prefix}")
        out[prefix] = obj  # preserve remainder as-is (never dropped)
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, dict):
                _flatten(v, key, depth + 1, max_depth, out, notes)
            else:
                out[key] = v
    else:
        out[prefix] = obj


class JsonParser(Parser):
    name = "json"
    version = "1.0.0"
    formats = ("json",)

    def accept(self, msg: str) -> bool:
        stripped = msg.lstrip()
        return stripped.startswith("{") or stripped.startswith("[")

    def _parse(self, msg: str) -> ParseResult:
        res = ParseResult()
        try:
            doc = json.loads(msg, object_pairs_hook=_pairs_hook)
        except ValueError as exc:
            res.status = "FAILED"
            res.notes.append(f"JSON_INVALID:{exc}")
            return res

        notes: List[str] = []
        flat: Dict[str, Any] = {}
        if isinstance(doc, dict):
            _flatten(doc, "", 0, _DEFAULT_LIMITS.max_nested_depth, flat, notes)
        else:
            # non-object JSON: preserve verbatim, do not force object shape
            res.unknown_fields["json.value"] = doc
            res.notes.append("JSON_NON_OBJECT_TOP_LEVEL:preserved under unknown layer")

        fields: Dict[str, Any] = {}
        originals: Dict[str, str] = {}
        for key, val in flat.items():
            base = key.split("#", 1)[0]
            if isinstance(val, (dict, list)):
                # arrays/objects reached directly: preserved verbatim
                originals[f"original.json.{key}"] = json.dumps(val, ensure_ascii=False)
                fields[key if key in _JSON_KEY_MAP or key.startswith("@") else f"json.{key}"] = val
                continue
            originals[f"original.json.{key}"] = str(val)
            mapped = _JSON_KEY_MAP.get(base)
            if mapped == "source.port" or mapped == "destination.port":
                fields[mapped] = int(val) if str(val).isdigit() else None
            elif mapped == "@timestamp":
                fields[mapped] = val  # type validation happens in normalization
            elif mapped:
                fields[mapped] = val
            else:
                fields[f"json.{key}"] = val
        res.fields = fields
        res.originals = originals
        res.decoded = {"json_top_level_type": type(doc).__name__}
        res.notes.extend(notes)
        res.status = "PARSED"
        return res


def _pairs_hook(pairs):
    """json object_pairs_hook: preserve duplicate keys deterministically."""
    out: Dict[str, Any] = {}
    dup: Dict[str, int] = {}
    for k, v in pairs:
        if k in out:
            dup[k] = dup.get(k, 1) + 1
            out[f"{k}#{dup[k]}"] = v
        else:
            out[k] = v
    return out
