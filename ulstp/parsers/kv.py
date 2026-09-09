"""Generic key=value (logfmt) parser (research:
docs/research/formats-kv-json-csv-plaintext.md).

Space-separated key=value tokens; double-quoted values may contain spaces
and escaped quotes. Duplicate keys: normalized layer keeps the last value;
every occurrence is preserved (`key`, `key#2`, ... — Rule 9). Tokens that
do not match key=value are preserved as unpaired tokens. Every key is
extracted (§16).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from .base import Parser, ParseResult

_KV_ACCEPT_MIN_TOKENS = 2
_TOKEN_RE = re.compile(r"""([A-Za-z][A-Za-z0-9_.\-]*)=("([^"\\]|\\.)*"|[^\s]*)""")
_UNPAIRED_SPLIT_RE = re.compile(r"\s+")

# Common generic KV aliases → normalized (researched; vendor parsers carry
# their own richer maps).
KV_KEY_MAP = {
    "src": "source.ip", "src_ip": "source.ip", "srcip": "source.ip",
    "dst": "destination.ip", "dst_ip": "destination.ip", "dstip": "destination.ip",
    "src_port": "source.port", "sport": "source.port", "srcport": "source.port",
    "dst_port": "destination.port", "dport": "destination.port", "dstport": "destination.port",
    "user": "source.user.name", "usr": "source.user.name", "suser": "source.user.name",
    "action": "event.action", "msg": "message", "message": "message",
    "host": "observer.hostname", "hostname": "observer.hostname",
    "proto": "network.transport", "protocol": "network.transport",
    "level": "log.level", "severity": "log.level",
    "app": "service.name", "appname": "service.name", "process": "process.name",
    "pid": "process.pid", "session_id": "session.id", "sessionid": "session.id",
    "bytes_sent": "source.bytes", "bytes_received": "destination.bytes",
}


def _unquote(value: str) -> str:
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        inner = value[1:-1]
        return inner.replace('\\"', '"').replace("\\\\", "\\")
    return value


def tokenize_kv(text: str) -> Tuple[Dict[str, str], List[str], Dict[str, str]]:
    """Deterministic tokenizer. Returns (pairs, unpaired, raw_value_map)."""
    pairs: Dict[str, str] = {}
    dup_count: Dict[str, int] = {}
    raw_values: Dict[str, str] = {}
    unpaired: List[str] = []
    pos = 0
    n = len(text)
    while pos < n:
        while pos < n and text[pos] == " ":
            pos += 1
        if pos >= n:
            break
        m = _TOKEN_RE.match(text, pos)
        if m:
            key, raw_val = m.group(1), m.group(2)
            if key in pairs:
                dup_count[key] = dup_count.get(key, 1) + 1
                dup_key = f"{key}#{dup_count[key]}"
                pairs[dup_key] = _unquote(raw_val)
                raw_values[dup_key] = raw_val
            else:
                pairs[key] = _unquote(raw_val)
                raw_values[key] = raw_val
            pos = m.end()
        else:
            # unpaired token up to next whitespace
            nxt = text.find(" ", pos)
            if nxt == -1:
                nxt = n
            unpaired.append(text[pos:nxt])
            pos = nxt
    return pairs, unpaired, raw_values


class KvParser(Parser):
    name = "key_value"
    version = "1.0.0"
    formats = ("key_value",)

    def accept(self, msg: str) -> bool:
        pairs, _, _ = tokenize_kv(msg)
        return len(pairs) >= _KV_ACCEPT_MIN_TOKENS

    def _parse(self, msg: str) -> ParseResult:
        res = ParseResult()
        pairs, unpaired, raw_values = tokenize_kv(msg)
        if len(pairs) < _KV_ACCEPT_MIN_TOKENS:
            res.status = "FAILED"
            res.notes.append("KV_INSUFFICIENT_TOKENS")
            return res
        fields: Dict[str, Any] = {}
        originals: Dict[str, str] = {}
        for key, val in pairs.items():
            base_key = key.split("#", 1)[0]
            originals[f"original.kv.{key}"] = raw_values.get(key, val)
            mapped = KV_KEY_MAP.get(base_key)
            if mapped in ("source.port", "destination.port", "source.bytes",
                          "destination.bytes", "process.pid"):
                fields[mapped] = int(val) if val.isdigit() else None
                if not val.isdigit():
                    res.notes.append(f"KV_INVALID_NUMERIC:{key}={val[:20]}")
            elif mapped:
                fields[mapped] = val
            else:
                res.unknown_fields[f"kv.{key}"] = val
        for idx, token in enumerate(unpaired):
            res.unknown_fields[f"kv.unpaired_{idx}"] = token
            res.notes.append(f"KV_UNPAIRED_TOKEN:{token[:40]}")
        res.fields = fields
        res.originals = originals
        res.decoded = {"kv_pairs": pairs}
        res.status = "PARSED"
        return res
