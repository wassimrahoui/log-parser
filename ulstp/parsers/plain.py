"""Plain text parser — the lossless fallback (§12: unknown must not vanish).

No field invention: records the message, basic line statistics, and keeps
the raw text in `message`. Guaranteed to "parse" anything (status PARSED),
because raw preservation IS the contract for unknown content (Skill 03).
Source/format stay unknown unless another stage identified them.
"""

from __future__ import annotations

from typing import Any, Dict

from .base import Parser, ParseResult


class PlainTextParser(Parser):
    name = "plain_text"
    version = "1.0.0"
    formats = ("plain_text", "unknown")

    def _parse(self, msg: str) -> ParseResult:
        res = ParseResult()
        res.fields = {
            "message": msg,
            "event.kind": "raw_preserved",
        }
        res.originals = {"original.message": msg}
        res.decoded = {
            "line_count": msg.count("\n") + 1,
            "byte_length": len(msg.encode("utf-8", errors="surrogateescape")),
        }
        res.status = "PARSED"
        return res
