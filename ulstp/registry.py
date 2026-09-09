"""Parser registry and deterministic resolution (build plan §14, §9; Skill 02).

Resolution sequence (fixed order, no probability):
  detected format candidates (ordered)
    → registry order within each candidate
    → parser.accept(signature) check
  First deterministic hit wins; the full decision is recorded on the event.

Syslog-envelope chaining: when a syslog parser wins and its decoded message
matches an inner format, ONE inner parse is performed and merged (parser
chain recorded, e.g. "rfc3164+cef").
"""

from __future__ import annotations

from typing import List, Optional

from . import format_detection as fd
from .parsers.base import Parser
from .parsers.rfc5424 import Rfc5424Parser
from .parsers.rfc3164 import Rfc3164Parser
from .parsers.cef import CefParser
from .parsers.leef import LeefParser
from .parsers.kv import KvParser
from .parsers.fortigate import FortiGateParser
from .parsers.cisco_asa import CiscoAsaParser
from .parsers.json_parser import JsonParser
from .parsers.csv_parser import CsvParser
from .parsers.plain import PlainTextParser

DEFAULT_REGISTRY_ORDER = [
    Rfc5424Parser,
    Rfc3164Parser,
    FortiGateParser,
    CefParser,
    LeefParser,
    KvParser,
    JsonParser,
    CsvParser,
    CiscoAsaParser,
    PlainTextParser,
]

SYSLOG_FORMATS = {"rfc5424", "rfc3164"}


class ParserRegistry:
    def __init__(self, parsers: Optional[List[Parser]] = None) -> None:
        if parsers is None:
            parsers = [cls() for cls in DEFAULT_REGISTRY_ORDER]
        self.parsers: List[Parser] = parsers

    def register(self, parser: Parser, index: Optional[int] = None) -> None:
        if index is None:
            self.parsers.append(parser)
        else:
            self.parsers.insert(index, parser)

    def resolve(self, candidates: List[str], text: str) -> Optional[Parser]:
        """Deterministic: iterate candidates (detection order), then registry
        order; first parser whose formats match the candidate AND whose
        signature accepts the text wins."""
        for candidate in candidates:
            for parser in self.parsers:
                if candidate in parser.formats and parser.accept(text):
                    return parser
        return None

    def resolve_inner(self, text: str) -> Optional[Parser]:
        """Resolve a parser for an inner message (after syslog envelope)."""
        candidates = fd.detect_formats_multi(text)
        non_syslog = [c for c in candidates if c not in SYSLOG_FORMATS]
        return self.resolve(non_syslog or candidates, text)
