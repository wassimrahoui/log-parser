"""CSV/TSV parser (research: docs/research/formats-kv-json-csv-plaintext.md).

Positional meaning comes ONLY from configuration (deterministic; no column
semantics guessing). Without a configured schema, columns are extracted as
col_1..col_N with a PARTIAL status note (structure preserved, semantics
recorded as absent — never fabricated). RFC 4180 quoting.

Delimiter selection is deterministic: an explicitly configured delimiter is
always used; otherwise the candidate set (comma, tab, semicolon per the
researched grammar) is scored per message and the most frequent wins, ties
broken in that fixed order. The delimiter actually used is recorded in the
decoded layer (csv_delimiter).
"""

from __future__ import annotations

import csv
import io
from typing import Any, Dict, List, Optional, Tuple

from .base import Parser, ParseResult

CANDIDATE_DELIMITERS: Tuple[str, ...] = (",", "\t", ";")


class CsvParser(Parser):
    name = "csv"
    version = "1.1.0"
    formats = ("csv",)

    def __init__(self, schema: Optional[List[str]] = None,
                 delimiter: Optional[str] = None, has_header: bool = False) -> None:
        self.schema = schema or []
        # None ⇒ auto-select per message (comma/tab/semicolon, see module doc).
        # An explicit delimiter always wins over auto-selection.
        self.delimiter = delimiter
        self.has_header = has_header  # inert for single-record events (documented)

    def _select_delimiter(self, msg: str) -> Optional[str]:
        """Deterministic: most frequent candidate wins; ties broken by the
        fixed candidate order. None when no candidate occurs."""
        if self.delimiter is not None:
            return self.delimiter if self.delimiter in msg else None
        best: Optional[str] = None
        best_count = 0
        for d in CANDIDATE_DELIMITERS:
            count = msg.count(d)
            if count > best_count:
                best, best_count = d, count
        return best

    def accept(self, msg: str) -> bool:
        if "\n" in msg:
            return False  # single-record events
        return self._select_delimiter(msg) is not None

    def _parse(self, msg: str) -> ParseResult:
        res = ParseResult()
        delimiter = self._select_delimiter(msg)
        if delimiter is None:
            res.status = "FAILED"
            res.notes.append("CSV_NO_DELIMITER")
            return res
        try:
            rows = list(csv.reader([msg], delimiter=delimiter,
                                   quotechar='"', skipinitialspace=False))
        except csv.Error as exc:
            res.status = "FAILED"
            res.notes.append(f"CSV_ERROR:{exc}")
            return res
        if not rows:
            res.status = "FAILED"
            res.notes.append("CSV_EMPTY")
            return res
        cols = rows[0]
        fields: Dict[str, Any] = {}
        originals: Dict[str, str] = {}
        if self.schema and len(cols) == len(self.schema):
            for name, val in zip(self.schema, cols):
                fields[name] = val
                originals[f"original.csv.{name}"] = val
            status = "PARSED"
        elif self.schema and len(cols) != len(self.schema):
            res.notes.append(
                f"CSV_COLUMN_COUNT_MISMATCH:{len(cols)} vs schema {len(self.schema)}"
            )
            for i, val in enumerate(cols):
                fields[f"col_{i + 1}"] = val
                originals[f"original.csv.col_{i + 1}"] = val
            status = "PARTIAL"
        else:
            for i, val in enumerate(cols):
                fields[f"col_{i + 1}"] = val
                originals[f"original.csv.col_{i + 1}"] = val
            res.notes.append("CSV_NO_SCHEMA:positional columns preserved without semantics")
            status = "PARTIAL"
        res.fields = fields
        res.originals = originals
        res.decoded = {"csv_columns": len(cols), "csv_delimiter": delimiter}
        res.status = status
        return res
