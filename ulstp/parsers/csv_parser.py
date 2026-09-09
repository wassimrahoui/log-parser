"""CSV/TSV parser (research: docs/research/formats-kv-json-csv-plaintext.md).

Positional meaning comes ONLY from configuration (deterministic; no column
semantics guessing). Without a configured schema, columns are extracted as
col_1..col_N with a PARTIAL status note (structure preserved, semantics
recorded as absent — never fabricated). RFC 4180 quoting.
"""

from __future__ import annotations

import csv
import io
from typing import Any, Dict, List, Optional, Tuple

from .base import Parser, ParseResult


class CsvParser(Parser):
    name = "csv"
    version = "1.0.0"
    formats = ("csv",)

    def __init__(self, schema: Optional[List[str]] = None,
                 delimiter: str = ",", has_header: bool = False) -> None:
        self.schema = schema or []
        self.delimiter = delimiter
        self.has_header = has_header

    def accept(self, msg: str) -> bool:
        if self.delimiter not in msg:
            return False
        if "\n" in msg:
            return False  # single-record events
        return True

    def _parse(self, msg: str) -> ParseResult:
        res = ParseResult()
        try:
            rows = list(csv.reader([msg], delimiter=self.delimiter,
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
        res.decoded = {"csv_columns": len(cols), "csv_delimiter": self.delimiter}
        res.status = status
        return res
