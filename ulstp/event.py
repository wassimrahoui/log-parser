"""Core lossless event model (build plan §10, §11; Skill 03).

The event carries ALL information layers; nothing is ever removed once set:

  ingestion metadata | transport metadata | source identity | protocol metadata |
  original raw event | decoded representation | normalized fields | vendor fields |
  unknown fields | parser metadata | validation metadata

Design rules:
- ``raw_message`` is sacred: exact original telemetry (str) and/or raw bytes.
- Normalization never replaces the original: originals survive in
  ``original.*`` / ``vendor.*`` / ``unknown.*`` layers.
- Status fields (parse/delivery) are explicit; no fabricated values anywhere.
- dict_event() output is JSON-serializable with only str keys (dotted paths
  preserved as-is for SIEM delivery).
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class ParseStatus(str, Enum):
    PENDING = "PENDING"
    PARSED = "PARSED"
    PARTIAL = "PARTIAL"          # some fields extracted, some unknown (§13)
    FAILED = "FAILED"            # parser matched but failed; raw preserved
    UNKNOWN_FORMAT = "UNKNOWN_FORMAT"  # no parser accepted; raw preserved (§12)
    SKIPPED = "SKIPPED"          # parse budget exhausted; partial so far kept


class DeliveryStatus(str, Enum):
    PENDING = "PENDING"
    DELIVERED = "DELIVERED"
    FAILED = "FAILED"            # transient; retry eligible
    REJECTED = "REJECTED"        # permanent; routed to spool, never discarded
    SPOOLED = "SPOOLED"


class ValidationStatus(str, Enum):
    NOT_VALIDATED = "NOT_VALIDATED"
    VALID = "VALID"
    INVALID = "INVALID"          # invalid fields recorded, data preserved (§28)


class SourceStatus(str, Enum):
    KNOWN = "KNOWN"              # explicit rule matched (config or exact signature rule)
    INFERRED = "INFERRED"        # deterministic evidence matched a mapping
    UNKNOWN = "UNKNOWN"          # no rule matched; still a valid event (§12)


def _new_event_id() -> str:
    return uuid.uuid4().hex


@dataclass
class LosslessEvent:
    # ---- ingestion metadata -------------------------------------------------
    event_id: str = field(default_factory=_new_event_id)
    ingested_at_unix_utc: float = field(default_factory=time.time)

    # ---- transport metadata (filled by collector/framing) -------------------
    transport: Optional[str] = None           # udp | tcp | file | replay | stdin
    transport_protocol: Optional[str] = None  # syslog/udp | syslog/tcp | file/line | ...
    peer_ip: Optional[str] = None
    peer_port: Optional[int] = None
    local_port: Optional[int] = None
    source_name: Optional[str] = None         # configured source definition id, if matched
    file_path: Optional[str] = None
    file_line_number: Optional[int] = None

    # ---- original raw event (sacred, §11) -----------------------------------
    raw_message: Optional[str] = None
    raw_bytes_b64: Optional[str] = None       # only when transport supplies bytes (§ Skill 03)
    raw_size_bytes: Optional[int] = None

    # ---- protocol metadata ---------------------------------------------------
    protocol_metadata: dict = field(default_factory=dict)
    # e.g. syslog: {rfc: "5424"|"3164"|None, pri, facility, severity, is_valid_pri...}

    # ---- decoded representation ---------------------------------------------
    decoded: dict = field(default_factory=dict)   # format-level decode (syslog fields, cef header...)
    decode_ok: Optional[bool] = None
    decode_notes: list = field(default_factory=list)

    # ---- source identity ------------------------------------------------------
    source_status: str = SourceStatus.UNKNOWN.value
    vendor: Optional[str] = None
    product: Optional[str] = None
    product_version: Optional[str] = None
    hostname: Optional[str] = None
    source_evidence: list = field(default_factory=list)  # ordered [(key, value), ...] (Skill 04)

    # ---- parser metadata -------------------------------------------------------
    parser_name: Optional[str] = None
    parser_version: Optional[str] = None
    parse_status: str = ParseStatus.PENDING.value
    parse_notes: list = field(default_factory=list)
    format_detected: Optional[str] = None

    # ---- extracted / normalized layers ------------------------------------------
    normalized: dict = field(default_factory=dict)   # standardized names + typed values
    vendor_fields: dict = field(default_factory=dict)  # mapped vendor-specific fields
    unknown_fields: dict = field(default_factory=dict)  # unmapped fields, preserved (§ Rule 9)
    original_fields: dict = field(default_factory=dict)  # original string reps (Skill 03 rule 4)

    # ---- validation metadata ------------------------------------------------------
    validation_status: str = ValidationStatus.NOT_VALIDATED.value
    validation_problems: list = field(default_factory=list)  # list of {field, problem, value}

    # ---- delivery metadata ------------------------------------------------------------
    delivery_status: str = DeliveryStatus.PENDING.value
    delivery_target: Optional[str] = None
    delivery_error: Optional[str] = None
    delivery_attempts: int = 0

    # limits/observability
    truncated: bool = False
    parse_duration_ms: Optional[float] = None

    # ------------------------------------------------------------------ mutation API
    def add_evidence(self, key: str, value: Any) -> None:
        self.source_evidence.append((str(key), str(value)))

    def add_parse_note(self, note: str) -> None:
        if note not in self.parse_notes:
            self.parse_notes.append(note)

    def add_decode_note(self, note: str) -> None:
        if note not in self.decode_notes:
            self.decode_notes.append(note)

    def add_validation_problem(self, field_name: str, problem: str, value: Any) -> None:
        self.validation_problems.append(
            {"field": field_name, "problem": problem, "value": _safe(value)}
        )
        self.validation_status = ValidationStatus.INVALID.value

    # ------------------------------------------------------------------ serialization
    def dict_event(self) -> dict:
        """Full lossless event as a JSON-serializable dict (dotted keys preserved)."""
        return {
            "ingestion": {
                "event_id": self.event_id,
                "ingested_at_unix_utc": self.ingested_at_unix_utc,
            },
            "transport": {
                "transport": self.transport,
                "protocol": self.transport_protocol,
                "peer_ip": self.peer_ip,
                "peer_port": self.peer_port,
                "local_port": self.local_port,
                "source_name": self.source_name,
                "file_path": self.file_path,
                "file_line_number": self.file_line_number,
            },
            "raw": {
                "raw_message": self.raw_message,
                "raw_bytes_b64": self.raw_bytes_b64,
                "raw_size_bytes": self.raw_size_bytes,
                "truncated": self.truncated,
            },
            "protocol_metadata": self.protocol_metadata,
            "decoded": self.decoded,
            "decode_ok": self.decode_ok,
            "decode_notes": self.decode_notes,
            "source": {
                "status": self.source_status,
                "vendor": self.vendor,
                "product": self.product,
                "product_version": self.product_version,
                "hostname": self.hostname,
                "evidence": [[k, v] for k, v in self.source_evidence],
            },
            "parser": {
                "name": self.parser_name,
                "version": self.parser_version,
                "status": self.parse_status,
                "notes": self.parse_notes,
                "format_detected": self.format_detected,
                "duration_ms": self.parse_duration_ms,
            },
            "normalized": self.normalized,
            "vendor": self.vendor_fields,
            "unknown": self.unknown_fields,
            "original": self.original_fields,
            "validation": {
                "status": self.validation_status,
                "problems": self.validation_problems,
            },
            "delivery": {
                "status": self.delivery_status,
                "target": self.delivery_target,
                "error": self.delivery_error,
                "attempts": self.delivery_attempts,
            },
        }

    def to_json(self) -> str:
        return json.dumps(self.dict_event(), ensure_ascii=False, separators=(",", ":"))


def _safe(value: Any) -> Any:
    """Make a value safe for storage in metadata lists (never raises)."""
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        return repr(value)
