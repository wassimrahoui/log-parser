"""Resource limits (build plan §39; Skills 08/09).

All limits are configurable. Limits are enforced BEFORE allocation-heavy
work. Exceeding a limit ends in an explicit, counted, observable state —
never a silent drop and never an unbounded allocation. Where truncation is
configured, it is recorded as a status flag and preserves as much original
information as possible.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ResourceLimits:
    max_message_bytes: int = 64 * 1024          # max telemetry message size
    max_field_bytes: int = 8 * 1024             # max single extracted field size
    max_field_count: int = 512                  # max fields extracted per event
    max_nested_depth: int = 32                  # max JSON/SD nesting depth
    max_connections: int = 256                  # per listener
    max_queue_size: int = 10_000                # bounded internal queue
    max_parse_seconds: float = 2.0              # parser budget per event
    max_batch_events: int = 500                 # SIEM batch size
    max_spool_bytes: int = 256 * 1024 * 1024    # disk spool bound
    max_delivery_retries: int = 5              # before routing to spool
    retry_backoff_seconds: float = 1.0

    def validate(self) -> None:
        problems = []
        if self.max_message_bytes < 1:
            problems.append("max_message_bytes must be >= 1")
        if self.max_field_count < 1:
            problems.append("max_field_count must be >= 1")
        if self.max_nested_depth < 1:
            problems.append("max_nested_depth must be >= 1")
        if self.max_queue_size < 1:
            problems.append("max_queue_size must be >= 1")
        if self.max_parse_seconds <= 0:
            problems.append("max_parse_seconds must be > 0")
        if problems:
            raise ValueError("; ".join(problems))


DEFAULT_LIMITS = ResourceLimits()
