"""Operational metrics (build plan §40).

Thread-safe counters + gauges for the platform's own observability. These
count events received/parsed/partial/unknown, format and source outcomes,
errors per taxonomy, queue state and delivery results. This is operational
telemetry about the platform itself — not a security analytics engine.
"""

from __future__ import annotations

import threading
from typing import Dict


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: Dict[str, int] = {}

    def inc(self, name: str, amount: int = 1) -> None:
        with self._lock:
            self._counters[name] = self._counters.get(name, 0) + amount

    def get(self, name: str) -> int:
        with self._lock:
            return self._counters.get(name, 0)

    def snapshot(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._counters)

    # Convenience canonical metric names (§40) --------------------------------
    def event_received(self) -> None:
        self.inc("events_received")

    def event_parsed(self) -> None:
        self.inc("events_parsed")

    def event_partial(self) -> None:
        self.inc("events_partial_parsed")

    def event_unknown_source(self) -> None:
        self.inc("events_unknown_source")

    def event_unknown_format(self) -> None:
        self.inc("events_unknown_format")

    def event_parse_failed(self) -> None:
        self.inc("events_parse_failed")

    def event_validation_failed(self) -> None:
        self.inc("events_validation_failed")

    def delivered(self, target: str) -> None:
        self.inc(f"delivery_delivered.{target}")

    def delivery_failed(self, target: str) -> None:
        self.inc(f"delivery_failed.{target}")

    def delivery_rejected(self, target: str) -> None:
        self.inc(f"delivery_rejected.{target}")

    def spooled(self) -> None:
        self.inc("events_spooled")

    def error(self, code: str) -> None:
        self.inc(f"error.{code}")
