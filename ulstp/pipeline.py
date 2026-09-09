"""Pipeline orchestration (build plan §9 conceptual flow).

    collect → frame/decode (collector stage) → format detection →
    configured-source parser_hint (§20, pre-parse) → parser resolution →
    parsing → merge/normalize → field limits (§39) → source identification →
    type handling → validation → sink (delivery layer)

Determinism: same input + same registry/config ⇒ same event output.
No event is ever dropped: unknown formats fall back to lossless
preservation with explicit status (§12), failures are counted and noted.
Limit enforcement is annotation + counted status, never deletion (Skill 03).
"""

from __future__ import annotations

import queue
import threading
import time
from collections import deque
from typing import Callable, Deque, List, Optional

from .errors import ErrorCode
from .event import LosslessEvent, ParseStatus, SourceStatus, ValidationStatus
from .format_detection import FORMAT_UNKNOWN, detect_formats_multi
from .limits import DEFAULT_LIMITS, ResourceLimits
from .metrics import Metrics
from .normalize import finalize_types, merge_parse_result
from .parsers.plain import PlainTextParser
from .registry import ParserRegistry
from .source_id import SourceDefinition, SourceIdentifier


class Pipeline:
    def __init__(
        self,
        limits: Optional[ResourceLimits] = None,
        registry: Optional[ParserRegistry] = None,
        source_definitions: Optional[List[SourceDefinition]] = None,
        metrics: Optional[Metrics] = None,
        history_size: int = 1000,
    ) -> None:
        self.limits = limits or DEFAULT_LIMITS
        self.metrics = metrics or Metrics()
        self.registry = registry or ParserRegistry()
        self.source_identifier = SourceIdentifier(source_definitions or [])
        self.in_queue: "queue.Queue[LosslessEvent]" = queue.Queue(
            maxsize=self.limits.max_queue_size
        )
        from .collectors import CollectorStage, ReplayCollector

        self.stage = CollectorStage(self.in_queue, self.limits, self.metrics)
        self.replay = ReplayCollector(self.stage)
        self.sink: Optional[Callable[[LosslessEvent], None]] = None
        self._history: Deque[LosslessEvent] = deque(maxlen=history_size)
        self._history_lock = threading.Lock()
        self._stop = threading.Event()
        self._worker: Optional[threading.Thread] = None

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> None:
        self._worker = threading.Thread(target=self._run, name="ulstp-pipeline", daemon=True)
        self._worker.start()

    def stop(self) -> None:
        self._stop.set()
        if self._worker:
            self._worker.join(timeout=10)

    def wait_until_drained(self, timeout: float = 10.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.in_queue.empty():
                # give the worker a beat to finish the current event
                time.sleep(0.05)
                if self.in_queue.empty():
                    return True
            time.sleep(0.05)
        return False

    # ------------------------------------------------------------------ synchronous entry (tests/CLI/replay)
    def process_text(self, text: str, meta: Optional[dict] = None) -> LosslessEvent:
        event = LosslessEvent(raw_message=text)
        for key, value in (meta or {}).items():
            if hasattr(event, key):
                setattr(event, key, value)
        self.metrics.event_received()
        self._process_event(event)
        self._record(event)
        return event

    # ------------------------------------------------------------------ worker
    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                event = self.in_queue.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                self._process_event(event)
            except Exception as exc:  # never lose the event silently (Rule 27)
                self.metrics.error(ErrorCode.PARSE_ERROR)
                event.add_parse_note(f"PIPELINE_ERROR:{type(exc).__name__}:{exc}")
                event.parse_status = ParseStatus.FAILED.value
            finally:
                self._record(event)

    def _record(self, event: LosslessEvent) -> None:
        with self._history_lock:
            self._history.append(event)
        if self.sink is not None:
            try:
                self.sink(event)
            except Exception as exc:  # delivery-layer errors are its own status
                self.metrics.error(ErrorCode.SIEM_DELIVERY_ERROR)
                event.delivery_status = event.delivery_status or None

    def _enforce_field_limits(self, event: LosslessEvent) -> None:
        """§39 field limits over the EXTRACTED layers (normalized, vendor,
        unknown). Enforcement is annotation + counted status; values are
        never removed, and the original_fields preservation layer is exempt
        by design (it exists to guarantee nothing is lost)."""
        limits = self.limits
        oversized: List[str] = []
        for layer_name in ("normalized", "vendor_fields", "unknown_fields"):
            layer = getattr(event, layer_name)
            for key, value in layer.items():
                if isinstance(value, str):
                    size = len(value.encode("utf-8", errors="replace"))
                    if size > limits.max_field_bytes:
                        oversized.append(f"{key}:{size}>{limits.max_field_bytes}")
        extracted = (len(event.normalized) + len(event.vendor_fields)
                     + len(event.unknown_fields))
        over_count = extracted - limits.max_field_count
        for item in oversized:
            event.add_parse_note(f"FIELD_LIMIT_EXCEEDED:{item}")
        if over_count > 0:
            event.add_parse_note(
                f"FIELD_COUNT_LIMIT_EXCEEDED:{over_count}_beyond_{limits.max_field_count}"
            )
        if oversized or over_count > 0:
            event.truncated = True
            self.metrics.inc("events_field_limits")

    # ------------------------------------------------------------------ core stage sequence
    def _process_event(self, event: LosslessEvent) -> None:
        text = event.raw_message or ""
        started = time.perf_counter()

        # 1) format detection (deterministic candidates, §23)
        candidates = detect_formats_multi(text)
        primary_format = candidates[0] if candidates else FORMAT_UNKNOWN

        # 2) parser resolution (deterministic, §14/§9/§20). A matched
        # configured source may carry a parser_hint: the hinted parser is
        # tried first, fallback is the standard walk, and the routing
        # decision is recorded on the event. The configured match is
        # evaluated exactly once here and reused by identification below.
        pre_matched = self.source_identifier.pre_parse_hint(event)
        hint = pre_matched[0].parser_hint if pre_matched[0] is not None else None
        parser, hint_decision = self.registry.resolve_with_hint(candidates, text, hint)
        if hint_decision is not None:
            event.add_parse_note(f"PARSER_HINT:{hint_decision}:{hint}")

        result = None
        inner_result = None
        chain = None
        if parser is None:
            # UNKNOWN FORMAT: lossless fallback — raw preserved, explicit status (§12)
            result = PlainTextParser().parse(text)
            merge_parse_result(event, result, "plain_text", "1.0.0", FORMAT_UNKNOWN)
            event.parse_status = ParseStatus.UNKNOWN_FORMAT.value
            self.metrics.event_unknown_format()
        else:
            result = parser.parse(text)
            merge_parse_result(event, result, parser.name, parser.version, primary_format)
            # 3) syslog-envelope inner chaining (one level, deterministic).
            # plain_text inner results add nothing (message already carried
            # verbatim by the envelope) — no chain, no noise.
            if parser.name in ("rfc5424", "rfc3164"):
                inner_text = result.decoded.get("message") or ""
                if inner_text:
                    inner_parser = self.registry.resolve_inner(inner_text)
                    if (inner_parser is not None
                            and inner_parser.name != parser.name
                            and inner_parser.name != "plain_text"):
                        inner_result = inner_parser.parse(inner_text)
                        chain = f"{parser.name}+{inner_parser.name}"
                        merge_parse_result(
                            event,
                            inner_result,
                            inner_parser.name,
                            inner_parser.version,
                            inner_parser.name,
                            chain=chain,
                        )
                        # the ENVELOPE format stays the event's format
                        event.format_detected = primary_format
            # plain_text as the FALLBACK carrier means: no format recognized.
            # Honest status is UNKNOWN_FORMAT, not PARSED (§12; Skill 03).
            if parser.name == "plain_text":
                event.format_detected = FORMAT_UNKNOWN
                event.parse_status = ParseStatus.UNKNOWN_FORMAT.value
                self.metrics.event_unknown_format()

        # reconcile status when a chain ran (envelope + inner)
        if chain and result is not None:
            statuses = {result.status}
            if inner_result is not None:
                statuses.add(inner_result.status)
            if "FAILED" in statuses and len(statuses) > 1:
                event.parse_status = ParseStatus.PARTIAL.value
                event.add_parse_note("CHAIN_PARTIAL:envelope parsed, inner failed")
            elif "FAILED" in statuses:
                event.parse_status = ParseStatus.FAILED.value
            elif "PARTIAL" in statuses:
                event.parse_status = ParseStatus.PARTIAL.value

        # 3.5) field-level resource limits (§39): exceeding a field limit is
        # an explicit, counted, per-field note — values are never deleted
        # (Skill 03 lossless rule).
        self._enforce_field_limits(event)

        # parse budget observation (Skill 09; preemptive kill is documented
        # as a limitation — synchronous parser records overruns explicitly)
        duration_ms = (time.perf_counter() - started) * 1000.0
        event.parse_duration_ms = round(duration_ms, 3)
        if duration_ms > self.limits.max_parse_seconds * 1000.0:
            event.add_parse_note("PARSE_BUDGET_EXCEEDED:recorded (synchronous parse)")

        # 4) source identification (deterministic, explainable, §20)
        ident = self.source_identifier.identify(event, pre_matched=pre_matched)
        event.source_status = ident.status
        event.vendor = ident.vendor
        event.product = ident.product
        if ident.source_id:
            event.source_name = ident.source_id
        event.source_evidence = list(ident.evidence)
        if ident.status == SourceStatus.UNKNOWN.value:
            self.metrics.event_unknown_source()

        # 5) type handling (§12/§18) — annotated, never destructive
        finalize_types(event)

        # 6) validation (§28) — structural checks; invalid data preserved
        problems = list(event.validation_problems)
        if not event.raw_message:
            problems.append({"field": "raw", "problem": "raw_message missing", "value": None})
        for p in problems:
            if p not in event.validation_problems:
                event.add_validation_problem(p["field"], p["problem"], p["value"])
        if event.validation_problems:
            event.validation_status = ValidationStatus.INVALID.value
            self.metrics.event_validation_failed()
        else:
            event.validation_status = ValidationStatus.VALID.value

        # 7) outcome metrics
        if event.parse_status == ParseStatus.PARSED.value:
            self.metrics.event_parsed()
        elif event.parse_status == ParseStatus.PARTIAL.value:
            self.metrics.event_partial()

    # ------------------------------------------------------------------ inspection
    def history(self) -> List[LosslessEvent]:
        with self._history_lock:
            return list(self._history)
