"""SIEM delivery (build plan §16, §29, §30; Skill 06).

Adapters (deterministic serialization, honest status, no silent loss):
- SpoolTarget:    JSONL file, full lossless event (verification + fallback)
- SyslogTarget:   RFC3164 envelope, JSON payload in MSG (Wazuh-compatible)
- ElasticTarget:  _bulk NDJSON over HTTP(S) with per-item error checking
- QradarTarget:   LEEF:1.0 serialization over syslog

DeliveryManager: bounded queue, batched delivery, retry with backoff, and a
guaranteed spool fallback on permanent failure. An event ends as DELIVERED,
FAILED (still retryable/spooled — never discarded), or SPOOLED.
"""

from __future__ import annotations

import base64
import json
import queue
import re
import socket
import threading
import time
from typing import Dict, List, Optional, Tuple

from .errors import ErrorCode
from .event import DeliveryStatus, LosslessEvent
from .limits import ResourceLimits
from .metrics import Metrics


# --------------------------------------------------------------------------
# serialization helpers
# --------------------------------------------------------------------------

def _leef_safe_key(key: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", key)


def _leef_escape_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n").replace("\r", "\\r")


def serialize_leef(event: LosslessEvent) -> str:
    """LEEF:1.0 tab-delimited; preserves raw + all preserved layers as
    attributes (QRadar accepts arbitrary key=value attributes)."""
    header_vendor = (event.vendor or "UnknownVendor").replace("|", "/")
    header_product = (event.product or event.parser_name or "UnknownProduct").replace("|", "/")
    event_id = (event.product or event.parser_name or "event").replace("|", "/")
    parts = [f"LEEF:1.0|{header_vendor}|{header_product}|1.0|{event_id}\t"]
    attrs: List[Tuple[str, str]] = [("sev", str(_event_severity(event)))]
    src_ip = event.normalized.get("source.ip")
    dst_ip = event.normalized.get("destination.ip")
    if src_ip:
        attrs.append(("src", str(src_ip)))
    if dst_ip:
        attrs.append(("dst", str(dst_ip)))
    raw = event.raw_message or ""
    attrs.append(("raw", _leef_escape_value(raw)))
    for layer_prefix, layer in (("u", event.unknown_fields), ("v", event.vendor_fields)):
        for key, val in layer.items():
            attrs.append((_leef_safe_key(f"{layer_prefix}_{key}"), _leef_escape_value(str(val))))
    parts.append("\t".join(f"{k}={v}" for k, v in attrs))
    return "".join(parts)


def _event_severity(event: LosslessEvent) -> int:
    sev = event.normalized.get("event.severity")
    if isinstance(sev, int):
        return max(0, min(10, sev))
    syslog_sev = event.protocol_metadata.get("syslog.severity")
    if isinstance(syslog_sev, int):
        return syslog_sev
    return 5


def serialize_syslog_json(event: LosslessEvent, tag: str = "ulstp", pri: int = 134) -> str:
    """RFC3164 envelope with full lossless JSON as MSG (Wazuh path)."""
    payload = json.dumps(event.dict_event(), ensure_ascii=False, separators=(",", ":"))
    host = event.hostname or (event.peer_ip or "unknown")
    return f"<{pri}>{_syslog_ts(event)} {host} {tag}: {payload}"


def _syslog_ts(event: LosslessEvent) -> str:
    ts = time.gmtime(event.ingested_at_unix_utc)
    return time.strftime("%b %e %H:%M:%S", ts).replace("  ", "  ")


# --------------------------------------------------------------------------
# targets
# --------------------------------------------------------------------------

class DeliveryTarget:
    name = "target"

    def deliver(self, events: List[LosslessEvent]) -> List[LosslessEvent]:
        """Deliver a batch; returns the subset that was DELIVERED. Failures
        are recorded on the events (status + error) and NOT returned."""
        raise NotImplementedError


class SpoolTarget(DeliveryTarget):
    """Append-only JSONL file. The guaranteed-lossless local target."""

    def __init__(self, path: str) -> None:
        self.name = f"spool:{path}"
        self.path = path
        self._lock = threading.Lock()

    def deliver(self, events: List[LosslessEvent]) -> List[LosslessEvent]:
        delivered: List[LosslessEvent] = []
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as fh:
                for ev in events:
                    try:
                        fh.write(ev.to_json() + "\n")
                        delivered.append(ev)
                    except (TypeError, ValueError) as exc:
                        ev.delivery_status = DeliveryStatus.FAILED.value
                        ev.delivery_error = f"SPOOL_SERIALIZE:{exc}"
                fh.flush()
        return delivered


class SyslogTarget(DeliveryTarget):
    """Syslog delivery (UDP or TCP newline-framed) — Wazuh-compatible path."""

    def __init__(self, host: str, port: int, transport: str = "udp",
                 tag: str = "ulstp", pri: int = 134, timeout: float = 5.0) -> None:
        self.name = f"syslog-{transport}:{host}:{port}"
        self.host = host
        self.port = port
        self.transport = transport
        self.tag = tag
        self.pri = pri
        self.timeout = timeout

    def deliver(self, events: List[LosslessEvent]) -> List[LosslessEvent]:
        delivered: List[LosslessEvent] = []
        sock: Optional[socket.socket] = None
        try:
            if self.transport == "tcp":
                sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
                sock.settimeout(self.timeout)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
            for ev in events:
                try:
                    line = serialize_syslog_json(ev, tag=self.tag, pri=self.pri)
                    wire = line.encode("utf-8", errors="surrogateescape") + b"\n"
                    if self.transport == "tcp":
                        sock.sendall(wire)
                    else:
                        sock.sendto(wire, (self.host, self.port))
                    ev.delivery_status = DeliveryStatus.DELIVERED.value
                    ev.delivery_target = self.name
                    delivered.append(ev)
                except OSError as exc:
                    ev.delivery_status = DeliveryStatus.FAILED.value
                    ev.delivery_error = f"SYSLOG_SEND:{exc}"
        except OSError as exc:
            for ev in events:
                if ev not in delivered:
                    ev.delivery_status = DeliveryStatus.FAILED.value
                    ev.delivery_error = f"SYSLOG_CONNECT:{exc}"
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        return delivered


class QradarTarget(SyslogTarget):
    """LEEF over syslog — QRadar path."""

    def __init__(self, host: str, port: int, transport: str = "tcp",
                 timeout: float = 5.0) -> None:
        super().__init__(host, port, transport=transport, tag="leef", timeout=timeout)
        self.name = f"qradar-leef-{transport}:{host}:{port}"

    def deliver(self, events: List[LosslessEvent]) -> List[LosslessEvent]:
        delivered: List[LosslessEvent] = []
        sock: Optional[socket.socket] = None
        try:
            if self.transport == "tcp":
                sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
                sock.settimeout(self.timeout)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
            for ev in events:
                try:
                    line = serialize_leef(ev)
                    wire = line.encode("utf-8", errors="surrogateescape") + b"\n"
                    if self.transport == "tcp":
                        sock.sendall(wire)
                    else:
                        sock.sendto(wire, (self.host, self.port))
                    ev.delivery_status = DeliveryStatus.DELIVERED.value
                    ev.delivery_target = self.name
                    delivered.append(ev)
                except OSError as exc:
                    ev.delivery_status = DeliveryStatus.FAILED.value
                    ev.delivery_error = f"QRADAR_SEND:{exc}"
        except OSError as exc:
            for ev in events:
                if ev not in delivered:
                    ev.delivery_status = DeliveryStatus.FAILED.value
                    ev.delivery_error = f"QRADAR_CONNECT:{exc}"
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        return delivered


class ElasticTarget(DeliveryTarget):
    """Elasticsearch/OpenSearch _bulk NDJSON over HTTP(S). Checks per-item
    errors in the response body — HTTP 200 with errors:true is NOT success
    (Skill 06 rule 3: never claim delivered that did not happen)."""

    def __init__(self, url: str, index_prefix: str = "ulstp",
                 api_key: Optional[str] = None, basic: Optional[Tuple[str, str]] = None,
                 timeout: float = 10.0) -> None:
        self.name = f"elastic:{url}"
        self.url = url.rstrip("/")
        self.index_prefix = index_prefix
        self.api_key = api_key
        self.basic = basic
        self.timeout = timeout

    def _index_name(self, event: LosslessEvent) -> str:
        day = time.strftime("%Y.%m.%d", time.gmtime(event.ingested_at_unix_utc))
        return f"{self.index_prefix}-{day}"

    @staticmethod
    def _flatten(doc: Dict, prefix: str = "") -> Dict:
        flat: Dict = {}
        for k, v in doc.items():
            key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, dict):
                flat.update(ElasticTarget._flatten(v, key))
            else:
                flat[key] = v
        return flat

    def deliver(self, events: List[LosslessEvent]) -> List[LosslessEvent]:
        import http.client
        from urllib.parse import urlparse

        parsed = urlparse(self.url)
        tls = parsed.scheme == "https"
        conn_cls = http.client.HTTPSConnection if tls else http.client.HTTPConnection
        conn = conn_cls(parsed.hostname, parsed.port or (443 if tls else 80),
                        timeout=self.timeout)
        body_lines: List[str] = []
        for ev in events:
            action = {"index": {"_index": self._index_name(ev)}}
            body_lines.append(json.dumps(action, separators=(",", ":")))
            doc = ElasticTarget._flatten(ev.dict_event())
            body_lines.append(json.dumps(doc, ensure_ascii=False, separators=(",", ":")))
        body = ("\n".join(body_lines) + "\n").encode("utf-8")
        headers = {"Content-Type": "application/x-ndjson"}
        if self.api_key:
            headers["Authorization"] = f"ApiKey {self.api_key}"
        elif self.basic:
            import base64 as b64
            cred = b64.b64encode(f"{self.basic[0]}:{self.basic[1]}".encode()).decode()
            headers["Authorization"] = f"Basic {cred}"
        delivered: List[LosslessEvent] = []
        try:
            conn.request("POST", "/_bulk", body=body, headers=headers)
            resp = conn.getresponse()
            resp_body = resp.read().decode("utf-8", errors="replace")
        except OSError as exc:
            for ev in events:
                ev.delivery_status = DeliveryStatus.FAILED.value
                ev.delivery_error = f"ELASTIC_CONNECT:{exc}"
            conn.close()
            return []
        except Exception as exc:  # http.client protocol errors etc.
            for ev in events:
                ev.delivery_status = DeliveryStatus.FAILED.value
                ev.delivery_error = f"ELASTIC_PROTOCOL:{type(exc).__name__}"
            conn.close()
            return []
        try:
            if resp.status != 200:
                for ev in events:
                    ev.delivery_status = DeliveryStatus.FAILED.value
                    ev.delivery_error = f"ELASTIC_HTTP:{resp.status}"
                return []
            try:
                data = json.loads(resp_body)
            except ValueError:
                for ev in events:
                    ev.delivery_status = DeliveryStatus.FAILED.value
                    ev.delivery_error = "ELASTIC_BAD_RESPONSE"
                return []
            items = data.get("items", [])
            if data.get("errors") or len(items) != len(events):
                for i, ev in enumerate(events):
                    item = items[i] if i < len(items) else {}
                    result = item.get("index", item)
                    if result.get("error"):
                        ev.delivery_status = DeliveryStatus.FAILED.value
                        ev.delivery_error = f"ELASTIC_ITEM:{result.get('error')}"
                    else:
                        ev.delivery_status = DeliveryStatus.DELIVERED.value
                        ev.delivery_target = self.name
                        delivered.append(ev)
            else:
                for ev in events:
                    ev.delivery_status = DeliveryStatus.DELIVERED.value
                    ev.delivery_target = self.name
                delivered = list(events)
        except OSError as exc:
            for ev in events:
                ev.delivery_status = DeliveryStatus.FAILED.value
                ev.delivery_error = f"ELASTIC_CONNECT:{exc}"
        finally:
            conn.close()
        return delivered


# --------------------------------------------------------------------------
# delivery manager (bounded queue + retry + spool, §30)
# --------------------------------------------------------------------------

class DeliveryManager:
    def __init__(
        self,
        target: DeliveryTarget,
        spool: SpoolTarget,
        limits: ResourceLimits,
        metrics: Metrics,
        batch_size: int = 100,
        flush_interval: float = 1.0,
    ) -> None:
        self.target = target
        self.spool = spool
        self.limits = limits
        self.metrics = metrics
        self.batch_size = min(batch_size, limits.max_batch_events)
        self.flush_interval = flush_interval
        self._queue: "queue.Queue[LosslessEvent]" = queue.Queue(
            maxsize=limits.max_queue_size
        )
        self._stop = threading.Event()
        self._worker: Optional[threading.Thread] = None
        self.errors: List[str] = []

    def start(self) -> None:
        self._worker = threading.Thread(target=self._run, name="ulstp-delivery", daemon=True)
        self._worker.start()

    def stop(self, flush: bool = True) -> None:
        self._stop.set()
        if self._worker:
            self._worker.join(timeout=15)
        if flush:
            self._drain_sync()

    def submit(self, event: LosslessEvent) -> None:
        try:
            self._queue.put(event, block=True, timeout=5.0)
        except queue.Full:
            self.metrics.error(ErrorCode.QUEUE_ERROR)
            self.metrics.inc("delivery_queue_overflow")
            self.errors.append("delivery queue full; event routed to spool")
            self._spool_event(event)  # never silently discard (§30)

    def _run(self) -> None:
        while not self._stop.is_set():
            batch: List[LosslessEvent] = []
            try:
                batch.append(self._queue.get(timeout=self.flush_interval))
            except queue.Empty:
                continue
            while len(batch) < self.batch_size:
                try:
                    batch.append(self._queue.get_nowait())
                except queue.Empty:
                    break
            self._deliver_batch(batch)

    def _drain_sync(self) -> None:
        batch: List[LosslessEvent] = []
        while True:
            try:
                batch.append(self._queue.get_nowait())
            except queue.Empty:
                break
        if batch:
            self._deliver_batch(batch)

    def _deliver_batch(self, batch: List[LosslessEvent]) -> None:
        pending = batch
        attempt = 0
        while pending and attempt <= self.limits.max_delivery_retries:
            delivered = self._safe_deliver(pending)
            for ev in delivered:
                ev.delivery_status = DeliveryStatus.DELIVERED.value
                ev.delivery_target = self.target.name
                ev.delivery_attempts = attempt + 1
                self.metrics.delivered(self.target.name.split(":")[0])
            pending = [ev for ev in pending if ev not in delivered]
            if not pending:
                return
            attempt += 1
            if attempt <= self.limits.max_delivery_retries:
                time.sleep(min(self.limits.retry_backoff_seconds * (2 ** (attempt - 1)), 30.0))
        # retries exhausted: spool fallback (explicit, never silent)
        for ev in pending:
            self._spool_event(ev)

    def _safe_deliver(self, batch: List[LosslessEvent]) -> List[LosslessEvent]:
        try:
            return self.target.deliver(batch)
        except Exception as exc:  # adapter bug → explicit failure, not crash
            self.errors.append(f"ADAPTER_ERROR:{type(exc).__name__}:{exc}")
            self.metrics.error(ErrorCode.SIEM_DELIVERY_ERROR)
            for ev in batch:
                ev.delivery_status = DeliveryStatus.FAILED.value
                ev.delivery_error = f"ADAPTER:{type(exc).__name__}:{exc}"
            return []

    def _spool_event(self, event: LosslessEvent) -> None:
        delivered = self.spool.deliver([event])
        if delivered:
            event.delivery_status = DeliveryStatus.SPOOLED.value
            event.delivery_target = self.spool.name
            self.metrics.spooled()
        else:
            # spool itself failed (disk full etc.): last resort, counted loudly
            event.delivery_status = DeliveryStatus.REJECTED.value
            self.metrics.delivery_rejected("spool")
            self.errors.append(f"SPOOL_FAILED:{event.delivery_error}")
