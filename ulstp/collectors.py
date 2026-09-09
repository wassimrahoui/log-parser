"""Collectors (build plan §21).

Collectors acquire telemetry and push (raw bytes, transport metadata) tuples
into the bounded pipeline queue. They do NOT parse content (concern
separation, §21). All are bounded and observable (Skills 08/09).

- UdpCollector: one datagram = one message (OS-framed).
- TcpCollector: RFC 6587 stream; connection-limited; per-connection framer.
- FileCollector: line-oriented tailing of a file (newline framing).
- ReplayCollector: deterministic replay of saved raw telemetry (§35).
"""

from __future__ import annotations

import queue
import socket
import threading
import time
from typing import Callable, List, Optional, Tuple

from .errors import CollectorError, ErrorCode, LimitExceededError
from .event import LosslessEvent
from .framing import TcpFramer, frame_datagram, decode_message
from .limits import ResourceLimits
from .metrics import Metrics

RawBatch = Tuple[str, Optional[str], dict]  # (text, raw_bytes_b64|None, transport_meta)


class CollectorStage:
    """Common sink contract: collectors call emit(text, raw_b64, meta)."""

    def __init__(
        self,
        out_queue: "queue.Queue[LosslessEvent]",
        limits: ResourceLimits,
        metrics: Metrics,
    ) -> None:
        self.out_queue = out_queue
        self.limits = limits
        self.metrics = metrics

    def emit(self, text: str, raw_b64: Optional[str], meta: dict,
             notes: Optional[List[str]] = None) -> None:
        event = LosslessEvent(
            raw_message=text,
            raw_bytes_b64=raw_b64,
            raw_size_bytes=len(text.encode("utf-8", errors="surrogateescape")),
            truncated=False,
        )
        for note in notes or []:
            event.add_decode_note(note)
        for key, value in meta.items():
            if hasattr(event, key):
                setattr(event, key, value)
        self.metrics.event_received()
        # Bounded queue with explicit overflow accounting (Skill 09):
        try:
            self.out_queue.put(event, block=True, timeout=5.0)
        except queue.Full:
            self.metrics.error(ErrorCode.QUEUE_ERROR)
            self.metrics.inc("events_queue_overflow")
            # Backpressure exhausted: explicit, counted rejection — never silent.
            raise CollectorError("queue full; event rejected after backpressure timeout")


class UdpCollector:
    def __init__(
        self,
        stage: CollectorStage,
        host: str = "127.0.0.1",
        port: int = 5514,
        limits: Optional[ResourceLimits] = None,
    ) -> None:
        self.stage = stage
        self.host = host
        self.port = port
        self.limits = limits or stage.limits
        self._sock: Optional[socket.socket] = None
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.errors: List[str] = []

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        self._sock.bind((self.host, self.port))
        self.port = self._sock.getsockname()[1]  # resolved (port 0 → ephemeral)
        self._sock.settimeout(0.5)
        self._thread = threading.Thread(
            target=self._run, name="ulstp-udp-collector", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(self.limits.max_message_bytes + 1)
            except socket.timeout:
                continue
            except OSError as exc:
                if self._stop.is_set():
                    break
                if getattr(exc, "winerror", None) == 10040:
                    # WSAEMSGSIZE: datagram larger than recv buffer ⇒ oversized
                    # input, explicitly counted rejection (Skill 09)
                    self.stage.metrics.error(ErrorCode.LIMIT_EXCEEDED)
                    self.stage.metrics.inc("events_oversized_datagram")
                    continue
                self.errors.append(f"recvfrom: {exc}")
                self.stage.metrics.error(ErrorCode.COLLECTOR_ERROR)
                continue
            try:
                data = frame_datagram(data, self.limits)
                text, raw_b64, notes = decode_message(data, self.limits)
            except LimitExceededError:
                # oversized input: explicit, counted rejection (Skill 09)
                self.stage.metrics.error(ErrorCode.LIMIT_EXCEEDED)
                self.stage.metrics.inc("events_oversized_datagram")
                continue
            except Exception as exc:  # counted, observable, non-fatal
                self.stage.metrics.error(ErrorCode.DECODE_ERROR)
                self.errors.append(f"decode: {exc}")
                continue
            meta = {
                "transport": "udp",
                "transport_protocol": "syslog/udp",
                "peer_ip": addr[0],
                "peer_port": addr[1],
                "local_port": self.port,
            }
            self.stage.emit(text, raw_b64, meta, notes=notes)


class TcpCollector:
    def __init__(
        self,
        stage: CollectorStage,
        host: str = "127.0.0.1",
        port: int = 5601,
        limits: Optional[ResourceLimits] = None,
    ) -> None:
        self.stage = stage
        self.host = host
        self.port = port
        self.limits = limits or stage.limits
        self._sock: Optional[socket.socket] = None
        self._stop = threading.Event()
        self._threads: List[threading.Thread] = []
        self.errors: List[str] = []
        self._conn_count = 0
        self._conn_lock = threading.Lock()

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self.port = self._sock.getsockname()[1]  # resolved (port 0 → ephemeral)
        self._sock.listen(64)
        self._sock.settimeout(0.5)
        t = threading.Thread(target=self._accept_loop, name="ulstp-tcp-accept", daemon=True)
        t.start()
        self._threads.append(t)

    def stop(self) -> None:
        self._stop.set()
        for t in self._threads:
            t.join(timeout=5)

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                continue
            with self._conn_lock:
                if self._conn_count >= self.limits.max_connections:
                    self.stage.metrics.inc("connections_rejected_limit")
                    conn.close()
                    continue
                self._conn_count += 1
            t = threading.Thread(
                target=self._handle,
                args=(conn, addr),
                name="ulstp-tcp-conn",
                daemon=True,
            )
            t.start()
            self._threads.append(t)

    def _handle(self, conn: socket.socket, addr) -> None:
        framer = TcpFramer(self.limits)
        try:
            conn.settimeout(30.0)
            while not self._stop.is_set():
                try:
                    data = conn.recv(65536)
                except socket.timeout:
                    continue
                if not data:
                    break
                framer.feed(data)
                if framer.error:
                    self.stage.metrics.error(ErrorCode.FRAME_ERROR)
                    self.errors.append(f"frame: {framer.error}")
                    break
                while framer.frames:
                    raw = framer.frames.pop(0)
                    self._emit_frame(raw, addr)
        finally:
            with self._conn_lock:
                self._conn_count -= 1
            conn.close()

    def _emit_frame(self, raw: bytes, addr) -> None:
        try:
            text, raw_b64, notes = decode_message(raw, self.limits)
        except Exception as exc:
            self.stage.metrics.error(ErrorCode.DECODE_ERROR)
            self.errors.append(f"decode: {exc}")
            return
        meta = {
            "transport": "tcp",
            "transport_protocol": "syslog/tcp",
            "peer_ip": addr[0],
            "peer_port": addr[1],
            "local_port": self.port,
        }
        self.stage.emit(text, raw_b64, meta, notes=notes)


class FileCollector:
    """Tail/ingest a text file line-by-line (newline framing).

    Reads from the start by default (deterministic replay of a file corpus).
    Polls for growth when follow=True.
    """

    def __init__(
        self,
        stage: CollectorStage,
        path: str,
        follow: bool = False,
        limits: Optional[ResourceLimits] = None,
    ) -> None:
        self.stage = stage
        self.path = path
        self.follow = follow
        self.limits = limits or stage.limits
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run, name="ulstp-file-collector", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _run(self) -> None:
        line_no = 0
        with open(self.path, "r", encoding="utf-8", errors="surrogateescape") as fh:
            while not self._stop.is_set():
                line = fh.readline()
                if line:
                    line_no += 1
                    self._emit_line(line, line_no)
                    continue
                if not self.follow:
                    break
                time.sleep(0.2)

    def _emit_line(self, line: str, line_no: int) -> None:
        text = line[:-1] if line.endswith("\n") else line
        if text.endswith("\r"):
            text = text[:-1]
        if len(text.encode("utf-8", errors="surrogateescape")) > self.limits.max_message_bytes:
            self.stage.metrics.error(ErrorCode.LIMIT_EXCEEDED)
            self.stage.metrics.inc("events_oversized_file_line")
            return
        meta = {
            "transport": "file",
            "transport_protocol": "file/line",
            "file_path": self.path,
            "file_line_number": line_no,
        }
        self.stage.emit(text, None, meta)


class ReplayCollector:
    """Deterministic replay of saved raw telemetry through the SAME pipeline
    (build plan §35). Accepts raw strings OR raw bytes (byte-exact replay of
    captured telemetry, incl. non-UTF-8)."""

    def __init__(self, stage: CollectorStage) -> None:
        self.stage = stage

    def replay(self, raw_messages: List, transport: str = "replay") -> List[str]:
        event_ids: List[str] = []
        for i, raw in enumerate(raw_messages):
            data = raw if isinstance(raw, (bytes, bytearray)) else \
                raw.encode("utf-8", errors="surrogateescape")
            text, raw_b64, notes = decode_message(bytes(data), self.stage.limits)
            meta = {
                "transport": transport,
                "transport_protocol": f"{transport}/line",
                "file_line_number": i + 1,
            }
            self.stage.emit(text, raw_b64, meta, notes=notes)
        return event_ids
