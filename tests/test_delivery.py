"""SIEM delivery tests (Skill 06/07; §29/§30).

Real local receivers — no mocked success claims:
- spool target: real file, full lossless round-trip
- syslog targets: real UDP/TCP sockets, wire bytes verified
- LEEF serialization: attribute fidelity + raw preservation
- ElasticTarget: real local HTTP server (stdlib http.server) incl. the
  errors:true-per-item case (never claim delivered that did not happen)
- DeliveryManager: retry exhaustion routes to spool (never silent loss)
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from ulstp.delivery import (
    DeliveryManager, ElasticTarget, QradarTarget, SpoolTarget, SyslogTarget,
    serialize_leef, serialize_syslog_json,
)
from ulstp.event import DeliveryStatus
from ulstp.limits import ResourceLimits
from ulstp.metrics import Metrics
from ulstp.pipeline import Pipeline
from tests.telemetry.golden.corpus import SAMPLES

LIMITS = ResourceLimits(max_delivery_retries=1, retry_backoff_seconds=0.05)


def make_event(idx=1):
    p = Pipeline()
    return p.process_text(SAMPLES[idx]["raw"])


class TestSpoolTarget:
    def test_full_round_trip(self, tmp_path):
        target = SpoolTarget(str(tmp_path / "spool.jsonl"))
        ev = make_event()
        delivered = target.deliver([ev])
        assert delivered == [ev]
        line = (tmp_path / "spool.jsonl").read_text(encoding="utf-8").splitlines()[0]
        doc = json.loads(line)
        assert doc["raw"]["raw_message"] == SAMPLES[1]["raw"]
        assert doc["normalized"]["source.ip"] == "10.1.2.1"
        assert doc["source"]["vendor"] == "Cisco"

    def test_two_events_append(self, tmp_path):
        target = SpoolTarget(str(tmp_path / "spool.jsonl"))
        target.deliver([make_event(1)])
        target.deliver([make_event(0)])
        lines = (tmp_path / "spool.jsonl").read_text().splitlines()
        assert len(lines) == 2


class TestSyslogTarget:
    def test_udp_wire_format(self):
        received = []
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        sock.settimeout(2)
        port = sock.getsockname()[1]

        def reader():
            data, _ = sock.recvfrom(65536)
            received.append(data)

        t = threading.Thread(target=reader, daemon=True)
        t.start()
        target = SyslogTarget("127.0.0.1", port, transport="udp")
        ev = make_event()
        delivered = target.deliver([ev])
        t.join(2)
        sock.close()
        assert delivered == [ev]
        assert ev.delivery_status == DeliveryStatus.DELIVERED.value
        wire = received[0].decode("utf-8")
        assert wire.startswith("<134>")
        payload = wire.split(" ulstp: ", 1)[1]
        doc = json.loads(payload)
        assert doc["raw"]["raw_message"] == SAMPLES[1]["raw"]

    def test_tcp_wire_newline_framed(self):
        received = []
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        def reader():
            conn, _ = srv.accept()
            data = conn.recv(65536)
            received.append(data)
            conn.close()

        t = threading.Thread(target=reader, daemon=True)
        t.start()
        target = SyslogTarget("127.0.0.1", port, transport="tcp")
        ev = make_event()
        delivered = target.deliver([ev])
        t.join(2)
        srv.close()
        assert delivered == [ev]
        assert received[0].endswith(b"\n")  # newline framing for wazuh-remoted

    def test_connection_refused_is_failure_not_success(self):
        # port 1 on loopback: nothing listens there
        target = SyslogTarget("127.0.0.1", 1, transport="tcp", timeout=0.5)
        ev = make_event()
        delivered = target.deliver([ev])
        assert delivered == []
        assert ev.delivery_status == DeliveryStatus.FAILED.value
        assert ev.delivery_error


class TestQradarTarget:
    def test_leef_serialization_fidelity(self):
        ev = make_event(1)
        leef = serialize_leef(ev)
        # vendor/product from deterministic signature identification
        assert leef.startswith("LEEF:1.0|Cisco|ASA|1.0|ASA\t")
        assert "src=10.1.2.1" in leef
        assert "dst=10.1.1.2" in leef
        assert "raw=" in leef
        # tabs separate attributes; no tab inside raw (escaped)
        attrs = leef.split("\t")
        assert any(a.startswith("raw=") for a in attrs)

    def test_leef_tcp_delivery(self):
        received = []
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        def reader():
            conn, _ = srv.accept()
            received.append(conn.recv(65536))
            conn.close()

        t = threading.Thread(target=reader, daemon=True)
        t.start()
        target = QradarTarget("127.0.0.1", port, transport="tcp")
        ev = make_event(2)  # CEF event
        delivered = target.deliver([ev])
        t.join(2)
        srv.close()
        assert delivered == [ev]
        wire = received[0].decode("utf-8")
        # CEF event: product from CEF header identification
        assert wire.startswith("LEEF:1.0|Security|threat-manager|1.0|threat-manager\t")
        assert "src=10.0.0.5" in wire


class _BulkHandler(BaseHTTPRequestHandler):
    behavior = "ok"

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8")
        lines = [l for l in body.split("\n") if l]
        n_items = len(lines) // 2
        if _BulkHandler.behavior == "ok":
            resp = {"errors": False, "items": [{"index": {"_index": "x"}} for _ in range(n_items)]}
            self.send_response(200)
        elif _BulkHandler.behavior == "item_errors":
            resp = {"errors": True,
                    "items": [{"index": {"error": {"type": "mapper_parsing_exception"}}}
                              if i == 0 else {"index": {"_index": "x"}}
                              for i in range(n_items)]}
            self.send_response(200)
        else:  # http_error
            self.send_response(503)
            resp = None
        body_out = json.dumps(resp).encode()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body_out)))
        self.end_headers()
        if resp is not None:
            self.wfile.write(body_out)

    def log_message(self, *args):
        pass


class TestElasticTarget:
    def _server(self):
        srv = HTTPServer(("127.0.0.1", 0), _BulkHandler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv, f"http://127.0.0.1:{srv.server_port}"

    def test_successful_bulk(self):
        srv, url = self._server()
        _BulkHandler.behavior = "ok"
        try:
            target = ElasticTarget(url)
            ev = make_event()
            delivered = target.deliver([ev])
            assert delivered == [ev]
            assert ev.delivery_status == DeliveryStatus.DELIVERED.value
        finally:
            srv.shutdown()

    def test_per_item_errors_not_claimed_delivered(self):
        srv, url = self._server()
        _BulkHandler.behavior = "item_errors"
        try:
            target = ElasticTarget(url)
            ev1, ev2 = make_event(1), make_event(2)
            delivered = target.deliver([ev1, ev2])
            assert delivered == [ev2]  # item 0 failed per response
            assert ev1.delivery_status == DeliveryStatus.FAILED.value
            assert "ELASTIC_ITEM" in ev1.delivery_error
            assert ev2.delivery_status == DeliveryStatus.DELIVERED.value
        finally:
            srv.shutdown()

    def test_http_error_not_claimed_delivered(self):
        srv, url = self._server()
        _BulkHandler.behavior = "http_error"
        try:
            target = ElasticTarget(url)
            ev = make_event()
            delivered = target.deliver([ev])
            assert delivered == []
            assert ev.delivery_status == DeliveryStatus.FAILED.value
        finally:
            srv.shutdown()

    def test_ndjson_body_shape(self):
        captured = {}

        class Capture(_BulkHandler):
            def do_POST(self):
                captured["body"] = self.rfile.read(
                    int(self.headers.get("Content-Length", 0))).decode()
                captured["ctype"] = self.headers.get("Content-Type")
                self.send_response(200)
                out = json.dumps({"errors": False, "items": [{"index": {}}]}).encode()
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

        srv = HTTPServer(("127.0.0.1", 0), Capture)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            target = ElasticTarget(f"http://127.0.0.1:{srv.server_port}")
            target.deliver([make_event()])
            lines = captured["body"].rstrip("\n").split("\n")
            assert captured["ctype"] == "application/x-ndjson"
            assert len(lines) == 2
            action = json.loads(lines[0])
            assert "index" in action and action["index"]["_index"].startswith("ulstp-")
            doc = json.loads(lines[1])
            assert doc["raw.raw_message"] == SAMPLES[1]["raw"]  # flattened layers
        finally:
            srv.shutdown()


class TestDeliveryManager:
    def test_delivered_via_spool_when_target_down(self, tmp_path):
        spool = SpoolTarget(str(tmp_path / "spool.jsonl"))
        mgr = DeliveryManager(
            SyslogTarget("127.0.0.1", 1, transport="tcp", timeout=0.3),
            spool, LIMITS, Metrics(), batch_size=10, flush_interval=0.1,
        )
        ev = make_event()
        mgr.submit(ev)
        mgr.stop(flush=True)
        assert ev.delivery_status == DeliveryStatus.SPOOLED.value
        lines = (tmp_path / "spool.jsonl").read_text().splitlines()
        assert len(lines) == 1  # event preserved, not discarded
        assert json.loads(lines[0])["raw"]["raw_message"] == SAMPLES[1]["raw"]

    def test_delivered_via_real_target(self, tmp_path):
        spool = SpoolTarget(str(tmp_path / "spool.jsonl"))
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        sock.settimeout(2)
        port = sock.getsockname()[1]
        mgr = DeliveryManager(
            SyslogTarget("127.0.0.1", port, transport="udp"),
            spool, LIMITS, Metrics(), batch_size=10, flush_interval=0.1,
        )
        mgr.start()
        ev = make_event()
        mgr.submit(ev)
        try:
            sock.recvfrom(65536)
        except socket.timeout:
            pass
        mgr.stop(flush=True)
        sock.close()
        assert ev.delivery_status == DeliveryStatus.DELIVERED.value
