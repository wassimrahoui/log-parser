"""Resource limit / overflow / security tests (Skill 08/09; §26, §39)."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from ulstp.event import ParseStatus, ValidationStatus
from ulstp.framing import TcpFramer
from ulstp.limits import ResourceLimits
from ulstp.pipeline import Pipeline
from ulstp.errors import LimitExceededError
from tests.telemetry.golden.corpus import SAMPLES

ABUSE_SAMPLES = [
    "<134>1 " + "A" * 5000,                                  # huge token
    "CEF:0|" + "|".join(["x"] * 500),                        # 500 header fields
    "k=" + "v" * 5000 + " a=1 b=2",                          # huge value
    ("<134>1 2026-09-09T12:00:00Z h a 1 ID " + "[x a=\"b\"] " * 200 + "msg"),
    "\x00\x01\x02 control chars \x1f here",                  # control chars
    "<134>1 2026-09-09T12:00:00Z h a 1 ID - " + "Z" * 3000,  # huge msg
    "a=1 " * 300,                                            # 300 pairs
]


class TestOversizedInput:
    def test_tcp_framer_buffer_cap(self):
        tiny = ResourceLimits(max_message_bytes=64)
        f = TcpFramer(tiny)
        f.feed(b"x" * 200)
        assert f.error and "max_message_bytes" in f.error

    def test_udp_oversized_counted_rejected(self):
        p = Pipeline(limits=ResourceLimits(max_message_bytes=64))
        p.start()
        from ulstp.collectors import UdpCollector
        coll = UdpCollector(p.stage, host="127.0.0.1", port=0, limits=p.limits)
        coll.start()
        import socket, time
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b"x" * 200, ("127.0.0.1", coll.port))
        time.sleep(0.4)
        coll.stop()
        p.stop()
        # nothing enqueued; rejection counted explicitly
        assert p.history() == []
        assert p.metrics.get("error.LIMIT_EXCEEDED") >= 1


class TestMalformedRobustness:
    """Platform survives abuse; nothing crashes the pipeline (Skill 08)."""

    def test_abuse_survives_with_preservation(self):
        p = Pipeline()
        for raw in ABUSE_SAMPLES:
            ev = p.process_text(raw)  # must not raise
            assert ev.raw_message == raw
            assert ev.parse_status

    def test_control_chars_preserved_not_interpreted(self):
        p = Pipeline()
        raw = "\x00\x01\x02 control chars \x1f here"
        ev = p.process_text(raw)
        assert ev.normalized.get("message") == raw  # verbatim, no interpretation
        doc = ev.to_json()
        assert "\x00" not in doc  # JSON-escaped safely on serialization


class TestValidation:
    def test_invalid_ip_flagged_preserved(self):
        p = Pipeline()
        ev = p.process_text("CEF:0|V|P|1|s|n|5|src=999.999.1.1")
        assert ev.validation_status == ValidationStatus.INVALID.value
        assert ev.normalized.get("source.ip") == "999.999.1.1"  # preserved
        assert ev.validation_problems[0]["field"] == "source.ip"

    def test_invalid_port_flagged_preserved(self):
        p = Pipeline()
        ev = p.process_text("CEF:0|V|P|1|s|n|5|spt=99999")
        assert ev.validation_status == ValidationStatus.INVALID.value
        assert ev.normalized.get("source.port") == 99999  # preserved for review

    def test_valid_event(self):
        p = Pipeline()
        ev = p.process_text(SAMPLES[0]["raw"])
        assert ev.validation_status == ValidationStatus.VALID.value

    def test_empty_raw_invalid(self):
        p = Pipeline()
        ev = p.process_text("")
        assert ev.validation_status == ValidationStatus.INVALID.value


class TestDeterminism:
    def test_same_input_same_output(self):
        """Skill 02: same input + config ⇒ same output (twice, fresh registries)."""
        p1, p2 = Pipeline(), Pipeline()
        for raw in [c["raw"] for c in SAMPLES] + ABUSE_SAMPLES:
            e1, e2 = p1.process_text(raw), p2.process_text(raw)
            assert e1.normalized == e2.normalized
            assert e1.vendor_fields == e2.vendor_fields
            assert e1.unknown_fields == e2.unknown_fields
            assert e1.original_fields == e2.original_fields
            assert e1.parse_status == e2.parse_status
            assert e1.source_status == e2.source_status
