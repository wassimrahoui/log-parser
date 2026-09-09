"""Golden (§49), lossless (§50), unknown-source (§51), partial-parse (§52),
no-silent-loss (§53), and E2E (§54) pipeline tests."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import base64
import time

from ulstp.event import ParseStatus, SourceStatus, ValidationStatus
from ulstp.pipeline import Pipeline
from tests.telemetry.golden.corpus import SAMPLES
from tests.telemetry.generic.syslog.malformed import CORPUS as SYSLOG_MALFORMED
from tests.telemetry.generic.cef.malformed import CORPUS as CEF_MALFORMED
from tests.telemetry.generic.json.malformed import CORPUS as JSON_MALFORMED


def make_pipeline() -> Pipeline:
    return Pipeline()


class TestGolden:
    def test_golden_corpus(self):
        p = make_pipeline()
        for case in SAMPLES:
            ev = p.process_text(case["raw"])
            exp = case["expect"]
            assert ev.source_status == exp["source_status"], case["name"]
            assert ev.format_detected == exp["format"], case["name"]
            assert ev.parser_name == exp["parser"], case["name"]
            if "vendor" in exp:
                assert ev.vendor == exp["vendor"], case["name"]
            if "parse_status" in exp:
                assert ev.parse_status == exp["parse_status"], case["name"]
            else:
                assert ev.parse_status in ("PARSED", "PARTIAL"), case["name"]
            for key, val in exp["fields"].items():
                assert ev.normalized.get(key) == val, \
                    f"{case['name']}: {key}={ev.normalized.get(key)!r} != {val!r}"
            for key in exp["originals_present"]:
                assert key in ev.original_fields, f"{case['name']}: missing {key}"
            for key in exp.get("unknown_present", []):
                assert key in ev.unknown_fields, f"{case['name']}: missing unknown {key}"
            if exp["raw_preserved"]:
                assert ev.raw_message == case["raw"], case["name"]


class TestLossless:
    """§50: raw recoverable after every stage incl. SIEM serialization."""

    def test_raw_survives_full_pipeline(self):
        p = make_pipeline()
        for case in SAMPLES:
            ev = p.process_text(case["raw"])
            assert ev.raw_message == case["raw"]
            assert ev.dict_event()["raw"]["raw_message"] == case["raw"]

    def test_raw_survives_json_serialization(self):
        import json
        p = make_pipeline()
        ev = p.process_text(SAMPLES[1]["raw"])
        round_trip = json.loads(ev.to_json())
        assert round_trip["raw"]["raw_message"] == SAMPLES[1]["raw"]

    def test_raw_survives_leef_serialization(self):
        from ulstp.delivery import serialize_leef
        p = make_pipeline()
        ev = p.process_text(SAMPLES[1]["raw"])
        leef = serialize_leef(ev)
        assert "raw=" in leef
        # raw attribute present and escaped; raw_message still on event
        assert ev.raw_message == SAMPLES[1]["raw"]

    def test_raw_survives_syslog_json_serialization(self):
        import json
        from ulstp.delivery import serialize_syslog_json
        p = make_pipeline()
        ev = p.process_text(SAMPLES[1]["raw"])
        line = serialize_syslog_json(ev)
        payload = line.split(" ulstp: ", 1)[1]
        doc = json.loads(payload)
        assert doc["raw"]["raw_message"] == SAMPLES[1]["raw"]

    def test_invalid_utf8_bytes_recoverable(self):
        """Invalid UTF-8 must survive collection with byte-exact recovery.
        Exercised through the real transport path (UDP datagram with raw
        non-UTF-8 bytes) — the only path where raw bytes exist."""
        import socket, time
        p = make_pipeline()
        p.start()
        from ulstp.collectors import UdpCollector
        coll = UdpCollector(p.stage, host="127.0.0.1", port=0, limits=p.limits)
        coll.start()
        time.sleep(0.1)
        raw_bytes = b"<134>bad \xff\xfe bytes from device"
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(raw_bytes, ("127.0.0.1", coll.port))
        deadline = time.time() + 5
        while time.time() < deadline and not p.history():
            time.sleep(0.05)
        coll.stop()
        p.stop()
        assert p.history(), "event lost"
        ev = p.history()[0]
        assert ev.raw_bytes_b64 is not None
        assert base64.b64decode(ev.raw_bytes_b64) == raw_bytes  # byte-exact
        assert any("latin-1 lossless" in n for n in ev.decode_notes)


class TestUnknownSource:
    """§51: unknown telemetry must be accepted, preserved, not fabricated."""

    def test_unknown_preserved(self):
        p = make_pipeline()
        ev = p.process_text("weird gadget says beep 42 !!")
        assert ev.parse_status == ParseStatus.UNKNOWN_FORMAT.value
        assert ev.source_status == SourceStatus.UNKNOWN.value
        assert ev.raw_message == "weird gadget says beep 42 !!"
        assert ev.normalized.get("message") == "weird gadget says beep 42 !!"
        assert ev.vendor is None and ev.product is None

    def test_unknown_still_deliverable_shape(self):
        p = make_pipeline()
        ev = p.process_text("weird gadget says beep 42 !!")
        doc = ev.dict_event()
        assert doc["raw"]["raw_message"]
        assert doc["parser"]["status"] == "UNKNOWN_FORMAT"


class TestPartialParse:
    """§52: understood parts extracted, unknown parts preserved."""

    def test_asa_unresearched_msgid(self):
        p = make_pipeline()
        ev = p.process_text("<163>Jan 12 10:22:11 FW01 : %ASA-4-733100: threat level changed")
        assert ev.parse_status == ParseStatus.PARTIAL.value
        assert ev.normalized.get("cisco.message_id") == "733100"  # understood part
        assert ev.normalized.get("message") == "threat level changed"
        assert any("ASA_BODY_NOT_SUBPARSED" in n for n in ev.parse_notes)
        assert ev.raw_message  # raw preserved

    def test_csv_no_schema(self):
        p = make_pipeline()
        ev = p.process_text("v1,v2,v3,v4")
        assert ev.parse_status == ParseStatus.PARTIAL.value
        assert ev.normalized.get("col_1") == "v1"
        assert any("CSV_NO_SCHEMA" in n for n in ev.parse_notes)

    def test_cef_unknown_ext_keys(self):
        p = make_pipeline()
        ev = p.process_text(
            "CEF:0|V|P|1|s|n|5|src=1.2.3.4 brandnewkey=brandnewvalue")
        assert ev.normalized.get("source.ip") == "1.2.3.4"
        assert ev.unknown_fields.get("cef.ext.brandnewkey") == "brandnewvalue"


class TestNoSilentLoss:
    """§53: input exists ⇒ output contains it (or an explicit failure path)."""

    def test_malformed_syslog_corpus(self):
        p = make_pipeline()
        for raw, note in SYSLOG_MALFORMED:
            ev = p.process_text(raw)
            if raw == "":
                assert ev.raw_message == "" and ev.validation_problems, note
                continue
            assert ev.raw_message == raw, note
            doc = ev.dict_event()
            assert doc["raw"]["raw_message"] == raw, note
            assert ev.parse_status, note

    def test_malformed_cef_corpus(self):
        p = make_pipeline()
        for raw, note in CEF_MALFORMED:
            if raw == "":
                continue
            ev = p.process_text(raw)
            assert ev.raw_message == raw, note
            assert ev.parse_status, note

    def test_malformed_json_corpus(self):
        p = make_pipeline()
        for raw, note in JSON_MALFORMED:
            ev = p.process_text(raw)
            assert ev.raw_message == raw, note
            assert ev.parse_status, note

    def test_every_event_has_explicit_status(self):
        p = make_pipeline()
        all_corpus = [c["raw"] for c in SAMPLES] + \
                     [r for r, _ in SYSLOG_MALFORMED] + \
                     [r for r, _ in CEF_MALFORMED] + \
                     [r for r, _ in JSON_MALFORMED]
        for raw in all_corpus:
            ev = p.process_text(raw)
            assert ev.parse_status in (
                ParseStatus.PARSED.value, ParseStatus.PARTIAL.value,
                ParseStatus.FAILED.value, ParseStatus.UNKNOWN_FORMAT.value,
            ), raw[:40]
            assert ev.validation_status in (
                ValidationStatus.VALID.value, ValidationStatus.INVALID.value,
            )


class TestEndToEnd:
    """§54 (local scope): full pipeline with real collector transport."""

    def test_udp_to_event(self):
        import socket, threading, time
        p = make_pipeline()
        p.start()
        coll = None
        from ulstp.collectors import UdpCollector
        coll = UdpCollector(p.stage, host="127.0.0.1", port=0, limits=p.limits)
        coll.start()
        time.sleep(0.1)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        raw = SAMPLES[1]["raw"]
        sock.sendto(raw.encode(), ("127.0.0.1", coll.port))
        deadline = time.time() + 5
        while time.time() < deadline and not p.history():
            time.sleep(0.05)
        coll.stop()
        p.stop()
        assert p.history(), "event did not arrive via UDP"
        ev = p.history()[0]
        assert ev.raw_message == raw
        assert ev.transport == "udp"
        assert ev.peer_ip == "127.0.0.1"
        assert ev.normalized.get("source.ip") == "10.1.2.1"

    def test_tcp_octet_counting_to_event(self):
        import socket, time
        p = make_pipeline()
        p.start()
        from ulstp.collectors import TcpCollector
        coll = TcpCollector(p.stage, host="127.0.0.1", port=0, limits=p.limits)
        coll.start()
        time.sleep(0.1)
        raw = SAMPLES[0]["raw"].encode()
        sock = socket.create_connection(("127.0.0.1", coll.port), timeout=5)
        sock.sendall(str(len(raw)).encode() + b" " + raw)
        time.sleep(0.3)
        sock.close()
        deadline = time.time() + 5
        while time.time() < deadline and not p.history():
            time.sleep(0.05)
        coll.stop()
        p.stop()
        assert p.history(), "event did not arrive via TCP octet counting"
        ev = p.history()[0]
        assert ev.raw_message == SAMPLES[0]["raw"]
        assert ev.transport == "tcp"

    def test_replay_deterministic(self):
        """§35: replay of the same raw telemetry ⇒ same normalized output."""
        p1 = make_pipeline()
        p2 = make_pipeline()
        p2.start()
        raws = [c["raw"] for c in SAMPLES]
        evs1 = [p1.process_text(r) for r in raws]
        p2.replay.replay(raws)
        assert p2.wait_until_drained(10), "replay events not processed"
        time.sleep(0.1)
        evs2 = p2.history()
        assert len(evs1) == len(evs2)
        for a, b in zip(evs1, evs2):
            assert a.normalized == b.normalized
            assert a.parse_status == b.parse_status
            assert a.parser_name == b.parser_name
            assert a.vendor == b.vendor
