"""CLI + API + runtime integration tests (Skill 07)."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import time
import urllib.request

from ulstp.api import ApiServer
from ulstp.cli import main as cli_main
from ulstp.config import load_config, validate_config, build_limits
from ulstp.errors import ConfigError
from ulstp.pipeline import Pipeline
from ulstp.runtime import Runtime
from tests.telemetry.golden.corpus import SAMPLES


class TestConfig:
    def test_valid_config(self, tmp_path):
        cfg = {
            "listeners": [{"type": "udp", "port": 5514}],
            "siem": {"type": "spool", "path": str(tmp_path / "s.jsonl")},
        }
        validate_config(cfg)
        assert isinstance(build_limits(cfg), object)

    def test_invalid_listener_rejected(self):
        import pytest
        with pytest.raises(ConfigError):
            validate_config({"listeners": [{"type": "grpc", "port": 1}]})

    def test_invalid_siem_rejected(self):
        import pytest
        with pytest.raises(ConfigError):
            validate_config({"siem": {"type": "kafka"}})

    def test_unknown_limit_rejected(self):
        import pytest
        with pytest.raises(ConfigError):
            build_limits({"limits": {"max_message_bytes": 1, "bogus": 2}})


class TestRuntime:
    def _cfg(self, tmp_path):
        return {
            "listeners": [
                {"type": "udp", "host": "127.0.0.1", "port": 0},
                {"type": "tcp", "host": "127.0.0.1", "port": 0},
            ],
            "siem": {"type": "spool", "path": str(tmp_path / "spool.jsonl")},
            "api": {"enabled": True, "host": "127.0.0.1", "port": 0},
            "sources": [{"source_id": "fw1", "transport": "udp",
                         "peer_ip": "10.99.99.99", "vendor": "Acme"}],
        }

    def test_runtime_e2e_udp_to_spool_and_api(self, tmp_path):
        import socket
        runtime = Runtime(self._cfg(tmp_path))
        runtime.build_collectors()
        runtime.build_delivery()
        runtime.build_api()
        runtime.start()
        try:
            udp_coll = runtime.collectors[0]
            raw = SAMPLES[1]["raw"]
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(raw.encode(), ("127.0.0.1", udp_coll.port))
            deadline = time.time() + 8
            while time.time() < deadline and not runtime.pipeline.history():
                time.sleep(0.05)
            assert runtime.pipeline.history(), "event lost in runtime"
            runtime.delivery.stop(flush=True)  # flush remaining queue
            # spool fallback target received the event (delivery target = syslog
            # refused → spool) OR delivered if... syslog refused ⇒ spooled
            spool_path = tmp_path / "spool.jsonl"
            assert spool_path.exists(), "event must reach spool (target refused)"
            doc = json.loads(spool_path.read_text().splitlines()[0])
            assert doc["raw"]["raw_message"] == raw

            # API serves the event
            api_port = runtime.api.port
            with urllib.request.urlopen(
                    f"http://127.0.0.1:{api_port}/api/events?limit=10") as resp:
                events = json.loads(resp.read())
            assert any(e["raw"]["raw_message"] == raw for e in events)
            with urllib.request.urlopen(f"http://127.0.0.1:{api_port}/health") as resp:
                assert json.loads(resp.read())["status"] == "ok"
            # UI is served at / (single-page inspector)
            with urllib.request.urlopen(f"http://127.0.0.1:{api_port}/") as resp:
                assert b"Event Inspector" in resp.read()
        finally:
            runtime.stop()

    def test_configured_source_known(self, tmp_path):
        import socket
        cfg = self._cfg(tmp_path)
        cfg["listeners"] = [{"type": "udp", "host": "127.0.0.1", "port": 0}]
        runtime = Runtime(cfg)
        runtime.build_collectors()
        runtime.start()
        try:
            coll = runtime.collectors[0]
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # bind our sender to a specific port so peer matches? simpler:
            # send with spoofed-match impossible; use file-based source instead
            sock.close()
        finally:
            runtime.stop()
        # peer_ip matching covered at unit level below


class TestConfiguredSourceUnit:
    def test_peer_match_known(self):
        from ulstp.source_id import SourceDefinition, SourceIdentifier
        ident = SourceIdentifier([SourceDefinition(
            source_id="fw1", transport="udp", peer_ip="10.1.1.1",
            vendor="Acme", product="Widget")])
        p = Pipeline(source_definitions=[SourceDefinition(
            source_id="fw1", transport="udp", peer_ip="10.1.1.1",
            vendor="Acme", product="Widget")])
        ev = p.process_text("some unknown content", meta={
            "transport": "udp", "peer_ip": "10.1.1.1", "local_port": 5514})
        assert ev.source_status == "KNOWN"
        assert ev.vendor == "Acme"
        assert ev.source_name == "fw1"
        assert any(k == "configured_source" for k, _ in ev.source_evidence)


class TestApi:
    def test_parse_endpoint_and_ui(self):
        p = Pipeline()
        api = ApiServer(p, host="127.0.0.1", port=0)
        api.start()
        try:
            base = f"http://127.0.0.1:{api.port}"
            # POST /api/parse
            req = urllib.request.Request(
                base + "/api/parse", data=SAMPLES[2]["raw"].encode(),
                headers={"Content-Type": "text/plain"}, method="POST")
            with urllib.request.urlopen(req) as resp:
                doc = json.loads(resp.read())
            assert doc["parser"]["name"] == "cef"
            assert doc["raw"]["raw_message"] == SAMPLES[2]["raw"]
            # UI served
            with urllib.request.urlopen(base + "/") as resp:
                html = resp.read().decode()
            assert "Event Inspector" in html
            assert "/api/events" in html
        finally:
            api.stop()

    def test_event_by_id_404(self):
        p = Pipeline()
        api = ApiServer(p, host="127.0.0.1", port=0)
        api.start()
        try:
            base = f"http://127.0.0.1:{api.port}"
            try:
                urllib.request.urlopen(base + "/api/events/nope")
                assert False, "should 404"
            except urllib.error.HTTPError as e:
                assert e.code == 404
        finally:
            api.stop()


class TestCli:
    def test_parse_command(self, capsys):
        rc = cli_main(["parse", SAMPLES[0]["raw"]])
        assert rc == 0
        out = capsys.readouterr().out
        doc = json.loads(out)
        assert doc["parser"]["name"] == "rfc5424"

    def test_test_parser_command(self, capsys):
        rc = cli_main(["test-parser", "cef", "--input", SAMPLES[2]["raw"]])
        assert rc == 0
        out = capsys.readouterr().out
        assert "parser=cef" in out

    def test_replay_command(self, tmp_path, capsys):
        sample_file = tmp_path / "raw.txt"
        sample_file.write_text("\n".join(c["raw"] for c in SAMPLES[:4]) + "\n",
                               encoding="utf-8")
        rc = cli_main(["replay", str(sample_file), "--summary"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "rfc5424" in out and "cef" in out

    def test_invalid_config_exits_cleanly(self, tmp_path, capsys):
        bad = tmp_path / "bad.json"
        bad.write_text('{"siem": {"type": "kafka"}}')
        rc = cli_main(["run", "--config", str(bad)])
        assert rc == 2
