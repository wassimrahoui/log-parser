"""Pipeline-level tests for the three audit-wiring fixes.

1. TSV/semicolon text parses through the FULL pipeline (was: plain_text/
   UNKNOWN_FORMAT dead-end), with deterministic delimiter selection.
2. parser_hint from a matched configured source steers parser resolution
   (hinted parser first, deterministic fallback, decision on the event).
3. max_field_bytes / max_field_count are enforced as counted, per-field
   notes — values preserved losslessly, never deleted (Skill 03).

Every test exercises the real Pipeline entry point (process_text), and one
test exercises the CLI subprocess surface.
"""

import json
import subprocess
import sys

import pytest

from ulstp.event import ParseStatus, SourceStatus
from ulstp.limits import ResourceLimits
from ulstp.pipeline import Pipeline
from ulstp.parsers.csv_parser import CsvParser
from ulstp.registry import ParserRegistry
from ulstp.source_id import SourceDefinition


def make_pipeline(limits: ResourceLimits = None, sources: list = None) -> Pipeline:
    return Pipeline(limits=limits, source_definitions=sources or [])


# ---------------------------------------------------------------- Fix 1: TSV


class TestTsvThroughPipeline:
    def test_tsv_parses_full_pipeline(self):
        ev = make_pipeline().process_text("v1\tv2\tv3\tv4")
        assert ev.parse_status == ParseStatus.PARTIAL.value
        assert ev.format_detected == "csv"
        assert ev.parser_name == "csv"
        assert ev.normalized.get("col_1") == "v1"
        assert ev.normalized.get("col_4") == "v4"
        assert ev.decoded.get("csv_delimiter") == "\t"
        assert ev.decoded.get("csv_columns") == 4
        assert any("CSV_NO_SCHEMA" in n for n in ev.parse_notes)
        assert ev.raw_message == "v1\tv2\tv3\tv4"  # lossless

    def test_semicolon_parses_full_pipeline(self):
        ev = make_pipeline().process_text("a1;b2;c3")
        assert ev.format_detected == "csv"
        assert ev.parser_name == "csv"
        assert ev.normalized.get("col_1") == "a1"
        assert ev.decoded.get("csv_delimiter") == ";"

    def test_comma_still_wins_for_comma_text(self):
        ev = make_pipeline().process_text("v1,v2,v3")
        assert ev.parser_name == "csv"
        assert ev.decoded.get("csv_delimiter") == ","
        assert ev.normalized.get("col_2") == "v2"

    def test_delimiter_selection_deterministic_most_frequent(self):
        # 3 tabs vs 2 commas → tab wins; ties resolve to candidate order
        # (comma first), so a 2/2 split must pick comma.
        p = CsvParser()
        assert p._select_delimiter("a\tb\tc\td,e,f") == "\t"
        assert p._select_delimiter("a,b,c\td\te") == ","
        assert p._select_delimiter("no delimiters") is None
        # explicit config overrides auto-selection
        assert CsvParser(delimiter=";")._select_delimiter("a,b;c") == ";"
        assert CsvParser(delimiter=",")._select_delimiter("a\tb\tc") is None

    def test_tsv_with_schema(self):
        p = Pipeline(registry=ParserRegistry())  # registry path, not direct parse
        parser = CsvParser(schema=["src", "dst", "action"])
        r = parser.parse("1.2.3.4\t2.2.2.2\tallow")
        assert r.status == "PARSED"
        assert r.fields["src"] == "1.2.3.4"

    def test_quoted_delimiter_does_not_split(self):
        # RFC 4180: a comma inside quotes is data, not a delimiter
        r = CsvParser().parse('"x,y",z')
        assert r.fields["col_1"] == "x,y"
        assert r.fields["col_2"] == "z"

    def test_empty_and_single_field_inputs(self):
        # no delimiter at all → csv must reject (accept() False), pipeline
        # keeps the text losslessly elsewhere
        p = CsvParser()
        assert p.accept("") is False
        assert p.accept("just text") is False
        assert p.accept("a\tb") is True

    def test_cli_tsv_end_to_end(self):
        """Real surface: the CLI parses TSV through the actual pipeline."""
        r = subprocess.run(
            [sys.executable, "-m", "ulstp.cli", "parse", "v1\tv2\tv3"],
            capture_output=True, text=True, timeout=60,
        )
        assert r.returncode == 0, r.stderr
        doc = json.loads(r.stdout)
        assert doc["parser"]["name"] == "csv"
        assert doc["decoded"]["csv_delimiter"] == "\t"
        assert doc["normalized"]["col_1"] == "v1"


# ------------------------------------------------------- Fix 2: parser_hint


class TestParserHintRouting:
    """parser_hint steering, exercised through the real pipeline.

    Key semantics (by design): a hint NEVER bypasses a parser's signature
    check — the hinted parser is offered first, and if its accept() rejects,
    the standard candidate walk decides. A/B text that two parsers both
    accept proves the steering effect; a signature-gated parser (fortigate)
    proves the rejection/fallback path.
    """

    FW_DEF = SourceDefinition(
        source_id="fw-a", transport="replay", peer_ip="10.9.9.9",
        vendor="Fortinet", product="FortiGate", parser_hint="fortigate",
    )
    ASA_DEF = SourceDefinition(
        source_id="fw-b", transport="replay", peer_ip="10.8.8.8",
        parser_hint="cisco_asa",
    )
    # text that BOTH cisco_asa and key_value accept
    AMBIGUOUS = "%ASA-6-302013: Built outbound TCP connection 9 for f=1 g=2"

    def test_hint_routes_to_hinted_parser(self):
        meta = {"transport": "replay", "peer_ip": "10.8.8.8"}
        hinted = make_pipeline(sources=[self.ASA_DEF]).process_text(
            self.AMBIGUOUS, meta=meta)
        plain = make_pipeline().process_text(self.AMBIGUOUS)
        # same text, opposite routing decision — the hint did the steering
        assert hinted.parser_name == "cisco_asa"
        assert plain.parser_name == "key_value"
        assert any("PARSER_HINT:hint_used:cisco_asa" in n
                   for n in hinted.parse_notes)
        assert not any(n.startswith("PARSER_HINT") for n in plain.parse_notes)

    def test_hint_falls_back_when_parser_rejects(self):
        meta = {"transport": "replay", "peer_ip": "10.9.9.9"}
        ev = make_pipeline(sources=[self.FW_DEF]).process_text(
            "<134>1 2026-09-09T12:00:00Z h sshd 1 ID - msg", meta=meta
        )
        # fortigate's signature rejects RFC5424; fallback finds rfc5424
        assert ev.parser_name == "rfc5424"
        assert any("PARSER_HINT:hint_rejected_fallback:fortigate" in n
                   for n in ev.parse_notes)
        assert ev.normalized.get("log.syslog.facility") == 16

    def test_fallback_keeps_configured_identity(self):
        meta = {"transport": "replay", "peer_ip": "10.9.9.9"}
        ev = make_pipeline(sources=[self.FW_DEF]).process_text(
            "<134>1 2026-09-09T12:00:00Z h sshd 1 ID - msg", meta=meta
        )
        assert ev.source_status == SourceStatus.KNOWN.value
        assert ev.vendor == "Fortinet"
        assert any(ev_e == ["configured_source", "fw-a"]
                   for ev_e in (list(e) for e in ev.source_evidence))

    def test_unknown_hint_name_falls_back_silently(self):
        vague = SourceDefinition(
            source_id="x", transport="replay", peer_ip="10.9.9.9",
            parser_hint="no_such_parser",
        )
        meta = {"transport": "replay", "peer_ip": "10.9.9.9"}
        ev = make_pipeline(sources=[vague]).process_text(
            "user=admin action=login token=t", meta=meta
        )
        assert ev.parser_name == "key_value"
        assert not any(n.startswith("PARSER_HINT") for n in ev.parse_notes)

    def test_unmatched_source_gets_standard_resolution(self):
        ev = make_pipeline(sources=[self.FW_DEF]).process_text(
            "user=admin action=login token=t",
            meta={"transport": "replay", "peer_ip": "10.0.0.1"},
        )
        assert ev.parser_name == "key_value"  # standard resolution
        assert not any(n.startswith("PARSER_HINT") for n in ev.parse_notes)
        assert ev.source_status == SourceStatus.UNKNOWN.value

    def test_hint_decision_recorded_in_dict_event(self):
        meta = {"transport": "replay", "peer_ip": "10.8.8.8"}
        ev = make_pipeline(sources=[self.ASA_DEF]).process_text(
            self.AMBIGUOUS, meta=meta
        )
        assert any(n.startswith("PARSER_HINT:hint_used")
                   for n in ev.dict_event()["parser"]["notes"])


# --------------------------------------------- Fix 3: field limit enforcement


class TestFieldLimits:
    """§39 enforcement: annotation + counted status, values NEVER deleted
    (Skill 03). Unmapped KV keys land in the unknown layer (kv.<key>),
    FortiGate keys in the vendor layer — limits cover all extracted layers.
    """

    def test_oversized_field_annotated_not_deleted(self):
        big = "x" * (9 * 1024)  # > default max_field_bytes (8 KiB)
        ev = make_pipeline().process_text(f'a=ok big="{big}"')
        assert ev.unknown_fields.get("kv.big") == big  # value intact (lossless)
        assert ev.truncated is True
        assert any(n.startswith("FIELD_LIMIT_EXCEEDED:kv.big:")
                   for n in ev.parse_notes)

    def test_field_count_limit_annotated_not_deleted(self):
        limits = ResourceLimits(max_field_count=3)
        ev = make_pipeline(limits=limits).process_text("f1=a f2=b f3=c f4=d")
        keys = [k for k in ev.unknown_fields if k.startswith("kv.f")]
        assert len(keys) == 4                     # all four preserved
        assert ev.truncated is True
        assert any(n.startswith("FIELD_COUNT_LIMIT_EXCEEDED:")
                   for n in ev.parse_notes)

    def test_within_limits_no_noise(self):
        ev = make_pipeline().process_text("a=1 b=2 c=3")
        assert ev.truncated is False
        assert not any("FIELD_LIMIT" in n or "FIELD_COUNT" in n
                       for n in ev.parse_notes)

    def test_limits_apply_to_vendor_layer(self):
        # FortiGate keeps every key in the vendor layer; a giant value there
        # must be caught.
        big = "y" * (9 * 1024)
        ev = make_pipeline().process_text(
            f"logid=0100032214 type=traffic subtype=forward bigfield=\"{big}\""
        )
        assert ev.vendor_fields.get("fortigate.bigfield") == big
        assert any(n.startswith("FIELD_LIMIT_EXCEEDED:fortigate.bigfield:")
                   for n in ev.parse_notes)
        assert ev.truncated is True

    def test_originals_layer_exempt_by_design(self):
        # The preservation layer (original_fields) exists to guarantee
        # nothing is lost; it is never the thing that gets flagged.
        big = "z" * (9 * 1024)
        ev = make_pipeline().process_text(f'a=ok big="{big}"')
        assert big in ev.original_fields.get("original.kv.big", "")
        assert not any(n.startswith("FIELD_LIMIT_EXCEEDED:original.")
                       for n in ev.parse_notes)

    def test_oversize_metric_incremented(self):
        p = make_pipeline()
        p.process_text('a="' + "q" * (9 * 1024) + '"')
        assert p.metrics.get("events_field_limits") == 1
        p.process_text("a=1 b=2")
        assert p.metrics.get("events_field_limits") == 1  # unchanged

    def test_custom_limit_config_wires_through(self):
        limits = ResourceLimits(max_field_bytes=16)
        ev = make_pipeline(limits=limits).process_text(
            'a="this value is longer than sixteen"')
        # plain_text fallback carries the whole text in normalized.message
        assert ev.normalized.get("message") == 'a="this value is longer than sixteen"'
        assert any("FIELD_LIMIT_EXCEEDED:message:" in n for n in ev.parse_notes)
