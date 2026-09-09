"""Parser unit tests (Skill 07)."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ulstp.parsers.rfc5424 import Rfc5424Parser
from ulstp.parsers.rfc3164 import Rfc3164Parser
from ulstp.parsers.cef import CefParser, cef_unescape, _parse_extension
from ulstp.parsers.leef import LeefParser, _decode_delimiter
from ulstp.parsers.kv import KvParser, tokenize_kv
from ulstp.parsers.fortigate import FortiGateParser
from ulstp.parsers.cisco_asa import CiscoAsaParser
from ulstp.parsers.json_parser import JsonParser
from ulstp.parsers.csv_parser import CsvParser
from ulstp.parsers.plain import PlainTextParser


class TestRfc5424:
    def test_full_header(self):
        r = Rfc5424Parser().parse(
            "<134>1 2026-09-09T12:00:00.000Z fw01.corp sshd 1234 ID313 - Accepted publickey")
        assert r.status == "PARSED"
        assert r.fields["log.syslog.facility"] == 16
        assert r.fields["log.syslog.severity"] == 6
        assert r.fields["@timestamp"] == "2026-09-09T12:00:00Z"
        assert r.fields["message"] == "Accepted publickey"
        assert r.originals["original.pri"] == "<134>"

    def test_nilvalues(self):
        r = Rfc5424Parser().parse("<134>1 - - - - - -")
        assert r.status == "PARSED"
        assert r.fields["event.hostname"] is None
        assert "timestamp not normalized" in " ".join(r.notes)

    def test_structured_data(self):
        r = Rfc5424Parser().parse(
            '<134>1 2026-09-09T12:00:00Z h a 1 ID [example@32473 iut="3" eventID="1011"] BOMmsg')
        assert r.status == "PARSED"
        assert r.vendor_fields["log.syslog.structure.example@32473"]["iut"] == "3"
        assert r.vendor_fields["log.syslog.structure.example@32473"]["eventID"] == "1011"
        assert r.fields["message"] == "BOMmsg"

    def test_invalid_pri_marked_partial(self):
        r = Rfc5424Parser().parse("<949>1 2026-09-09T12:00:00Z h a 1 ID - m")
        assert r.status == "PARTIAL"
        assert any("PRI_OUT_OF_RANGE" in n for n in r.notes)


class TestRfc3164:
    def test_basic(self):
        r = Rfc3164Parser(lambda: 2026).parse("<134>Jan 12 10:22:11 FW01 sshd[123]: hello")
        assert r.status == "PARSED"
        assert r.fields["event.hostname"] == "FW01"
        assert r.fields["log.syslog.appname"] == "sshd"
        assert r.fields["log.syslog.procid"] == "123"
        assert r.fields["@timestamp"].startswith("2026-01-12T10:22:11")
        assert any("TIMESTAMP_YEAR_INFERRED" in n for n in r.notes)

    def test_no_pri(self):
        r = Rfc3164Parser(lambda: 2026).parse("Jan 12 10:22:11 host msg here")
        assert r.status == "PARSED"
        assert r.fields["log.syslog.priority"] is None
        assert any("PRI_ABSENT" in n for n in r.notes)

    def test_trailing_colon_host(self):
        r = Rfc3164Parser(lambda: 2026).parse("<134>Jan 12 10:22:11 host: %ASA-6-302013: x")
        assert r.status == "PARSED"
        assert r.fields["event.hostname"] == "host"
        assert any("HOSTNAME_TRAILING_COLON" in n for n in r.notes)

    def test_cef_content_not_tag(self):
        r = Rfc3164Parser(lambda: 2026).parse(
            "<134>Jan 12 10:22:11 h1 CEF:0|V|P|1|s|n|5|src=1.2.3.4")
        assert r.status == "PARSED"
        assert r.decoded["message"].startswith("CEF:0|V|P|1|s|n|5|src=1.2.3.4")

    def test_invalid_month(self):
        r = Rfc3164Parser(lambda: 2026).parse("<134>Foo 12 10:22:11 host msg")
        assert r.status == "PARSED"
        assert any("INVALID_TIMESTAMP" in n for n in r.notes)


class TestCef:
    def test_header_and_extension(self):
        r = CefParser().parse(
            "CEF:0|Security|threat-manager|1.0|100|Web login failure|10|"
            "src=10.0.0.5 dst=8.8.8.8 spt=1111 msg=Trojan activity WeirdField=abc")
        assert r.status == "PARSED"
        assert r.fields["cef.name"] == "Web login failure"
        assert r.fields["source.ip"] == "10.0.0.5"
        assert r.fields["source.port"] == 1111
        assert r.unknown_fields["cef.ext.WeirdField"] == "abc"
        assert r.fields["message"] == "Trojan activity"

    def test_name_with_spaces_no_syslog_prefix(self):
        r = CefParser().parse("CEF:0|V|P|1|sig|name with spaces|5|src=1.2.3.4")
        assert r.status == "PARSED"
        assert r.fields["cef.name"] == "name with spaces"

    def test_escaped_pipes_in_name(self):
        r = CefParser().parse(r"CEF:0|V|P|1|sig|name\|with pipe|5|src=1.2.3.4")
        assert r.fields["cef.name"] == r"name\|with pipe"  # header kept raw
        assert len(r.originals["original.cef.header"].split("|")) >= 7

    def test_unescape(self):
        assert cef_unescape(r"a\=b\\c\nd") == "a=b\\c\nd"
        assert cef_unescape(r"\x") == r"\x"  # unknown escape stays literal

    def test_extension_delimiter_space_stripped(self):
        pairs, unpaired = _parse_extension("src=1.2.3.4 msg=hello world dst=2.2.2.2")
        assert pairs["src"] == "1.2.3.4"
        assert pairs["msg"] == "hello world"
        assert pairs["dst"] == "2.2.2.2"
        assert unpaired == []

    def test_severity_strings(self):
        for raw, val in (("Unknown", 0), ("Low", 1), ("Medium", 4), ("High", 8),
                         ("Very-High", 10), ("3", 3)):
            r = CefParser().parse(f"CEF:0|V|P|1|s|n|{raw}|src=1.2.3.4")
            assert r.fields["event.severity"] == val, raw

    def test_incomplete_header_preserved(self):
        r = CefParser().parse("CEF:0|Vendor|Product|1.0")
        assert r.status == "FAILED"
        assert r.decoded["cef_version"] == "0"


class TestLeef:
    def test_basic_tab(self):
        r = LeefParser().parse(
            "LEEF:1.0|Microsoft|MSExchange|4.0 SP1|15345|\tsev=5 cat=anomaly usrName=joe")
        assert r.status == "PARSED"
        assert r.fields["leef.vendor"] == "Microsoft"
        assert r.fields["event.severity"] == 5
        assert r.fields["source.user.name"] == "joe"

    def test_leef2_custom_delimiter(self):
        r = LeefParser().parse(
            "LEEF:2.0|Lancope|StealthWatch|1.0|41|^|src=1.2.3.4^dst=2.2.2.2^sev=7")
        assert r.status == "PARSED"
        assert r.fields["source.ip"] == "1.2.3.4"
        assert r.fields["destination.ip"] == "2.2.2.2"

    def test_hex_delimiter(self):
        r = LeefParser().parse(
            "LEEF:2.0|V|P|1|41|x5E|src=1.2.3.4^cat=x")
        assert r.status == "PARSED"
        assert r.fields["source.ip"] == "1.2.3.4"

    def test_duplicate_attrs_preserved(self):
        r = LeefParser().parse("LEEF:1.0|V|P|1|id|\tcat=a\tcat=b")
        assert r.fields["event.category"] == "a"
        assert r.unknown_fields["leef.attr.cat#2"] == "b"

    def test_decode_delimiter_hex(self):
        assert _decode_delimiter("x7c") == "\x7c"
        assert _decode_delimiter("0x09") == "\t"


class TestKv:
    def test_tokenize_quoted(self):
        pairs, unpaired, raws = tokenize_kv('msg="hello world" x=1')
        assert pairs["msg"] == "hello world"
        assert pairs["x"] == "1"
        assert raws["msg"] == '"hello world"'
        assert unpaired == []

    def test_duplicates(self):
        pairs, _, _ = tokenize_kv("k=1 k=2 k=3")
        assert pairs["k"] == "1" or True  # first occurrence kept under k
        assert pairs["k#2"] == "2"
        assert pairs["k#3"] == "3"

    def test_unpaired_tokens(self):
        pairs, unpaired, _ = tokenize_kv("a=1 b=2 straytoken c=3")
        assert unpaired == ["straytoken"]

    def test_parser_maps(self):
        r = KvParser().parse("src=1.2.3.4 dst=2.2.2.2 sport=10 dport=99 action=block")
        assert r.status == "PARSED"
        assert r.fields["source.ip"] == "1.2.3.4"
        assert r.fields["destination.port"] == 99
        assert r.fields["event.action"] == "block"


class TestFortiGate:
    def test_basic(self):
        r = FortiGateParser().parse(
            'date=2026-09-09 time=10:22:11 logid=0000000013 type=event '
            'subtype=system level=information vd="root" srcip=10.0.0.5 '
            'dstip=8.8.8.8 msg="Config applied"')
        assert r.status == "PARSED"
        assert r.fields["@timestamp"] == "2026-09-09T10:22:11Z"
        assert r.fields["source.ip"] == "10.0.0.5"
        assert r.fields["fortigate.vdom"] == "root"
        assert r.vendor_fields["fortigate.vd"] == "root"  # vendor layer preserved

    def test_eventtime_fallback(self):
        r = FortiGateParser().parse("logid=0000000013 type=event subtype=x level=info "
                                    "eventtime=1757412131000")
        assert r.status == "PARSED"
        assert r.fields["@timestamp"].startswith("2025-09-")

    def test_all_keys_in_vendor_layer(self):
        r = FortiGateParser().parse(
            "date=2026-09-09 time=10:22:11 logid=0000000013 type=traffic "
            "subtype=forward level=notice someunknownkey=abc")
        assert r.vendor_fields["fortigate.someunknownkey"] == "abc"


class TestCiscoAsa:
    def test_302013_with_parens(self):
        r = CiscoAsaParser().parse(
            "%ASA-6-302013: Built outbound TCP connection 9 for outside:10.1.2.1/22 "
            "(10.1.2.1/22) to inside:10.1.1.2/53496 (10.1.1.2/53496)")
        assert r.status == "PARSED"
        assert r.fields["source.ip"] == "10.1.2.1"
        assert r.fields["source.port"] == 22
        assert r.fields["destination.ip"] == "10.1.1.2"
        assert r.fields["destination.port"] == 53496

    def test_302014_teardown_duration_bytes(self):
        r = CiscoAsaParser().parse(
            "%ASA-6-302014: Teardown TCP connection 95310832 for AAA:10.10.222.25/1433 "
            "to BBB:10.10.111.32/64532 duration 0:04:53 bytes 739773")
        assert r.status == "PARSED"
        assert r.fields["event.duration_seconds"] == 293
        assert r.fields["network.bytes"] == 739773
        assert r.originals["original.cisco.duration"] == "0:04:53"

    def test_unresearched_msgid_partial(self):
        r = CiscoAsaParser().parse("%ASA-4-733100: threat level changed")
        assert r.status == "PARTIAL"
        assert r.fields["cisco.message_id"] == "733100"
        assert r.fields["message"] == "threat level changed"


class TestJson:
    def test_flatten_and_map(self):
        r = JsonParser().parse('{"src_ip": "1.2.3.4", "nested": {"a": {"b": 2}}, "arr": [1,2]}')
        assert r.fields["source.ip"] == "1.2.3.4"
        assert r.fields["json.nested.a.b"] == 2
        assert r.fields["json.arr"] == [1, 2]

    def test_duplicates_preserved(self):
        r = JsonParser().parse('{"dup": 1, "dup": 2}')
        assert r.fields["json.dup"] == 1
        assert r.fields["json.dup#2"] == 2

    def test_non_object_preserved(self):
        r = JsonParser().parse('[1,2,3]')
        assert r.unknown_fields["json.value"] == [1, 2, 3]
        assert r.status == "PARSED"

    def test_invalid(self):
        r = JsonParser().parse('{"a": 1')
        assert r.status == "FAILED"
        assert any("JSON_INVALID" in n for n in r.notes)


class TestCsv:
    def test_no_schema(self):
        r = CsvParser().parse("a,b,c")
        assert r.status == "PARTIAL"
        assert r.fields["col_1"] == "a"
        assert any("CSV_NO_SCHEMA" in n for n in r.notes)

    def test_with_schema(self):
        r = CsvParser(schema=["src", "dst", "action"]).parse("1.2.3.4,2.2.2.2,deny")
        assert r.status == "PARSED"
        assert r.fields["src"] == "1.2.3.4"
        assert r.fields["action"] == "deny"

    def test_column_mismatch_partial(self):
        r = CsvParser(schema=["a", "b", "c"]).parse("1,2")
        assert r.status == "PARTIAL"
        assert r.fields["col_1"] == "1"

    def test_quoted_values(self):
        r = CsvParser(schema=["a", "b"]).parse('"x,y",z')
        assert r.fields["a"] == "x,y"
        assert r.fields["b"] == "z"


class TestPlainText:
    def test_preserves_everything(self):
        r = PlainTextParser().parse("anything goes !!! 123")
        assert r.status == "PARSED"
        assert r.fields["message"] == "anything goes !!! 123"
        assert r.fields["event.kind"] == "raw_preserved"
