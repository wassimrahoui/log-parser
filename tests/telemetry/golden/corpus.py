"""Golden corpus (build plan §49).

Each case: raw input → expected source/format/parser/normalized fields.
Compared COMPLETELY (per §49) against the real pipeline output.
"""

SAMPLES = [
    {
        "name": "rfc5424_sshd",
        "raw": "<134>1 2026-09-09T12:00:00.000Z fw01.corp sshd 1234 ID313 - "
               "Accepted publickey for admin from 10.0.0.5 port 51234 ssh2",
        "expect": {
            "source_status": "UNKNOWN",
            "format": "rfc5424",
            "parser": "rfc5424",
            "fields": {
                "@timestamp": "2026-09-09T12:00:00Z",
                "log.syslog.facility": 16,
                "log.syslog.severity": 6,
                "log.syslog.priority": 134,
                "log.syslog.appname": "sshd",
                "log.syslog.procid": "1234",
                "log.syslog.msgid": "ID313",
                "event.hostname": "fw01.corp",
            },
            "originals_present": ["original.hostname", "original.pri", "original.timestamp"],
            "raw_preserved": True,
        },
    },
    {
        "name": "cisco_asa_302013",
        "raw": "<163>Jan 12 10:22:11 FW01 : %ASA-6-302013: Built outbound TCP "
               "connection 9 for outside:10.1.2.1/22 (10.1.2.1/22) to "
               "inside:10.1.1.2/53496 (10.1.1.2/53496)",
        "expect": {
            "source_status": "INFERRED",
            "vendor": "Cisco",
            "format": "rfc3164",  # wire format; inner parse visible as parser chain
            "parser": "rfc3164+cisco_asa",
            "fields": {
                "source.ip": "10.1.2.1", "destination.ip": "10.1.1.2",
                "source.port": 22, "destination.port": 53496,
                "network.transport": "tcp", "cisco.message_id": "302013",
                "event.severity": 6,
            },
            "originals_present": ["original.pri", "original.timestamp",
                                  "original.cisco.first_tuple",
                                  "original.cisco.second_tuple"],
            "raw_preserved": True,
        },
    },
    {
        "name": "cef_full",
        "raw": "CEF:0|Security|threat-manager|1.0|100|Web login failure|10|"
               "src=10.0.0.5 dst=8.8.8.8 spt=1111 msg=Trojan activity WeirdField=abc",
        "expect": {
            "source_status": "INFERRED",
            "vendor": "Security",
            "format": "cef",
            "parser": "cef",
            "fields": {
                "cef.version": "0",
                "cef.device_vendor": "Security",
                "cef.device_product": "threat-manager",
                "cef.device_version": "1.0",
                "cef.device_event_class_id": "100",
                "cef.name": "Web login failure",
                "cef.severity": "10",
                "event.severity": 10,
                "source.ip": "10.0.0.5",
                "destination.ip": "8.8.8.8",
                "source.port": 1111,
            },
            "unknown_present": ["cef.ext.WeirdField"],
            "originals_present": ["original.cef.header", "original.cef.src"],
            "raw_preserved": True,
        },
    },
    {
        "name": "leef_basic",
        "raw": "LEEF:1.0|Microsoft|MSExchange|4.0 SP1|15345|\tsev=5 cat=anomaly "
               "srcPort=81 usrName=joe.black",
        "expect": {
            "source_status": "INEFRED_PLACEHOLDER",  # replaced below
            "vendor": "Microsoft",
            "format": "leef",
            "parser": "leef",
            "fields": {
                "leef.version": "1.0", "leef.vendor": "Microsoft",
                "leef.product": "MSExchange", "leef.product_version": "4.0 SP1",
                "leef.event_id": "15345",
                "event.severity": 5, "event.category": "anomaly",
                "source.port": 81, "source.user.name": "joe.black",
            },
            "originals_present": ["original.leef.header", "original.leef.srcPort"],
            "raw_preserved": True,
        },
    },
    {
        "name": "fortigate_kv",
        "raw": 'date=2026-09-09 time=10:22:11 logid=0000000013 type=event '
               'subtype=system level=information vd="root" srcip=10.0.0.5 '
               'dstip=8.8.8.8 msg="Config applied"',
        "expect": {
            "source_status": "INFERRED",
            "vendor": "Fortinet",
            "format": "key_value",
            "parser": "fortigate",
            "fields": {
                "source.ip": "10.0.0.5", "destination.ip": "8.8.8.8",
                "log.level": "information", "message": "Config applied",
                "fortigate.logid": "0000000013", "fortigate.type": "event",
                "fortigate.subtype": "system", "fortigate.vdom": "root",
            },
            "originals_present": ["original.fortigate.srcip", "original.fortigate.msg"],
            "raw_preserved": True,
        },
    },
    {
        "name": "json_generic",
        "raw": '{"timestamp": "2026-09-09T10:00:00Z", "src_ip": "10.1.1.1", '
               '"dst_port": 443, "action": "allow", "nested": {"a": 1}, '
               '"dup": 1, "dup": 2}',
        "expect": {
            "source_status": "UNKNOWN",
            "format": "json",
            "parser": "json",
            "fields": {
                "@timestamp": "2026-09-09T10:00:00Z",
                "source.ip": "10.1.1.1",
                "destination.port": 443,
                "event.action": "allow",
                "json.nested.a": 1,
                "json.dup": 1,
                "json.dup#2": 2,
            },
            "originals_present": ["original.json.src_ip", "original.json.dup#2"],
            "raw_preserved": True,
        },
    },
    {
        "name": "kv_generic",
        "raw": "src=192.168.1.10 dst=10.0.0.1 sport=1234 dport=514 user=alice "
               "action=deny proto=udp",
        "expect": {
            "source_status": "UNKNOWN",
            "format": "key_value",
            "parser": "key_value",
            "fields": {
                "source.ip": "192.168.1.10", "destination.ip": "10.0.0.1",
                "source.port": 1234, "destination.port": 514,
                "source.user.name": "alice", "event.action": "deny",
                "network.transport": "udp",
            },
            "originals_present": ["original.kv.src", "original.kv.action"],
            "raw_preserved": True,
        },
    },
    {
        "name": "unknown_source",
        "raw": "totally unknown telemetry content 12345 !!!",
        "expect": {
            "source_status": "UNKNOWN",
            "format": "unknown",
            "parser": "plain_text",
            "parse_status": "UNKNOWN_FORMAT",
            "fields": {"message": "totally unknown telemetry content 12345 !!!"},
            "originals_present": ["original.message"],
            "raw_preserved": True,
        },
    },
]

# fix the LEEF expected source status (deterministic inference via header)
for s in SAMPLES:
    if s["name"] == "leef_basic":
        s["expect"]["source_status"] = "INFERRED"
