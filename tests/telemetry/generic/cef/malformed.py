"""CEF malformed corpus (build plan §26)."""

CORPUS = [
    ("CEF:0|Vendor|Product|1.0|sig|name|5", "NO_EXTENSION"),
    ("CEF:0|Vendor|Product|1.0", "TRUNCATED_HEADER_4_FIELDS"),
    ("CEF:0|Vendor|Product|1.0|sig|name|X|src=1.2.3.4", "SEVERITY_NON_NUMERIC"),
    ("CEF:0|Vendor|Product|1.0|sig|name|5|src=not_an_ip dst=1.2.3.4", "INVALID_IP_VALUE"),
    ("CEF:0|Vendor|Product|1.0|sig|name|5|spt=99999", "PORT_OUT_OF_RANGE"),
    ("CEF:0|Vendor|Product|1.0|sig|name|5|src=1.2.3.4 src=5.6.7.8", "DUPLICATE_KEY"),
    ("CEF:0|Vendor|Product|1.0|sig|name|5|justtext nokey", "UNPAIRED_TOKENS"),
    ("CEF:0|Vendor|Product|1.0|sig|name|5|key_with\\=equals=after value", "ESCAPED_EQUALS"),
    ("CEF:0|Vendor|Product|1.0|sig|name|5|custom|pipe=data", "UNESCAPED_PIPE_IN_EXT"),
    ("", "EMPTY"),
]
