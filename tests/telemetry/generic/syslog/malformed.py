"""Syslog malformed corpus (build plan §26).

Each entry: (raw_message, note).
These are inputs the platform MUST survive without silent loss.
"""

CORPUS = [
    ("<949>1 2026-09-09T12:00:00Z host app 1 2 - out of range pri", "PRI_OUT_OF_RANGE:949>191"),
    ("<134>0 2026-09-09T12:00:00Z host app 1 2 - version zero", "RFC5424_VERSION_ZERO"),
    ("<134>1 2026-13-45T99:99:99Z host app 1 2 - invalid timestamp", "RFC3339_INVALID"),
    ("<134>1 - - - - - -", "ALL_NILVALUES"),
    ("<134>1 2026-09-09T12:00:00Z host app 1 2 [a@1 k=\"v1\" k=\"v2\"] msg", "SD_DUPLICATE_PARAMS"),
    ("<134>1 2026-09-09T12:00:00Z host app 1 2 [unclosed msg", "SD_UNBALANCED"),
    ("<134>1 2026-09-09T12:00:00Z host app 1 2", "MISSING_SD_AND_MSG"),
    ("", "EMPTY_MESSAGE"),
    ("<134>1 2026-09-09T12:00:00Z", "TRUNCATED_HEADER"),
    ("no pri no header at all just text", "NO_HEADER"),
    ("<134>Jan 32 25:61:61 host msg", "RFC3164_INVALID_TIME"),
    ("<134>Foo 12 10:22:11 host msg", "RFC3164_INVALID_MONTH"),
]
