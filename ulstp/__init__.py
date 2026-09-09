"""ULSTP — Universal Lossless SIEM Telemetry Platform.

Deterministic, AI-free telemetry collection, parsing, normalization and SIEM
delivery with lossless preservation of original telemetry.

Pipeline:
    collect -> frame -> decode -> detect format -> identify source ->
    resolve parser -> parse -> extract -> normalize -> preserve (lossless) ->
    validate -> queue -> SIEM adapter
"""

__version__ = "0.1.0"
