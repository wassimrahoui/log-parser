"""Error taxonomy (build plan §37) and internal exception types.

Every major subsystem has an explicit error state. Errors are observable:
they are recorded on events / metrics, never silently swallowed, and never
cause telemetry disappearance (Skill 03).
"""


class ErrorCode:
    COLLECTOR_ERROR = "COLLECTOR_ERROR"
    FRAME_ERROR = "FRAME_ERROR"
    DECODE_ERROR = "DECODE_ERROR"
    FORMAT_UNKNOWN = "FORMAT_UNKNOWN"
    SOURCE_UNKNOWN = "SOURCE_UNKNOWN"
    PARSER_NOT_FOUND = "PARSER_NOT_FOUND"
    PARTIAL_PARSE = "PARTIAL_PARSE"
    PARSE_ERROR = "PARSE_ERROR"
    NORMALIZATION_ERROR = "NORMALIZATION_ERROR"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    QUEUE_ERROR = "QUEUE_ERROR"
    SIEM_DELIVERY_ERROR = "SIEM_DELIVERY_ERROR"
    CONFIG_ERROR = "CONFIG_ERROR"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"


class UlstpError(Exception):
    """Base class for all platform errors."""

    code = "ULSTP_ERROR"


class CollectorError(UlstpError):
    code = ErrorCode.COLLECTOR_ERROR


class FrameError(UlstpError):
    code = ErrorCode.FRAME_ERROR


class DecodeError(UlstpError):
    code = ErrorCode.DECODE_ERROR


class ParserNotFoundError(UlstpError):
    code = ErrorCode.PARSER_NOT_FOUND


class ParseError(UlstpError):
    code = ErrorCode.PARSE_ERROR


class NormalizationError(UlstpError):
    code = ErrorCode.NORMALIZATION_ERROR


class ValidationError(UlstpError):
    code = ErrorCode.VALIDATION_ERROR


class QueueError(UlstpError):
    code = ErrorCode.QUEUE_ERROR


class DeliveryError(UlstpError):
    code = ErrorCode.SIEM_DELIVERY_ERROR


class ConfigError(UlstpError):
    code = ErrorCode.CONFIG_ERROR


class LimitExceededError(UlstpError):
    code = ErrorCode.LIMIT_EXCEEDED
