"""Framing + decoding tests (Skill 07)."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from ulstp.framing import TcpFramer, frame_datagram, decode_message
from ulstp.errors import FrameError, LimitExceededError
from ulstp.limits import ResourceLimits

LIMITS = ResourceLimits()


def feed_all(framer: TcpFramer, chunks) -> list:
    for c in chunks:
        framer.feed(c)
    out = framer.frames[:]
    framer.frames.clear()
    return out


class TestOctetCounting:
    def test_single_frame(self):
        f = TcpFramer(LIMITS)
        msg = b"<134>1 hello world"
        frames = feed_all(f, [str(len(msg)).encode() + b" " + msg])
        assert frames == [msg]

    def test_fragmented(self):
        f = TcpFramer(LIMITS)
        msg = b"<134>1 fragmented message"
        blob = str(len(msg)).encode() + b" " + msg
        frames = feed_all(f, [blob[:5], blob[5:12], blob[12:]])  # contiguous
        assert frames == [msg]

    def test_multiple_frames_one_chunk(self):
        f = TcpFramer(LIMITS)
        m1, m2 = b"<134>one", b"<134>two two"
        blob = str(len(m1)).encode() + b" " + m1 + str(len(m2)).encode() + b" " + m2
        assert feed_all(f, [blob]) == [m1, m2]

    def test_count_includes_embedded_newlines(self):
        f = TcpFramer(LIMITS)
        msg = b"<134>line1\nline2\nline3"
        frames = feed_all(f, [str(len(msg)).encode() + b" " + msg])
        assert frames == [msg]
        assert b"\n" in frames[0]

    def test_invalid_count_is_frame_error(self):
        f = TcpFramer(LIMITS)
        f.feed(b"0 hello")
        assert f.error and "invalid octet count" in f.error

    def test_oversized_count_is_frame_error(self):
        f = TcpFramer(LIMITS)
        f.feed(b"999999999 x")
        assert f.error and "invalid octet count" in f.error


class TestNewlineFraming:
    def test_basic(self):
        f = TcpFramer(LIMITS)
        assert feed_all(f, [b"<134>one\n<134>two\n"]) == [b"<134>one", b"<134>two"]

    def test_crlf(self):
        f = TcpFramer(LIMITS)
        assert feed_all(f, [b"<134>one\r\n<134>two\r\n"]) == [b"<134>one", b"<134>two"]

    def test_style_locked_after_first(self):
        f = TcpFramer(LIMITS)
        f.feed(b"3 abc\n")
        assert f._style == "octet"
        assert f.frames == [b"abc"]  # octet frame completed by count, not LF
        f.frames.clear()
        # newline in buffer now must NOT produce a frame under octet style
        f.feed(b"\n")
        assert f.frames == []


class TestDecode:
    def test_utf8(self):
        text, b64, notes = decode_message("héllo".encode("utf-8"), LIMITS)
        assert text == "héllo"
        assert b64 is None
        assert notes == []

    def test_invalid_utf8_lossless(self):
        raw = b"<134>bad \xff\xfe bytes"
        text, b64, notes = decode_message(raw, LIMITS)
        assert b64 is not None
        assert any("latin-1 lossless" in n for n in notes)
        import base64
        assert base64.b64decode(b64) == raw  # byte-exact recovery

    def test_datagram_limit(self):
        with pytest.raises(LimitExceededError):
            frame_datagram(b"x" * (LIMITS.max_message_bytes + 1), LIMITS)

    def test_message_limit(self):
        with pytest.raises(LimitExceededError):
            decode_message(b"x" * (LIMITS.max_message_bytes + 1), LIMITS)
