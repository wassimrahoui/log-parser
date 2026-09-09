"""Framing and decoding (build plan §22; Skill 05).

Transport is not format: this layer only determines message boundaries and
decodes bytes to text. It never interprets message content.

- TCP: RFC 6587 auto-detection per connection (octet counting vs newline
  framing), deterministic, never switches styles mid-frame.
- UDP: datagrams are already framed by the OS (helpers provided for limits).
- Decoding: UTF-8 strict; on failure, latin-1 fallback (byte-preserving
  bijective mapping) with a recorded note; raw bytes always retained on the
  event so no information is lost either way (Skill 03).
"""

from __future__ import annotations

from typing import List, Optional, Tuple

from .errors import FrameError, LimitExceededError
from .limits import ResourceLimits


class TcpFramer:
    """Incremental TCP stream framer (RFC 6587).

    Feed raw bytes as they arrive; pull complete frames from ``frames``.
    Framing style is auto-detected from the first frame and then fixed for
    the connection (senders must not mix styles per RFC 6587 §3.4).
    """

    def __init__(self, limits: ResourceLimits) -> None:
        self.limits = limits
        self._buffer = bytearray()
        self._style: Optional[str] = None  # "octet" | "newline", fixed after first frame
        self.frames: List[bytes] = []
        self.error: Optional[str] = None

    def feed(self, data: bytes) -> None:
        if self.error is not None:
            return
        self._buffer.extend(data)
        # Guard: buffer may not exceed max message size by more than the
        # count-prefix headroom; prevents memory exhaustion (Skill 09).
        if len(self._buffer) > self.limits.max_message_bytes + 16:
            self.error = "LIMIT:max_message_bytes exceeded before frame completion"
            return
        try:
            self._extract()
        except FrameError as exc:
            self.error = f"FRAME_ERROR:{exc}"

    def _extract(self) -> None:
        while True:
            if self._style in (None, "octet"):
                frame = self._try_octet_frame()
                if frame is not None:
                    if self._style is None:
                        self._style = "octet"
                    self.frames.append(frame)
                    continue
                if self._style == "octet":
                    return  # partial octet frame, wait for more bytes
            # fall through: newline framing (or undetermined yet)
            frame = self._try_newline_frame()
            if frame is not None:
                if self._style is None:
                    self._style = "newline"
                self.frames.append(frame)
                continue
            return

    def _try_octet_frame(self) -> Optional[bytes]:
        """Return a complete octet-counted frame, or None if not available."""
        # Find ": " separator (ASCII digits then SP per RFC 6587).
        sp_index = self._buffer.find(b" ")
        if sp_index == -1:
            return None
        prefix = bytes(self._buffer[:sp_index])
        if not prefix or not prefix.isdigit() or len(prefix) > 10:
            return None  # not an octet prefix
        total = int(prefix)
        if total <= 0 or total > self.limits.max_message_bytes:
            raise FrameError(f"invalid octet count {total}")
        start = sp_index + 1
        if len(self._buffer) - start < total:
            return None  # wait for the rest of the frame
        frame = bytes(self._buffer[start:start + total])
        del self._buffer[:start + total]
        return frame

    def _try_newline_frame(self) -> Optional[bytes]:
        for i, b in enumerate(self._buffer):
            if b == 0x0A:  # LF
                frame = bytes(self._buffer[:i])
                del self._buffer[:i + 1]
                # strip a single trailing CR (CR-LF tolerance)
                if frame.endswith(b"\r"):
                    frame = frame[:-1]
                return frame
        return None


def frame_datagram(data: bytes, limits: ResourceLimits) -> bytes:
    """Validate a datagram-sized message against the message limit."""
    if len(data) > limits.max_message_bytes:
        raise LimitExceededError(
            f"datagram size {len(data)} exceeds max_message_bytes {limits.max_message_bytes}"
        )
    return data


def decode_message(
    data: bytes, limits: ResourceLimits
) -> Tuple[str, Optional[str], List[str]]:
    """Decode bytes to text without information loss.

    Returns (text, raw_bytes_b64_or_None, notes).
    - UTF-8 strict first.
    - On failure: latin-1 (bijective byte mapping) so every byte survives;
      raw bytes are returned base64-encoded for byte-exact preservation.
    """
    notes: List[str] = []
    if len(data) > limits.max_message_bytes:
        raise LimitExceededError(
            f"message size {len(data)} exceeds max_message_bytes {limits.max_message_bytes}"
        )
    try:
        text = data.decode("utf-8")
        return text, None, notes
    except UnicodeDecodeError:
        text = data.decode("latin-1")
        import base64

        notes.append("DECODE:invalid utf-8; latin-1 lossless byte mapping used")
        return text, base64.b64encode(data).decode("ascii"), notes
