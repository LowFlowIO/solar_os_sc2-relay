"""Byte and text codecs shared by every SC2 component.

Strict standard base64 and lowercase hex, compact JSON, and a line buffer
that splits a byte stream into NDJSON frames with a hard length cap.
Only json, struct and binascii are used, so the module runs on CPython and
MicroPython alike.

SPDX-License-Identifier: MIT
"""

import binascii
import json

from .errors import ProtocolError

_B64_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_HEX = "0123456789abcdef"


def b64e(data):
    """Standard base64 with padding and without a trailing newline."""
    out = binascii.b2a_base64(bytes(data))
    if out[-1:] == b"\n":
        out = out[:-1]
    return out.decode()


def b64d(text, length=None, field="b64"):
    """Decode canonical standard base64 (padding required, no whitespace,
    zero trailing bits). With length set, the decoded size must match."""
    if not isinstance(text, str):
        raise ProtocolError(400, "bad_request", field + " must be base64 text")
    try:
        raw = text.encode()
    except UnicodeError:
        raise ProtocolError(400, "bad_request", field + " must be base64 text")
    if len(raw) % 4 != 0:
        raise ProtocolError(400, "bad_request", field + " is not canonical base64")
    pad = 0
    for i, c in enumerate(raw):
        if c == 61:  # '='
            pad += 1
            if i < len(raw) - 2:
                raise ProtocolError(400, "bad_request", field + " is not canonical base64")
        elif pad or c not in _B64_ALPHABET:
            raise ProtocolError(400, "bad_request", field + " is not canonical base64")
    if pad > 2:
        raise ProtocolError(400, "bad_request", field + " is not canonical base64")
    try:
        data = binascii.a2b_base64(raw)
    except (ValueError, binascii.Error):
        raise ProtocolError(400, "bad_request", field + " is not canonical base64")
    if b64e(data) != text:
        raise ProtocolError(400, "bad_request", field + " is not canonical base64")
    if length is not None and len(data) != length:
        raise ProtocolError(400, "bad_request", field + " has the wrong length")
    return data


def hexe(data):
    return binascii.hexlify(bytes(data)).decode()


def is_hex(text, chars):
    if not isinstance(text, str) or len(text) != chars:
        return False
    for c in text:
        if c not in _HEX:
            return False
    return True


def hexd(text, nbytes, field="hex"):
    """Decode lowercase hex of exactly nbytes bytes."""
    if not is_hex(text, 2 * nbytes):
        raise ProtocolError(400, "bad_request", field + " must be " + str(2 * nbytes) + " lowercase hex characters")
    return binascii.unhexlify(text)


def dumps(obj):
    """Compact JSON, UTF-8 kept as is (same output as the C core)."""
    try:
        return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
    except TypeError:  # MicroPython: no keyword support
        return json.dumps(obj)


def dumpb(obj):
    """One NDJSON line as bytes, newline included."""
    return (dumps(obj) + "\n").encode()


def loads(line):
    """Parse one line into a JSON object. Raises ProtocolError(400)."""
    if isinstance(line, (bytes, bytearray)):
        try:
            line = bytes(line).decode()
        except UnicodeError:
            raise ProtocolError(400, "bad_request", "line is not UTF-8")
    try:
        obj = json.loads(line)
    except ValueError:
        raise ProtocolError(400, "bad_request", "malformed JSON")
    if not isinstance(obj, dict):
        raise ProtocolError(400, "bad_request", "frame must be a JSON object")
    if not valid_text(obj):
        raise ProtocolError(400, "bad_request", "lone surrogate escape in JSON string")
    return obj


def valid_text(obj, depth=0):
    """True if every string (keys included) in a decoded JSON value is valid
    Unicode. JSON allows "\\ud800" escapes that decode to lone surrogates,
    which cannot be re-encoded as UTF-8; frames carrying them are rejected."""
    if depth > 64:
        return False
    if isinstance(obj, str):
        try:
            obj.encode("utf-8")
        except UnicodeError:
            return False
        return True
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not valid_text(k, depth + 1) or not valid_text(v, depth + 1):
                return False
        return True
    if isinstance(obj, list):
        for v in obj:
            if not valid_text(v, depth + 1):
                return False
    return True


class LineBuffer:
    """Accumulates bytes and yields complete lines (without the newline).

    A line longer than max_line raises ProtocolError(413) and the buffer is
    left unusable: the caller should answer and close. "\\r\\n" is accepted.
    Empty lines are skipped.
    """

    def __init__(self, max_line):
        self.max_line = max_line
        self._buf = b""
        self.overflow = False

    def feed(self, data):
        if self.overflow:
            raise ProtocolError(413, "too_large", "line too long")
        self._buf += bytes(data)
        lines = []
        while True:
            i = self._buf.find(b"\n")
            if i < 0:
                break
            line = self._buf[:i]
            self._buf = self._buf[i + 1:]
            if line[-1:] == b"\r":
                line = line[:-1]
            if len(line) > self.max_line:
                self.overflow = True
                raise ProtocolError(413, "too_large", "line too long")
            if line:
                lines.append(line)
        if len(self._buf) > self.max_line:
            self.overflow = True
            raise ProtocolError(413, "too_large", "line too long")
        return lines

    def pending(self):
        return len(self._buf)
