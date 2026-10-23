"""sc2proto: the shared, sans-IO SC2 protocol package.

Frame schemas and validation, SC2-1 binary layouts (AAD headers and signed
bytes), commit sequencing, error codes and retention / cursor logic. It uses
only json, struct and binascii (plus hashlib for SHA-256 when available, see
layouts.set_sha256) so the same code runs on CPython and MicroPython. No
sockets, no asyncio, no clock: callers supply time and I/O.

SPDX-License-Identifier: MIT
"""

from .errors import ERRORS, ProtocolError, error_frame
from .codec import LineBuffer, b64d, b64e, dumpb, dumps, hexd, hexe, is_hex, loads, valid_text
from . import frames, layouts, limits, relaykey, rooms

__all__ = ["ERRORS", "ProtocolError", "error_frame", "LineBuffer", "b64d", "b64e", "dumpb", "dumps", "hexd",
           "hexe", "is_hex", "loads", "valid_text", "frames", "layouts", "limits", "relaykey", "rooms"]

__version__ = "0.4.1"
