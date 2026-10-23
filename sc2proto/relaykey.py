"""Relay key outside moderation: the signed /.well-known descriptor, the
welcome proof (answer to the hello nonce) and key rotation. Byte layouts
match protocol/sc2/include/sc2_relaykey.h. sign is a callable
bytes -> 64-byte Ed25519 signature; verify(pk, msg, sig) -> bool.

SPDX-License-Identifier: MIT
"""

from .codec import b64e

DESC_LABEL = b"SC2-DESC\x01"
WELC_LABEL = b"SC2-WELC\x01"
ROTK_LABEL = b"SC2-ROTK\x01"
NONCE_LEN = 16
DESC_TEXT_MAX = 1024
FALLBACK_MAX = 3


def _id(relay_id):
    raw = relay_id.encode()
    if not 1 <= len(raw) <= 255:
        raise ValueError("relay id must be 1..255 bytes")
    return bytes([len(raw)]) + raw


def welcome_bytes(relay_id, nonce, challenge):
    if len(nonce) != NONCE_LEN or len(challenge) != 32:
        raise ValueError("nonce 16 bytes, challenge 32 bytes")
    return WELC_LABEL + _id(relay_id) + bytes(nonce) + bytes(challenge)


def rotation_bytes(relay_id, old_key, new_key):
    if len(old_key) != 32 or len(new_key) != 32:
        raise ValueError("keys are 32 bytes")
    return ROTK_LABEL + _id(relay_id) + bytes(old_key) + bytes(new_key)


def descriptor_text(relay_id, key, port, tls, host=None, pin=None, fallbacks=(), ts=None):
    """fallbacks: [(url, key_bytes)], at most FALLBACK_MAX."""
    if len(fallbacks) > FALLBACK_MAX:
        raise ValueError("at most %d fallback relays" % FALLBACK_MAX)
    lines = ["sc2-relay 1", "id " + relay_id, "key " + b64e(key)]
    if host:
        lines.append("host " + host)
    lines += ["port %d" % port, "tls %d" % (1 if tls else 0)]
    if pin:
        lines.append("pin " + pin)
    for url, fkey in fallbacks:
        lines.append("fallback %s %s" % (url, b64e(fkey)))
    if ts is not None:
        lines.append("ts %d" % ts)
    for ln in lines:
        if "\n" in ln or any(ord(c) < 0x20 for c in ln):
            raise ValueError("descriptor values must be single-line text")
    text = ("\n".join(lines) + "\n").encode()
    if len(text) > DESC_TEXT_MAX:
        raise ValueError("descriptor longer than %d bytes" % DESC_TEXT_MAX)
    return text


def sign_descriptor(sign, text):
    return sign(DESC_LABEL + text)


def verify_descriptor(verify, key, text, sig):
    return verify(key, DESC_LABEL + text, sig)


def parse_descriptor(text):
    """Minimal parser (tests, tooling): dict of the known fields."""
    out = {"fallback": []}
    lines = text.decode().split("\n")
    if lines[0] != "sc2-relay 1":
        raise ValueError("not an sc2 relay descriptor")
    for ln in lines[1:]:
        if not ln:
            continue
        k, _, v = ln.partition(" ")
        if k == "fallback":
            url, _, fkey = v.partition(" ")
            out["fallback"].append((url, fkey))
        else:
            out[k] = v
    return out
