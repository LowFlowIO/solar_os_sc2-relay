"""SC2-1 binary layouts: signed bytes, AAD headers and hashes.

These are the byte strings that get signed or authenticated. They are built
with struct, never from JSON, so no canonicalisation is needed (draft §6).
All integers are big-endian; variable-length fields carry a length prefix.

Layouts taken verbatim from the draft: auth, dk, spk, room header (H), room
signature, DM header (Hd), public post.

Layouts defined in Phase 4 (the draft names the frames but leaves the
encoding open; the C core does not implement them yet):
- commit:  "SC2-COMMIT\\x01" | suite:u8 | room:16 | prev:u32 | epoch:u32 |
           by:16 | n:u8 add[16]* | n:u8 remove[16]* | flag:u8 [n:u8 admins[16]*] |
           members_hash:32
- mod:     "SC2-MOD\\x01" | suite:u8 | len:u8 relay_id | len:u8 room | action:u8 |
           ref:8 | device:16 | until:u64 | seq:u64 | ts:u64
- invite:  invite_key = HMAC(invite_secret, "SC2-INVITE\\x01" | room:16)
           proof      = HMAC(invite_key, "SC2-JOIN\\x01" | joiner:16)

SHA-256 comes from hashlib when present (CPython and most MicroPython
ports). Callers on a port without it pass their own with set_sha256().

SPDX-License-Identifier: MIT
"""

import struct

from .errors import ProtocolError

SUITE = 1
NO_OPK = 0xFFFFFFFF

L_DK = b"SC2-DK\x01"
L_SPK = b"SC2-SPK\x01"
L_AUTH = b"SC2-AUTH\x01"
L_ROOM = b"SC2-ROOM\x01"
L_PUB = b"SC2-PUB\x01"
L_COMMIT = b"SC2-COMMIT\x01"
L_MOD = b"SC2-MOD\x01"
L_INVITE = b"SC2-INVITE\x01"
L_JOIN = b"SC2-JOIN\x01"

POST_TYPES = {"text": 1, "del": 2}
MOD_ACTIONS = {"remove": 1, "ban": 2}

try:
    import hashlib as _hashlib

    def _sha256_default(data):
        return _hashlib.sha256(bytes(data)).digest()
except ImportError:  # pragma: no cover - port without hashlib
    _sha256_default = None

_sha256 = _sha256_default


def set_sha256(fn):
    """Install the SHA-256 function (bytes -> 32 bytes) used by this module."""
    global _sha256
    _sha256 = fn


def sha256(data):
    if _sha256 is None:
        raise RuntimeError("sc2proto: no SHA-256 available, call set_sha256()")
    return _sha256(data)


def hmac_sha256(key, msg):
    """RFC 2104 HMAC-SHA-256 built on sha256() (no hmac module needed)."""
    key = bytes(key)
    if len(key) > 64:
        key = sha256(key)
    key = key + bytes(64 - len(key))
    ipad = bytes([b ^ 0x36 for b in key])
    opad = bytes([b ^ 0x5C for b in key])
    return sha256(opad + sha256(ipad + bytes(msg)))


def device_id(ik_pub):
    """Raw 16-byte device ID: SHA-256(IK)[0:16]."""
    return sha256(ik_pub)[:16]


def ct_equal(a, b):
    if len(a) != len(b):
        return False
    r = 0
    for x, y in zip(a, b):
        r |= x ^ y
    return r == 0


def _lp8(data, field):
    if len(data) > 255:
        raise ProtocolError(400, "bad_request", field + " too long")
    return bytes([len(data)]) + data


def auth_bytes(relay_id, challenge, ik_pub):
    return L_AUTH + _lp8(relay_id.encode(), "relay id") + bytes(challenge) + bytes(ik_pub)


def dk_signed(dk_pub):
    return L_DK + bytes(dk_pub)


def spk_signed(spk_id, spk_pub):
    return L_SPK + struct.pack(">I", spk_id) + bytes(spk_pub)


def room_header(room, epoch, frm, n, suite=SUITE):
    """H = "SC2R" | suite | room:16 | epoch:u32 | from:16 | n:u32 (45 bytes)."""
    return b"SC2R" + bytes([suite]) + bytes(room) + struct.pack(">I", epoch) + bytes(frm) + struct.pack(">I", n)


def room_signed(header, nonce, ct):
    return L_ROOM + bytes(header) + bytes(nonce) + bytes(ct)


def dm_header(frm, to, rk, pn, n, x3dh=None, suite=SUITE):
    """Hd = "SC2D" | suite | from:16 | to:16 | rk:32 | pn:u32 | n:u32 | flags:u8
    [| ek:32 | spk:u32 | opk:u32]. x3dh is (ek, spk_id, opk_id or None)."""
    out = b"SC2D" + bytes([suite]) + bytes(frm) + bytes(to) + bytes(rk) + struct.pack(">II", pn, n)
    if x3dh is None:
        return out + b"\x00"
    ek, spk_id, opk_id = x3dh
    return out + b"\x01" + bytes(ek) + struct.pack(">II", spk_id, NO_OPK if opk_id is None else opk_id)


def post_signed_fields(relay_id, room, suite, ik, msg_id, ts, t, name, body, ref):
    """Public post signed bytes from raw fields (bytes for ik/msg_id/ref)."""
    if t not in POST_TYPES:
        raise ProtocolError(400, "bad_request", "unknown post type")
    name_b = name.encode()
    body_b = body.encode()
    if len(body_b) > 0xFFFF:
        raise ProtocolError(413, "too_large", "body too long")
    return (L_PUB + bytes([suite]) + _lp8(relay_id.encode(), "relay id") + _lp8(room.encode(), "room") +
            bytes(ik) + bytes(msg_id) + struct.pack(">QB", ts, POST_TYPES[t]) + _lp8(name_b, "name") +
            struct.pack(">H", len(body_b)) + body_b + (bytes(ref) if ref is not None else bytes(8)))


def post_signed_bytes(relay_id, room, post):
    """Signed bytes of a validated wire post (see frames.validate_post)."""
    from .codec import b64d, hexd
    ref = hexd(post["ref"], 8, "ref") if post.get("ref") else None
    return post_signed_fields(relay_id, room, post["s"], b64d(post["ik"], 32, "ik"), hexd(post["id"], 8, "id"),
                              post["ts"], post["t"], post["name"], post["body"], ref)


def members_hash(member_ids):
    """SHA-256 over the sorted raw 16-byte member IDs, concatenated."""
    ids = sorted(bytes(m) for m in member_ids)
    return sha256(b"".join(ids))


def _id_list(ids, field):
    if len(ids) > 255:
        raise ProtocolError(400, "bad_request", field + " list too long")
    return bytes([len(ids)]) + b"".join(bytes(i) for i in ids)


def commit_signed_bytes(room, prev, epoch, by, add, remove, admins, mhash, suite=SUITE):
    """Commit signed bytes. add/remove/admins are lists of raw 16-byte IDs in
    the order they appear on the wire (canonical frames sort them); admins
    None means "admin list unchanged"."""
    out = (L_COMMIT + bytes([suite]) + bytes(room) + struct.pack(">II", prev, epoch) + bytes(by) +
           _id_list(add, "add") + _id_list(remove, "remove"))
    if admins is None:
        out += b"\x00"
    else:
        out += b"\x01" + _id_list(admins, "admins")
    return out + bytes(mhash)


def mod_signed_bytes(relay_id, room, action, ref, device, until, seq, ts, suite=SUITE):
    """Relay-signed moderation event. ref is 8 raw bytes or None, device is 16
    raw bytes or None, until is a unix time or None (indefinite -> 0)."""
    if action not in MOD_ACTIONS:
        raise ProtocolError(400, "bad_request", "unknown moderation action")
    return (L_MOD + bytes([suite]) + _lp8(relay_id.encode(), "relay id") + _lp8(room.encode(), "room") +
            bytes([MOD_ACTIONS[action]]) + (bytes(ref) if ref is not None else bytes(8)) +
            (bytes(device) if device is not None else bytes(16)) +
            struct.pack(">QQQ", 0 if until is None else until, seq, ts))


def invite_key(invite_secret, room):
    """What the admin registers with the relay (room.invite)."""
    return hmac_sha256(invite_secret, L_INVITE + bytes(room))


def invite_proof(key, joiner):
    """What a joiner sends in room.join.invite; joiner is the raw device ID."""
    return hmac_sha256(key, L_JOIN + bytes(joiner))
