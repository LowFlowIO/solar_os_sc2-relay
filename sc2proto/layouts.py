"""SC2-1 binary layouts: signed bytes, AAD headers and hashes.

These are the byte strings that get signed or authenticated. They are built
with struct, never from JSON, so no canonicalisation is needed (draft §6).
All integers are big-endian; variable-length fields carry a length prefix.

Layouts taken verbatim from the draft: auth, dk, spk, room header (H), room
signature, DM header (Hd), public post.

Fixed-size layouts finalised in Phase 4b (draft §6.7, §7.5), chosen so a
device without PSRAM can build, parse and verify them in a few hundred bytes
of stack with no JSON lists to buffer:
- commit (130 bytes, signed as-is by the admin's IK; commit ID = SHA-256):
           "SC2-COMMIT\x01" | suite:u8 | room:16 | epoch:u32 | prev:32 | by:16 |
           op:u8 | target:16 | count:u8 | roster_hash:32
           roster_hash = SHA-256 over sorted (device:16 | role:u8) entries
- mod (122 bytes, signed by the relay key):
           "SC2-MOD\x01" | suite:u8 | action:u8 | room:64 (zero padded) |
           seq:u64 | ts:u64 | ref:8 | device:16 | until:u64
- invite:  invite_key = HMAC(invite_secret, "SC2-INVITE\x01" | room:16)
           proof      = HMAC(invite_key, "SC2-JOIN\x01" | joiner:16)

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
MOD_ACTIONS = {"remove": 1, "ban": 2, "unban": 3}
COMMIT_OPS = {"create": 1, "add": 2, "remove": 3, "promote": 4, "demote": 5, "rotate": 6}
COMMIT_OP_NAMES = {v: k for k, v in COMMIT_OPS.items()}
COMMIT_LEN = 130
MOD_LEN = 122
MOD_ROOM_MAX = 63
ROOM_MEMBERS_MAX = 32
ROLE_MEMBER = 0
ROLE_ADMIN = 1
ZERO16 = bytes(16)
ZERO32 = bytes(32)

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


def roster_hash(roster):
    """SHA-256 over the sorted (device:16 | role:u8) entries. roster maps raw
    16-byte device IDs to ROLE_ADMIN or ROLE_MEMBER."""
    return sha256(b"".join(bytes(d) + bytes([roster[d]]) for d in sorted(bytes(x) for x in roster)))


def commit_record(room, epoch, prev, by, op, target, count, rhash, suite=SUITE):
    """The 130-byte commit record. op is a name from COMMIT_OPS."""
    if op not in COMMIT_OPS:
        raise ProtocolError(400, "bad_request", "unknown commit op")
    rec = (L_COMMIT + bytes([suite]) + bytes(room) + struct.pack(">I", epoch) + bytes(prev) + bytes(by) +
           bytes([COMMIT_OPS[op]]) + bytes(target) + bytes([count]) + bytes(rhash))
    if len(rec) != COMMIT_LEN:
        raise ProtocolError(400, "bad_request", "commit field sizes")
    return rec


def commit_parse(rec):
    """Parse and shape-check a commit record (no roster rules). Returns a dict
    with raw bytes for room/prev/by/target/hash."""
    rec = bytes(rec)
    if len(rec) != COMMIT_LEN or rec[:11] != L_COMMIT or rec[11] != SUITE:
        raise ProtocolError(400, "bad_request", "malformed commit record")
    if rec[80] not in COMMIT_OP_NAMES:
        raise ProtocolError(400, "bad_request", "unknown commit op")
    c = {"room": rec[12:28], "epoch": struct.unpack(">I", rec[28:32])[0], "prev": rec[32:64], "by": rec[64:80],
         "op": COMMIT_OP_NAMES[rec[80]], "target": rec[81:97], "count": rec[97], "hash": rec[98:130]}
    if not 1 <= c["count"] <= ROOM_MEMBERS_MAX or c["epoch"] == 0 or c["by"] == ZERO16:
        raise ProtocolError(400, "bad_request", "commit count, epoch or signer out of range")
    if c["op"] == "create":
        if c["epoch"] != 1 or c["count"] != 1 or c["prev"] != ZERO32 or c["target"] != c["by"]:
            raise ProtocolError(400, "bad_request", "genesis must be epoch 1, zero prev, target = by, count 1")
    elif c["epoch"] == 1:
        raise ProtocolError(400, "bad_request", "only a genesis commit may have epoch 1")
    elif (c["op"] == "rotate") != (c["target"] == ZERO16):
        raise ProtocolError(400, "bad_request", "rotate has a zero target; other ops need one")
    return c


def commit_id(rec):
    return sha256(rec)


def mod_record(action, room, seq, ts, ref=None, device=None, until=None, suite=SUITE):
    """The 122-byte relay-signed moderation record. ref is 8 raw bytes (remove
    only), device 16 raw bytes (always), until a unix time (ban only; None or
    0 = indefinite)."""
    if action not in MOD_ACTIONS:
        raise ProtocolError(400, "bad_request", "unknown moderation action")
    r = room.encode()
    if not 0 < len(r) <= MOD_ROOM_MAX or b"\x00" in r:
        raise ProtocolError(400, "bad_request", "room name length")
    if device is None or bytes(device) == ZERO16:
        raise ProtocolError(400, "bad_request", "moderation events name a device")
    if (action == "remove") != (ref is not None and bytes(ref) != bytes(8)):
        raise ProtocolError(400, "bad_request", "ref is required for remove and only for remove")
    if action != "ban" and until:
        raise ProtocolError(400, "bad_request", "until is only for ban")
    return (L_MOD + bytes([suite, MOD_ACTIONS[action]]) + r + bytes(64 - len(r)) + struct.pack(">QQ", seq, ts) +
            (bytes(ref) if ref is not None else bytes(8)) + bytes(device) + struct.pack(">Q", until or 0))


def invite_key(invite_secret, room):
    """What the admin registers with the relay (room.invite)."""
    return hmac_sha256(invite_secret, L_INVITE + bytes(room))


def invite_proof(key, joiner):
    """What a joiner sends in room.join.invite; joiner is the raw device ID."""
    return hmac_sha256(key, L_JOIN + bytes(joiner))
