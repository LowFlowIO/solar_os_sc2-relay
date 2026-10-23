"""SC2 v2 frame schemas: validation of client frames and builders for relay
frames (draft §6). Validators return a new, normalised dict that holds only
the known fields, so nothing unsigned or unexpected is stored or forwarded.
Every failure raises ProtocolError.

SPDX-License-Identifier: MIT
"""

from .codec import b64d, hexd, hexe, is_hex, loads
from .errors import ProtocolError
from . import layouts

PROTO = "sc2"
VERSION = 2
LINE_MAX = 16384
V1_LINE_MAX = 4096 * 6 + 768  # chatd CHATD_LINE_MAX
RID_MAX = 16
TYPE_MAX = 32
ROOM_NAME_MAX = 64
POST_NAME_MAX = 64
POST_BODY_WIRE_MAX = 4096
CLIENT_MAX = 64
ADMIT_MAX = 96
REASON_MAX = 256
TITLE_MAX = 64
OPK_MAX = 100
ROOM_MEMBERS_MAX = 32
SYNC_MAX = 500
SYNC_ROOMS_MAX = 128
U32 = 0xFFFFFFFF
U64 = 0xFFFFFFFFFFFFFFFF
PAD_BUCKETS = (256, 512, 1024, 2048, 4096, 8192)
TAG_LEN = 16
CT_LENGTHS = tuple(b + TAG_LEN for b in PAD_BUCKETS)
PRESENCE_STATES = ("online", "away", "hidden")
_PUB_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789-_."

CLIENT_TYPES = (
    "hello", "auth", "ping", "keys.publish", "keys.claim", "room.create", "room.list", "room.join",
    "room.leave", "room.members", "room.invite", "room.commit", "room.send", "room.post", "room.report",
    "dm.send", "sync", "ack", "presence.set",
)


def _bad(text):
    raise ProtocolError(400, "bad_request", text)


def _req(obj, key):
    if key not in obj:
        _bad("missing " + key)
    return obj[key]


def _int(v, field, lo=0, hi=U32):
    if isinstance(v, bool) or not isinstance(v, int) or v < lo or v > hi:
        _bad(field + " must be an integer in " + str(lo) + ".." + str(hi))
    return v


def _str(v, field, max_bytes, min_bytes=0):
    if not isinstance(v, str):
        _bad(field + " must be a string")
    n = len(v.encode())
    if n > max_bytes or n < min_bytes:
        raise ProtocolError(413 if n > max_bytes else 400, "too_large" if n > max_bytes else "bad_request",
                            field + " length out of range")
    return v


def _obj(v, field):
    if not isinstance(v, dict):
        _bad(field + " must be an object")
    return v


def _bool(v, field):
    if not isinstance(v, bool):
        _bad(field + " must be true or false")
    return v


def device_hex(v, field="device"):
    if not is_hex(v, 32):
        _bad(field + " must be a 32 hex device ID")
    return v


def msg_id_hex(v, field="id"):
    if not is_hex(v, 16):
        _bad(field + " must be a 16 hex message ID")
    return v


def parse_seq(v, field="seq"):
    """Relay sequence numbers travel as decimal strings (uint64)."""
    if not isinstance(v, str) or not v or len(v) > 20:
        _bad(field + " must be a decimal string")
    for c in v:
        if c < "0" or c > "9":
            _bad(field + " must be a decimal string")
    if len(v) > 1 and v[0] == "0":
        _bad(field + " must not have leading zeros")
    n = int(v)
    if n > U64:
        _bad(field + " out of range")
    return n


def fmt_seq(n):
    return str(int(n))


def is_public_room(room):
    if not isinstance(room, str) or not room.startswith("pub:"):
        return False
    name = room[4:]
    if not name or len(room) > ROOM_NAME_MAX:
        return False
    for c in name:
        if c not in _PUB_CHARS:
            return False
    return True


def is_private_room(room):
    return is_hex(room, 32)


def room_id(v, field="room"):
    if is_private_room(v) or is_public_room(v):
        return v
    _bad(field + " must be 32 hex (private) or pub:<name> (public)")


def public_room(v, field="room"):
    if not is_public_room(v):
        _bad(field + " must be a public room (pub:<name>)")
    return v


def private_room(v, field="room"):
    if not is_private_room(v):
        _bad(field + " must be a private room ID (32 hex)")
    return v


def public_room_name(name):
    """Config helper: "general" or "pub:general" -> "pub:general"."""
    room = name if name.startswith("pub:") else "pub:" + name
    if not is_public_room(room):
        raise ValueError("invalid public room name: " + name)
    return room


def ciphertext(v, field="ct"):
    ct = b64d(v, None, field)
    if len(ct) not in CT_LENGTHS:
        if len(ct) > CT_LENGTHS[-1]:
            raise ProtocolError(413, "too_large", field + " over the size limit")
        _bad(field + " is not a padded SC2 ciphertext")
    return v


# ---------------- envelope and object validators ----------------

def validate_room_env(env):
    env = _obj(env, "env")
    out = {
        "s": _int(_req(env, "s"), "s", 1, 255),
        "e": _int(_req(env, "e"), "e", 1),
        "from": device_hex(_req(env, "from"), "from"),
        "n": _int(_req(env, "n"), "n"),
        "nonce": _req(env, "nonce"),
        "ct": ciphertext(_req(env, "ct")),
        "sig": _req(env, "sig"),
    }
    if out["s"] != layouts.SUITE:
        _bad("unsupported suite")
    b64d(out["nonce"], 24, "nonce")
    b64d(out["sig"], 64, "sig")
    return out


def room_env_signed_bytes(room, env):
    hdr = layouts.room_header(hexd(room, 16, "room"), env["e"], hexd(env["from"], 16, "from"), env["n"], env["s"])
    return layouts.room_signed(hdr, b64d(env["nonce"], 24), b64d(env["ct"]))


def validate_dm_env(env):
    env = _obj(env, "env")
    out = {"s": _int(_req(env, "s"), "s", 1, 255), "from": device_hex(_req(env, "from"), "from")}
    if out["s"] != layouts.SUITE:
        _bad("unsupported suite")
    if "x3dh" in env:
        x = _obj(env["x3dh"], "x3dh")
        xo = {"ek": _req(x, "ek"), "spk": _int(_req(x, "spk"), "x3dh.spk")}
        b64d(xo["ek"], 32, "x3dh.ek")
        if "opk" in x:
            xo["opk"] = _int(x["opk"], "x3dh.opk", 0, U32 - 1)
        out["x3dh"] = xo
    out["rk"] = _req(env, "rk")
    b64d(out["rk"], 32, "rk")
    out["pn"] = _int(_req(env, "pn"), "pn")
    out["n"] = _int(_req(env, "n"), "n")
    out["nonce"] = _req(env, "nonce")
    b64d(out["nonce"], 24, "nonce")
    out["ct"] = ciphertext(_req(env, "ct"))
    return out


def validate_post(post, max_body=POST_BODY_WIRE_MAX, max_name=POST_NAME_MAX):
    """Validate a public post; the signature is checked by the caller using
    layouts.post_signed_bytes()."""
    post = _obj(post, "post")
    out = {
        "s": _int(_req(post, "s"), "s", 1, 255),
        "t": _req(post, "t"),
        "from": device_hex(_req(post, "from"), "from"),
        "ik": _req(post, "ik"),
        "id": msg_id_hex(_req(post, "id")),
        "ts": _int(_req(post, "ts"), "ts", 0, U64),
        "name": _str(_req(post, "name"), "name", max_name),
        "body": _str(_req(post, "body"), "body", max_body),
    }
    if out["s"] != layouts.SUITE:
        _bad("unsupported suite")
    if not isinstance(out["t"], str) or out["t"] not in layouts.POST_TYPES:
        _bad("unknown post type")
    ik = b64d(out["ik"], 32, "ik")
    if hexe(layouts.device_id(ik)) != out["from"]:
        _bad("from does not match ik")
    if "ref" in post and post["ref"] is not None:
        out["ref"] = msg_id_hex(post["ref"], "ref")
    if out["t"] == "del":
        if "ref" not in out:
            _bad("del needs ref")
        if out["body"] != "":
            _bad("del must have an empty body")
    out["sig"] = _req(post, "sig")
    b64d(out["sig"], 64, "sig")
    return out


def validate_commit(f):
    """The commit fields of room.create (private) and room.commit: the
    130-byte record and its signature, both base64. Shape rules are checked
    here; roster rules by rooms.RoomState."""
    out = {"commit": _req(f, "commit"), "sig": _req(f, "sig")}
    rec = b64d(out["commit"], layouts.COMMIT_LEN, "commit")
    b64d(out["sig"], 64, "sig")
    layouts.commit_parse(rec)
    return out


# ---------------- client frames ----------------

def parse(line):
    """Parse one client line: JSON object with a string type and optional rid.
    Returns (type, raw dict, rid)."""
    obj = loads(line)
    t = obj.get("type")
    if not isinstance(t, str) or not t or len(t) > TYPE_MAX:
        _bad("missing type")
    rid = obj.get("rid")
    if rid is not None:
        if not isinstance(rid, str) or len(rid.encode()) > RID_MAX:
            raise ProtocolError(400, "bad_request", "rid must be a string of at most 16 bytes")
    return t, obj, rid


def is_v2_hello(obj):
    return obj.get("type") == "hello" and obj.get("proto") == PROTO


def validate(t, f):
    """Validate a client frame of type t; returns the normalised frame."""
    v = _VALIDATORS.get(t)
    if v is None:
        _bad("unknown type")
    out = {"type": t}
    if f.get("rid") is not None:
        out["rid"] = f["rid"]
    body = v(f)
    for k in body:
        out[k] = body[k]
    return out


def _v_hello(f):
    if f.get("proto") != PROTO:
        _bad("proto must be sc2")
    v = _int(_req(f, "v"), "v", 1, 255)
    suites = f.get("suites", [layouts.SUITE])
    if not isinstance(suites, list) or not suites or len(suites) > 8:
        _bad("suites must be a list")
    for s in suites:
        _int(s, "suites", 1, 255)
    out = {"v": v, "proto": PROTO, "suites": list(suites),
           "client": _str(f.get("client", ""), "client", CLIENT_MAX)}
    if f.get("admit") is not None:
        out["admit"] = _str(f["admit"], "admit", ADMIT_MAX)
    if f.get("nonce") is not None:
        out["nonce"] = b64d(f["nonce"], 16, "nonce")
    return out


def _v_auth(f):
    out = {"ik": _req(f, "ik"), "sig": _req(f, "sig"), "resume": _bool(f.get("resume", False), "resume")}
    b64d(out["ik"], 32, "ik")
    b64d(out["sig"], 64, "sig")
    return out


def _v_empty(f):
    return {}


def _v_keys_publish(f):
    out = {"dk": _req(f, "dk"), "dk_sig": _req(f, "dk_sig")}
    b64d(out["dk"], 32, "dk")
    b64d(out["dk_sig"], 64, "dk_sig")
    spk = _obj(_req(f, "spk"), "spk")
    out["spk"] = {"id": _int(_req(spk, "id"), "spk.id"), "pub": _req(spk, "pub"), "sig": _req(spk, "sig")}
    b64d(out["spk"]["pub"], 32, "spk.pub")
    b64d(out["spk"]["sig"], 64, "spk.sig")
    opks = f.get("opks", [])
    if not isinstance(opks, list):
        _bad("opks must be a list")
    if len(opks) > OPK_MAX:
        raise ProtocolError(413, "too_large", "at most 100 one-time prekeys")
    seen = set()
    out["opks"] = []
    for o in opks:
        o = _obj(o, "opk")
        oid = _int(_req(o, "id"), "opk.id", 0, U32 - 1)
        if oid in seen:
            _bad("duplicate opk id")
        seen.add(oid)
        b64d(_req(o, "pub"), 32, "opk.pub")
        out["opks"].append({"id": oid, "pub": o["pub"]})
    return out


def _v_keys_claim(f):
    return {"device": device_hex(_req(f, "device"))}


def _v_room_create(f):
    kind = _req(f, "kind")
    room = _req(f, "room")
    if kind == "private":
        out = {"room": private_room(room), "kind": kind}
        pol = _obj(f.get("policy", {}), "policy")
        out["policy"] = {"max": _int(pol.get("max", ROOM_MEMBERS_MAX), "policy.max", 1, ROOM_MEMBERS_MAX)}
        out.update(validate_commit(f))
        return out
    if kind == "public":
        out = {"room": public_room(room), "kind": kind}
        out["title"] = _str(f.get("title", "#" + room[4:]), "title", TITLE_MAX, 1)
        return out
    _bad("kind must be private or public")


def _v_room_list(f):
    kind = f.get("kind", "public")
    if kind not in ("public", "private"):
        _bad("kind must be public or private")
    return {"kind": kind}


def _v_room_only(f):
    return {"room": room_id(_req(f, "room"))}


def _v_room_join(f):
    out = {"room": room_id(_req(f, "room"))}
    if f.get("invite") is not None:
        b64d(f["invite"], 32, "invite")
        out["invite"] = f["invite"]
    return out


def _v_room_invite(f):
    out = {"room": private_room(_req(f, "room")), "key": _req(f, "key"),
           "revoke": _bool(f.get("revoke", False), "revoke")}
    b64d(out["key"], 32, "key")
    return out


def _v_room_commit(f):
    out = {"room": private_room(_req(f, "room"))}
    out.update(validate_commit(f))
    return out


def _v_room_send(f):
    return {"room": private_room(_req(f, "room")), "env": validate_room_env(_req(f, "env"))}


def _v_room_post(f):
    return {"room": public_room(_req(f, "room")), "post": validate_post(_req(f, "post"))}


def _v_room_report(f):
    return {"room": public_room(_req(f, "room")), "ref": msg_id_hex(_req(f, "ref"), "ref"),
            "reason": _str(f.get("reason", ""), "reason", REASON_MAX)}


def _v_dm_send(f):
    return {"to": device_hex(_req(f, "to"), "to"), "env": validate_dm_env(_req(f, "env"))}


def _v_sync(f):
    out = {"inbox": parse_seq(f.get("inbox", "0"), "inbox"), "rooms": {}}
    rooms = _obj(f.get("rooms", {}), "rooms")
    if len(rooms) > SYNC_ROOMS_MAX:
        _bad("too many rooms in sync")
    for r in rooms:
        out["rooms"][room_id(r)] = parse_seq(rooms[r], "rooms." + r)
    out["max"] = _int(f.get("max", 100), "max", 1, SYNC_MAX)
    return out


def _v_ack(f):
    return {"inbox": parse_seq(_req(f, "inbox"), "inbox")}


def _v_presence(f):
    s = _req(f, "state")
    if s not in PRESENCE_STATES:
        _bad("state must be online, away or hidden")
    return {"state": s}


_VALIDATORS = {
    "hello": _v_hello,
    "auth": _v_auth,
    "ping": _v_empty,
    "keys.publish": _v_keys_publish,
    "keys.claim": _v_keys_claim,
    "room.create": _v_room_create,
    "room.list": _v_room_list,
    "room.join": _v_room_join,
    "room.leave": _v_room_only,
    "room.members": _v_room_only,
    "room.invite": _v_room_invite,
    "room.commit": _v_room_commit,
    "room.send": _v_room_send,
    "room.post": _v_room_post,
    "room.report": _v_room_report,
    "dm.send": _v_dm_send,
    "sync": _v_sync,
    "ack": _v_ack,
    "presence.set": _v_presence,
}


# ---------------- relay frames ----------------

def frame(t, rid=None, **fields):
    f = {"type": t}
    if rid is not None:
        f["rid"] = rid
    for k in fields:
        f[k] = fields[k]
    return f


def welcome(relay_id, relay_key_b64, challenge_b64, legacy_v1, limits, suite=layouts.SUITE, relay_sig_b64=None,
            rotation=None):
    """relay_sig_b64: the relay key's signature over the hello nonce
    (sc2proto.relaykey.welcome_bytes). rotation: {"from": old key b64,
    "sig": b64}, the old key's signature over the current key."""
    f = {"type": "welcome", "v": VERSION, "proto": PROTO, "suite": suite,
         "relay": {"id": relay_id, "key": relay_key_b64}, "challenge": challenge_b64,
         "legacy_v1": bool(legacy_v1), "limits": dict(limits)}
    if relay_sig_b64 is not None:
        f["relay_sig"] = relay_sig_b64
    if rotation is not None:
        f["rotation"] = {"from": rotation["from"], "sig": rotation["sig"]}
    return f


def mod_frame(room, action, seq, ts, sign, device, ref=None, until=None):
    """Relay-signed room.mod over the 122-byte record (layouts.mod_record).
    sign(bytes) -> 64-byte signature. device is the author for remove, the
    banned device for ban and unban. until: ban only, None = indefinite."""
    msg = layouts.mod_record(action, room, seq, ts, hexd(ref, 8, "ref") if ref else None,
                             hexd(device, 16, "device"), until)
    f = {"type": "room.mod", "room": room, "seq": fmt_seq(seq), "action": action, "ts": ts}
    if action == "remove":
        f["ref"] = ref
    f["device"] = device
    if action == "ban":
        f["until"] = until if until else None
    f["by"] = "relay"
    from .codec import b64e
    f["sig"] = b64e(sign(msg))
    return f


def mod_signed_bytes_from_frame(f):
    """The record a room.mod frame's signature covers (what a client rebuilds
    from the flat fields before checking it against the relay key)."""
    if f.get("by") != "relay":
        _bad("room.mod must be by relay")
    until = f.get("until")
    if until is not None and (f["action"] != "ban" or not isinstance(until, int) or isinstance(until, bool)):
        _bad("until is an integer and only for ban")
    return layouts.mod_record(f["action"], f["room"], parse_seq(f["seq"]), f["ts"],
                              hexd(f["ref"], 8, "ref") if f.get("ref") is not None else None,
                              hexd(f["device"], 16, "device"), until)
