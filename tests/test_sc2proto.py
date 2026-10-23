"""sc2proto (sans-IO package): codecs, layouts, validators, commit sequencing,
rate limiting and cursor logic, checked against the Phase 1 vectors.

SPDX-License-Identifier: MIT
"""

import ast
import json
import os

import pytest

import sc2ref
from sc2proto import LineBuffer, ProtocolError, b64d, b64e, dumps, error_frame, frames, hexe, layouts, limits
from sc2proto.rooms import RoomState, make_commit

HERE = os.path.dirname(os.path.abspath(__file__))
VEC = json.load(open(os.path.join(HERE, "..", "..", "protocol", "sc2", "vectors", "sc2_vectors.json")))
PKG = os.path.join(HERE, "..", "sc2proto")


def test_only_portable_imports():
    """json, struct, binascii (+ hashlib, optional) and relative imports only:
    the subset shared by CPython and MicroPython, no I/O, no time, no asyncio."""
    allowed = {"json", "struct", "binascii", "hashlib"}
    for name in os.listdir(PKG):
        if not name.endswith(".py"):
            continue
        tree = ast.parse(open(os.path.join(PKG, name)).read())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    assert a.name in allowed, (name, a.name)
            elif isinstance(node, ast.ImportFrom):
                assert node.level >= 1 or node.module in allowed, (name, node.module)
            elif isinstance(node, (ast.AsyncFunctionDef, ast.Await)):
                raise AssertionError("async code in sc2proto/" + name)


def test_b64_vectors():
    for v in VEC["b64"]:
        assert b64e(bytes.fromhex(v["bin"])) == v["b64"]
        assert b64d(v["b64"]) == bytes.fromhex(v["bin"])
    for bad in VEC["b64_bad"]:
        with pytest.raises(ProtocolError):
            b64d(bad)
    with pytest.raises(ProtocolError):
        b64d("AAAA", 4)


def test_sha256_and_hmac_vectors():
    for v in VEC["sha256"]:
        assert layouts.sha256(bytes.fromhex(v["msg"])).hex() == v["digest"]
    for v in VEC["hmac"]:
        assert layouts.hmac_sha256(bytes.fromhex(v["key"]), bytes.fromhex(v["msg"])).hex() == v["mac"]


def test_identity_and_signed_layouts():
    idv = VEC["identity"]
    ik = bytes.fromhex(idv["ik_pub"])
    assert hexe(layouts.device_id(ik)) == idv["device_id"]
    assert sc2ref.ed_verify(ik, layouts.dk_signed(bytes.fromhex(idv["dk_pub"])), bytes.fromhex(idv["dk_sig"]))
    assert sc2ref.ed_verify(ik, layouts.spk_signed(idv["spk_id"], bytes.fromhex(idv["spk_pub"])),
                            bytes.fromhex(idv["spk_sig"]))


def test_post_signed_bytes_vector():
    f = VEC["frames"]
    post = json.loads(f["room_post"])["post"]
    assert layouts.post_signed_bytes("relay.example", "pub:general", post).hex() == f["post_signed"]
    vp = frames.validate_post(post)
    assert vp == post
    assert sc2ref.ed_verify(b64d(post["ik"]), bytes.fromhex(f["post_signed"]), b64d(post["sig"]))
    d = json.loads(f["room_post_del"])["post"]
    assert sc2ref.ed_verify(b64d(d["ik"]), layouts.post_signed_bytes("relay.example", "pub:general", d),
                            b64d(d["sig"]))


def test_room_header_vector_and_signature():
    rv = VEC["room"]
    room, sender = bytes.fromhex(rv["room"]), bytes.fromhex(rv["sender"])
    send = json.loads(VEC["frames"]["room_send"])
    env = frames.validate_room_env(send["env"])
    hdr = layouts.room_header(bytes.fromhex(send["room"]), env["e"], bytes.fromhex(env["from"]), env["n"])
    assert len(hdr) == 45
    assert layouts.room_header(room, rv["epoch"], sender, 0)[:4] == b"SC2R"
    assert rv["hdr"] == layouts.room_header(room, rv["epoch"], sender, struct_n(rv)).hex()


def struct_n(rv):
    return int(rv["hdr"][-8:], 16)


def test_dm_header_matches_sc2ref():
    h = {"dh": bytes(range(32)), "pn": 3, "n": 7, "x3dh": {"ek": bytes(32), "spk_id": 5, "opk_id": sc2ref.NO_OPK}}
    a, b = bytes(16), bytes([1]) * 16
    assert sc2ref.dm_header(h, a, b) == layouts.dm_header(a, b, h["dh"], 3, 7, (bytes(32), 5, None))
    h["x3dh"] = None
    assert sc2ref.dm_header(h, a, b) == layouts.dm_header(a, b, h["dh"], 3, 7)


def test_vector_frames_validate():
    f = VEC["frames"]
    for key, t in (("hello", "hello"), ("auth", "auth"), ("dm_send", "dm.send"), ("dm_send_plain", "dm.send"),
                   ("room_send", "room.send"), ("room_post", "room.post"), ("room_post_del", "room.post")):
        t2, obj, rid = frames.parse(f[key])
        assert t2 == t
        out = frames.validate(t, obj)
        assert dumps(out) == dumps(obj), key  # normalisation keeps the C core's frames byte for byte
    w = json.loads(f["welcome"])
    assert w["limits"] == limits.WELCOME_LIMITS
    assert frames.welcome(w["relay"]["id"], w["relay"]["key"], w["challenge"], w["legacy_v1"], w["limits"]) == w


def test_parse_errors():
    for line, code in ((b"", 400), (b"[]", 400), (b"{}", 400), (b"\xff", 400), (b'{"type":1}', 400),
                       (b'{"type":"ping","rid":"' + b"x" * 17 + b'"}', 400)):
        with pytest.raises(ProtocolError) as e:
            frames.parse(line)
        assert e.value.code == code
    with pytest.raises(ProtocolError):
        frames.validate("nope", {})
    with pytest.raises(ProtocolError):
        frames.parse_seq("01")
    with pytest.raises(ProtocolError):
        frames.parse_seq(str(1 << 64))
    assert frames.parse_seq(str((1 << 64) - 1)) == (1 << 64) - 1
    assert error_frame(429, "rate_limited", rid="x", retry_ms=5) == {
        "type": "error", "rid": "x", "code": 429, "err": "rate_limited", "text": "slow down", "retry_ms": 5}
    with pytest.raises(ValueError):
        ProtocolError(418, "teapot")


def test_room_names():
    assert frames.is_public_room("pub:general") and frames.is_public_room("pub:solar-dev")
    for bad in ("general", "pub:", "pub:Upper", "pub:a b", "pub:" + "a" * 61, "PUB:x"):
        assert not frames.is_public_room(bad)
    assert frames.is_private_room("ab" * 16) and not frames.is_private_room("AB" * 16)
    assert frames.public_room_name("general") == "pub:general"


def test_line_buffer():
    lb = LineBuffer(10)
    assert lb.feed(b'{"a":1}\r\n{"b"') == [b'{"a":1}']
    assert lb.feed(b':2}\n\n') == [b'{"b":2}']
    with pytest.raises(ProtocolError) as e:
        lb.feed(b"x" * 11)
    assert e.value.code == 413
    with pytest.raises(ProtocolError):
        lb.feed(b"\n")


def _keys():
    ids = []
    for _ in range(4):
        seed = os.urandom(32)
        ik = sc2ref.ed_public(seed)
        ids.append((hexe(layouts.device_id(ik)), seed, ik))
    return ids


def test_commit_sequencing():
    (a, sa, ia), (b, sb, ib), (c, sc, ic), (d, sd, idd) = _keys()
    keys = {a: ia, b: ib, c: ic, d: idd}
    seeds = {a: sa, b: sb, c: sc, d: sd}

    def verify(dev, msg, sig):
        return sc2ref.ed_verify(keys[dev], msg, sig)

    def mk(state, by, op, target=None):
        return make_commit(state, by, op, target, sign=lambda m: sc2ref.ed_sign(seeds[by], m))

    room = "cd" * 16
    st = RoomState(room, max_members=3)
    g = mk(st, a, "create")
    st1, parsed = st.apply(*g, verify, creator=a)
    assert parsed["op"] == "create" and st1.epoch == 1 and st1.members == {a} and st1.admins == {a}
    assert st1.head == hexe(layouts.commit_id(g[0]))
    with pytest.raises(ProtocolError) as e:
        st1.apply(*g, verify, creator=a)
    assert e.value.code == 409
    with pytest.raises(ProtocolError) as e:
        st.apply(*g, verify, creator=b)  # someone else's genesis
    assert e.value.code == 403
    with pytest.raises(ProtocolError) as e:
        st.apply(*g, verify)  # a genesis needs room.create
    assert e.value.code == 400
    c1 = mk(st1, a, "add", b)
    st2, _ = st1.apply(*c1, verify)
    st3, _ = st2.apply(*mk(st2, a, "add", c), verify)
    assert st3.members == {a, b, c} and st3.epoch == 3 and st3.roster[b] == 0
    # linear: replaying c1 against a later state conflicts
    with pytest.raises(ProtocolError) as e:
        st3.apply(*c1, verify)
    assert e.value.err == "epoch_conflict" and e.value.extra["epoch"] == 3 and e.value.extra["head"] == st3.head
    # a fork (right epoch, wrong prev) conflicts too
    fork = st2.copy()
    fork.epoch = 3
    with pytest.raises(ProtocolError) as e:
        st3.apply(*mk(fork, a, "rotate"), verify)
    assert e.value.err == "epoch_conflict"
    # cap
    with pytest.raises(ProtocolError) as e:
        st3.apply(*mk(st3, a, "add", d), verify)
    assert e.value.code == 403
    # non-admin
    with pytest.raises(ProtocolError) as e:
        st3.apply(*mk(st3, b, "remove", c), verify)
    assert e.value.code == 403
    # the last admin can be neither removed nor demoted
    for op in ("remove", "demote"):
        with pytest.raises(ProtocolError) as e:
            st3.apply(*mk(st3, a, op, a), verify)
        assert "last admin" in e.value.text
    # promote, then the old admin can be removed by the new one
    st4, _ = st3.apply(*mk(st3, a, "promote", b), verify)
    assert st4.admins == {a, b}
    st5, _ = st4.apply(*mk(st4, b, "remove", a), verify)
    assert st5.admins == {b} and st5.members == {b, c}
    # rotate keeps the roster, moves the epoch and head
    st6, p6 = st5.apply(*mk(st5, b, "rotate"), verify)
    assert p6["target"] == bytes(16) and st6.roster == st5.roster and st6.epoch == 6 and st6.head != st5.head
    # a wrong signature, a wrong roster hash, another room
    rec, sig = mk(st5, b, "rotate")
    with pytest.raises(ProtocolError) as e:
        st5.apply(rec, bytes(64), verify)
    assert e.value.code == 401
    bad = bytearray(rec)
    bad[100] ^= 1
    with pytest.raises(ProtocolError):
        st5.apply(bytes(bad), sig, verify)
    other = st5.copy()
    other.room = "ef" * 16
    with pytest.raises(ProtocolError) as e:
        st5.apply(*mk(other, b, "rotate"), verify)
    assert "another room" in e.value.text
    # nothing above changed the states it was applied to
    assert st3.epoch == 3 and st3.admins == {a}
    # roster_hash is SHA-256 over sorted (id | role) entries
    want = layouts.sha256(b"".join(bytes.fromhex(x) + bytes([1 if x == a else 0]) for x in sorted((a, b, c))))
    assert st3.roster_hash() == want


def test_commit_and_mod_layouts_are_stable():
    room, by, tgt = bytes([7]) * 16, bytes([1]) * 16, bytes([2]) * 16
    rec = layouts.commit_record(room, 2, bytes([5]) * 32, by, "add", tgt, 2, bytes([9]) * 32)
    assert len(rec) == 130
    assert rec.hex() == ("5343322d434f4d4d495401" "01" + "07" * 16 + "00000002" + "05" * 32 + "01" * 16 + "02" +
                         "02" * 16 + "02" + "09" * 32)
    assert layouts.commit_parse(rec)["op"] == "add"
    for bad in (rec[:-1], b"X" + rec[1:], rec[:80] + b"\x07" + rec[81:], rec[:97] + b"\x00" + rec[98:],
                rec[:97] + b"\x21" + rec[98:], rec[:28] + bytes(4) + rec[32:], rec[:28] + b"\x00\x00\x00\x01" + rec[32:],
                rec[:81] + bytes(16) + rec[97:], rec[:64] + bytes(16) + rec[80:]):
        with pytest.raises(ProtocolError):
            layouts.commit_parse(bad)
    m = layouts.mod_record("ban", "pub:g", 7, 9, None, bytes([3]) * 16, 11)
    assert len(m) == 122
    assert m.hex() == ("5343322d4d4f4401" "01" "02" + b"pub:g".hex() + "00" * 59 + "%016x" % 7 + "%016x" % 9 +
                       "00" * 8 + "03" * 16 + "%016x" % 11)
    for kw in ({"action": "remove"}, {"action": "unban", "until": 5}, {"action": "ban", "device": None},
               {"action": "ban", "ref": bytes([1]) * 8}, {"room": "pub:" + "x" * 60}, {"action": "mute"}):
        args = dict(action="ban", room="pub:g", seq=1, ts=2, ref=None, device=bytes([3]) * 16, until=None)
        args.update(kw)
        with pytest.raises(ProtocolError):
            layouts.mod_record(**args)


def test_invite_proof():
    secret, room, joiner = b"s" * 16, bytes(16), bytes([9]) * 16
    k = layouts.invite_key(secret, room)
    import hmac, hashlib
    assert k == hmac.new(secret, b"SC2-INVITE\x01" + room, hashlib.sha256).digest()
    assert layouts.invite_proof(k, joiner) == hmac.new(k, b"SC2-JOIN\x01" + joiner, hashlib.sha256).digest()


def test_token_bucket_and_tables():
    b = limits.TokenBucket(10, 5, now=0)
    assert [b.take(0) for _ in range(5)] == [0] * 5
    w = b.take(0)
    assert 5900 <= w <= 6000
    assert b.take(6.0) == 0
    t = limits.RateTable(60, 1)
    assert t.take("k", 0) == 0 and t.take("k", 0) > 0 and t.take("j", 0) == 0
    t.prune(100)
    assert t.buckets == {}


def test_sync_window():
    assert limits.sync_window(0, None, None) == (0, None)
    assert limits.sync_window(5, 1, 10) == (5, None)
    assert limits.sync_window(10, 1, 10) == (10, None)
    assert limits.sync_window(2, 6, 10) == (5, (2, 6))
    assert limits.sync_window(0, 1, 10, floor=7) == (6, None)
    assert limits.sync_window(0, 8, 10, floor=7) == (7, (6, 8))
    assert limits.queue_admit(499, 0, 10) and not limits.queue_admit(500, 0, 10)
    assert not limits.queue_admit(0, 5242880 - 5, 10)
    assert limits.ttl_cutoff(10 * 86400) == 3 * 86400
