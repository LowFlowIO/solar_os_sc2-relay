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

    def verify(dev, msg, sig):
        return sc2ref.ed_verify(keys[dev], msg, sig)

    room = "cd" * 16
    st = RoomState(room, max_members=3)
    g = make_commit(room, st, a, add=[a], admins=[a], sign=lambda m: sc2ref.ed_sign(sa, m))
    g = frames.validate_commit(g)
    st1 = st.apply_genesis(a, g, verify)
    assert st1.epoch == 1 and st1.members == {a} and st1.admins == {a}
    with pytest.raises(ProtocolError) as e:
        st1.apply_genesis(a, g, verify)
    assert e.value.code == 409
    c1 = frames.validate_commit(make_commit(room, st1, a, add=[b, c], sign=lambda m: sc2ref.ed_sign(sa, m)))
    st2 = st1.apply(c1, verify)
    assert st2.members == {a, b, c} and st2.epoch == 2
    # linear: replaying c1 against st2 conflicts
    with pytest.raises(ProtocolError) as e:
        st2.apply(c1, verify)
    assert e.value.err == "epoch_conflict" and e.value.extra["epoch"] == 2
    # cap
    with pytest.raises(ProtocolError) as e:
        st2.apply(frames.validate_commit(make_commit(room, st2, a, add=[d], sign=lambda m: sc2ref.ed_sign(sa, m))),
                  verify)
    assert e.value.code == 403
    # non-admin
    with pytest.raises(ProtocolError) as e:
        st2.apply(frames.validate_commit(make_commit(room, st2, b, remove=[c], sign=lambda m: sc2ref.ed_sign(sb, m))),
                  verify)
    assert e.value.code == 403
    # removing the only admin without naming another leaves no admins
    with pytest.raises(ProtocolError):
        st2.apply(frames.validate_commit(make_commit(room, st2, a, remove=[a], sign=lambda m: sc2ref.ed_sign(sa, m))),
                  verify)
    ok = st2.apply(frames.validate_commit(make_commit(room, st2, a, remove=[a], admins=[b],
                                                      sign=lambda m: sc2ref.ed_sign(sa, m))), verify)
    assert ok.admins == {b} and ok.members == {b, c}
    # signature binds the room
    other = make_commit("ef" * 16, st2, a, add=[d], sign=lambda m: sc2ref.ed_sign(sa, m))
    with pytest.raises(ProtocolError):
        st2.apply(frames.validate_commit(other), verify)
    # members_hash is SHA-256 over the sorted raw IDs
    assert st2.members_hash() == layouts.sha256(b"".join(sorted(bytes.fromhex(x) for x in (a, b, c))))


def test_commit_and_mod_layouts_are_stable():
    room, by = bytes(16), bytes([1]) * 16
    blob = layouts.commit_signed_bytes(room, 1, 2, by, [bytes([2]) * 16], [], None, bytes(32))
    assert blob.hex() == ("5343322d434f4d4d495401" "01" + "00" * 16 + "00000001" "00000002" + "01" * 16 +
                          "01" + "02" * 16 + "00" + "00" + "00" * 32)
    m = layouts.mod_signed_bytes("r", "pub:g", "ban", None, bytes([3]) * 16, None, 7, 9)
    assert m.hex() == ("5343322d4d4f4401" "01" "01" "72" "05" + b"pub:g".hex() + "02" + "00" * 8 + "03" * 16 +
                       "0" * 16 + "%016x" % 7 + "%016x" % 9)


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
