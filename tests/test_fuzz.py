"""Seeded fuzzing of frame parsing: sc2proto must only ever raise
ProtocolError, and a relay session fed mutated frames must answer with error
frames and never hit an internal failure.

SPDX-License-Identifier: MIT
"""

import json
import logging
import os
import random

import sc2ref
from helpers import Clock, make_config
from sc2_relay.core import Relay
from sc2_relay.crypto import SigningKey
from sc2_relay.storage import Storage
from sc2proto import LineBuffer, ProtocolError, b64d, frames, layouts

HERE = os.path.dirname(os.path.abspath(__file__))
VEC = json.load(open(os.path.join(HERE, "data", "sc2_vectors.json")))
SEEDS = [F for F in VEC["frames"].values() if F.startswith("{")]
ITER = int(os.environ.get("SC2_FUZZ_ITER", "3000"))
SEED = int(os.environ.get("SC2_FUZZ_SEED", "0"))  # vary for longer campaigns
JUNK = ['"', "\\", "{", "}", "[", "]", ",", ":", "0", "-1", "1e999", "null", "true", "\u0000", "\u00ff", "\ud800",
        "18446744073709551616", '""', "AAAA", "====", "\n"]


def mutate(rng, line):
    s = line
    for _ in range(rng.randint(1, 4)):
        op = rng.randrange(6)
        i = rng.randrange(len(s) + 1)
        if op == 0 and s:
            s = s[:i] + s[i + 1:]
        elif op == 1:
            s = s[:i] + rng.choice(JUNK) + s[i:]
        elif op == 2 and s:
            j = min(len(s), i + rng.randint(1, 40))
            s = s[:i] + s[j:]
        elif op == 3 and s:
            s = s[:i] + chr(rng.randrange(0x20, 0x7f)) + s[i + 1:]
        elif op == 4:
            s = s[:i] + s[rng.randrange(len(s) + 1):][:30] + s[i:]
        else:
            try:
                obj = json.loads(s)
            except ValueError:
                continue
            s = json.dumps(_mutate_obj(rng, obj))
    return s


def _mutate_obj(rng, obj):
    if isinstance(obj, dict) and obj:
        k = rng.choice(list(obj))
        choice = rng.randrange(5)
        if choice == 0:
            del obj[k]
        elif choice == 1:
            obj[k] = rng.choice([None, 0, -1, 2 ** 64, "", "x" * 300, [], {}, True, 1.5])
        else:
            obj[k] = _mutate_obj(rng, obj[k])
    elif isinstance(obj, list) and obj:
        obj[rng.randrange(len(obj))] = _mutate_obj(rng, obj[0])
    elif isinstance(obj, str):
        return rng.choice([obj[::-1], obj + "=", obj[:-1], obj.upper(), ""])
    elif isinstance(obj, int) and not isinstance(obj, bool):
        return rng.choice([obj + 1, -obj, 2 ** 32, 2 ** 63])
    return obj


def test_sc2proto_never_crashes():
    rng = random.Random(0x5C2 ^ SEED)
    valid = 0
    for i in range(ITER):
        line = mutate(rng, rng.choice(SEEDS))
        try:
            t, obj, rid = frames.parse(line.encode("utf-8", "surrogatepass"))
            out = frames.validate(t, obj)
            valid += 1
            if t == "room.post":
                layouts.post_signed_bytes("relay.example", out["room"], out["post"])
            if t == "room.send":
                frames.room_env_signed_bytes(out["room"], out["env"])
        except ProtocolError:
            pass
    assert valid > 0  # some mutations stay valid, so the validators were reached


def test_line_buffer_random_chunks():
    rng = random.Random(7 ^ SEED)
    data = ("\n".join(SEEDS) + "\n").encode()
    for _ in range(50):
        lb = LineBuffer(frames.LINE_MAX)
        out, i = [], 0
        while i < len(data):
            n = rng.randint(1, 700)
            out += lb.feed(data[i:i + n])
            i += n
        assert [x.decode() for x in out] == SEEDS


def test_relay_session_survives_fuzz(tmp_path, caplog):
    cfg = make_config(str(tmp_path), relay_id="relay.example")
    store = Storage(str(tmp_path / "db.sqlite3"))
    relay = Relay(cfg, store, SigningKey(os.urandom(32)), clock=Clock())
    sent = []
    sess = relay.new_session("127.0.0.1", "tcp", sent.append, lambda: None)
    # authenticate with the vector post identity so authed handlers are exercised
    seed = bytes.fromhex(VEC["frames"]["post_seed"])
    ik = sc2ref.ed_public(seed)
    sess.feed(b'{"type":"hello","v":2,"proto":"sc2","suites":[1]}\n')
    ch = b64d(json.loads(sent[-1])["challenge"])
    sig = sc2ref.ed_sign(seed, layouts.auth_bytes("relay.example", ch, ik))
    sess.feed(sc2ref.dumps({"type": "auth", "ik": sc2ref.b64(ik), "sig": sc2ref.b64(sig)}).encode() + b"\n")
    assert json.loads(sent[-1])["type"] == "authed"
    sess.feed(b'{"type":"room.join","room":"pub:general"}\n')
    rng = random.Random(0xF00D ^ SEED)
    caplog.set_level(logging.ERROR, logger="sc2_relay")
    for i in range(ITER):
        line = mutate(rng, rng.choice(SEEDS))
        sess.closed = False
        sess.state = "authed"
        sess.feed(line.encode("utf-8", "surrogatepass") + b"\n")
    assert not [r for r in caplog.records if "handler failed" in r.getMessage()]
    for raw in sent:
        f = json.loads(raw)
        assert isinstance(f, dict) and "type" in f


V1_SEEDS = ['{"type":"hello","user":"ana","token":""}', '{"type":"join","channel":"general","cursor":0}',
            '{"type":"msg","channel":"general","text":"hi there"}', '{"type":"leave","channel":"general"}',
            '{"type":"delete","channel":"general"}', '{"type":"join","channel":"lab","cursor":18446744073709551615}',
            '{"type":"msg","text":"no channel"}']


def test_legacy_v1_session_survives_fuzz(tmp_path, caplog):
    cfg = make_config(str(tmp_path), relay_id="relay.example", legacy_v1=True)
    store = Storage(str(tmp_path / "db.sqlite3"))
    relay = Relay(cfg, store, SigningKey(os.urandom(32)), clock=Clock())
    sent = []
    sess = relay.new_session("127.0.0.1", "tcp", sent.append, lambda: None)
    sess.feed(b'{"type":"hello","user":"ana"}\n')
    assert sess.state == "v1"
    rng = random.Random(0xC4A7 ^ SEED)
    caplog.set_level(logging.ERROR, logger="sc2_relay")
    for i in range(ITER):
        line = mutate(rng, rng.choice(V1_SEEDS))
        sess.closed = False
        sess.feed(line.encode("utf-8", "surrogatepass") + b"\n")
        if sess.v1 is not None and not sess.v1.authed:
            sess.feed(b'{"type":"hello","user":"ana"}\n')
    assert not [r for r in caplog.records if "handler failed" in r.getMessage() or r.levelno >= logging.ERROR]
    for raw in sent:
        f = json.loads(raw)
        assert isinstance(f, dict) and "type" in f
