"""Host interop test: the C protocol/sc2 core and the SolarOS SC2 engine,
built with gcc into a small harness, talk to this Python relay over TCP.

The C sources come from the SolarOS client checkout (main + SC2 client
patches): set SC2_CLIENT_DIR to it (default: a sibling "solar_os" directory
of this repository, or of relay/). Skipped when gcc or the client checkout
is not available.

SPDX-License-Identifier: MIT
"""

import asyncio
import os
import shutil
import subprocess

import pytest

from helpers import relay_server, run

HERE = os.path.dirname(os.path.abspath(__file__))


def _client_dir():
    env = os.environ.get("SC2_CLIENT_DIR")
    if env:
        return os.path.abspath(env)
    for rel in (("..", "..", "..", "solar_os"), ("..", "..", "solar_os")):
        cand = os.path.abspath(os.path.join(HERE, *rel))
        if os.path.isdir(os.path.join(cand, "protocol", "sc2")):
            return cand
    return os.path.abspath(os.path.join(HERE, "..", "..", "..", "solar_os"))


REPO = _client_dir()
SC2 = os.path.join(REPO, "protocol", "sc2")
ED = os.path.join(REPO, "src", "vendor", "meshcore", "ed25519")
WG = os.path.join(REPO, "components", "wireguard_lwip", "src")
SVC = os.path.join(REPO, "src", "services")

_MISSING = os.path.join("src", "services", "solar_os_sc2_client.c")
pytestmark = [
    pytest.mark.skipif(shutil.which(os.environ.get("CC", "gcc")) is None, reason="no C compiler"),
    pytest.mark.skipif(not os.path.isfile(os.path.join(REPO, _MISSING)),
                       reason="SC2_CLIENT_DIR does not point at a SolarOS client checkout (%s)" % REPO),
]


@pytest.fixture(scope="module")
def harness(tmp_path_factory):
    cc = os.environ.get("CC", "gcc")
    out = tmp_path_factory.mktemp("c")
    inc = ["-I" + os.path.join(SC2, "include"), "-I" + ED, "-I" + os.path.join(WG, "crypto", "refc"), "-I" + WG,
           "-I" + SVC]
    vendor = [os.path.join(ED, f) for f in ("fe.c", "ge.c", "sc.c", "sha512.c")] + \
             [os.path.join(WG, "crypto", "refc", f) for f in ("x25519.c", "chacha20.c", "chacha20poly1305.c",
                                                              "poly1305-donna.c")] + [os.path.join(WG, "crypto.c")]
    objs = []
    for i, src in enumerate(vendor):
        o = str(out / ("v%d.o" % i))
        subprocess.run([cc, "-std=c11", "-O2", "-w"] + inc + ["-c", src, "-o", o], check=True)
        objs.append(o)
    core = sorted(os.path.join(SC2, "src", f) for f in os.listdir(os.path.join(SC2, "src")) if f.endswith(".c"))
    eng = [os.path.join(SVC, "solar_os_sc2_engine.c"), os.path.join(SVC, "solar_os_sc2_selftest.c")]
    exes = {}
    for name, extra in (("sc2_relay_c_client", []),
                        ("sc2_relay_sc2c_client", [os.path.join(SVC, "solar_os_sc2_client.c")]),
                        ("sc2_minirelay_server", [])):
        exe = str(out / name)
        r = subprocess.run([cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"] + inc +
                           [os.path.join(HERE, "c", name + ".c")] + extra + core + eng + objs + ["-o", exe],
                           capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        exes[name] = exe
    return exes


def test_c_engine_against_python_relay(harness):
    async def body():
        async with relay_server(relay_id="relay.c-interop") as srv:
            proc = await asyncio.create_subprocess_exec(harness["sc2_relay_c_client"], "127.0.0.1", str(srv.ports["plain"]),
                                                        "relay.c-interop", stdout=asyncio.subprocess.PIPE,
                                                        stderr=asyncio.subprocess.PIPE)
            out, err = await asyncio.wait_for(proc.communicate(), 60)
            assert proc.returncode == 0, err.decode()
            assert out.decode().strip() == "SC2-C-RELAY OK"
            st = srv.relay.store
            assert st.scalar("SELECT COUNT(*) FROM public_log") == 1
            assert st.scalar("SELECT COUNT(*) FROM room_log WHERE kind='msg'") == 2
            # nothing the relay stored contains the private plaintexts
            dump = "\n".join("\n".join(str(v) for v in row) for t in ("inbox", "room_log")
                             for row in st.all("SELECT * FROM " + t))
            assert "hello from C" not in dump and "sealed room message" not in dump
    run(body())


def test_device_client_against_python_relay(harness):
    """The sc2-sync client state machine: login, #general, DMs both ways,
    matching safety numbers, offline DM delivered after a reconnect."""
    async def body():
        async with relay_server(relay_id="relay.sc2c") as srv:
            proc = await asyncio.create_subprocess_exec(harness["sc2_relay_sc2c_client"], "127.0.0.1",
                                                        str(srv.ports["plain"]), "relay.sc2c",
                                                        stdout=asyncio.subprocess.PIPE,
                                                        stderr=asyncio.subprocess.PIPE)
            out, err = await asyncio.wait_for(proc.communicate(), 90)
            assert proc.returncode == 0, out.decode() + err.decode()
            assert out.decode().strip().endswith("SC2C-RELAY OK")
            st = srv.relay.store
            assert st.scalar("SELECT COUNT(*) FROM public_log") == 1
            dump = "\n".join(str(v) for row in st.all("SELECT * FROM inbox") for v in row)
            assert "hi bob" not in dump and "while you were away" not in dump
            # private room: created with an invite, the joiner admitted
            # automatically, posts sealed under the room key
            assert "private room " in out.decode()
            room = out.decode().split("private room ")[1].split()[0]
            assert st.scalar("SELECT COUNT(*) FROM members WHERE room=?", (room,)) == 2
            assert st.scalar("SELECT COUNT(*) FROM invites WHERE room=?", (room,)) == 1
            logged = "\n".join(str(v) for row in st.all("SELECT * FROM room_log") for v in row)
            assert "private hello" not in logged and "private reply" not in logged
    run(body())


def test_device_client_failover_to_fallback_relay(harness):
    """Multi-relay (sc2-sync failover): same identity on a fallback relay,
    keys published there without one-time prekeys, an SPK-only X3DH from a
    peer that only knows the fallback, and the primary's mailbox after the
    return. The fallback never holds any of alice's OPKs."""
    async def body():
        async with relay_server(relay_id="relay.primary") as p, relay_server(relay_id="relay.fallback") as f:
            proc = await asyncio.create_subprocess_exec(harness["sc2_relay_sc2c_client"], "127.0.0.1",
                                                        str(p.ports["plain"]), "relay.primary",
                                                        str(f.ports["plain"]), "relay.fallback",
                                                        stdout=asyncio.subprocess.PIPE,
                                                        stderr=asyncio.subprocess.PIPE)
            out, err = await asyncio.wait_for(proc.communicate(), 120)
            text = out.decode()
            assert proc.returncode == 0, text + err.decode()
            assert "SC2C-MULTI OK" in text and text.strip().endswith("SC2C-RELAY OK")
            assert f.relay.store.scalar("SELECT COUNT(*) FROM devices") == 3
            # alice and bob published to the fallback without OPKs; only
            # carol (a primary-style client there) has any
            owners = {r[0] for r in f.relay.store.all("SELECT DISTINCT device FROM opks")}
            assert len(owners) == 1
            assert p.relay.store.scalar("SELECT COUNT(*) FROM devices") == 2
    run(body())


async def _pin_login(exe, port, relay_id, key_b64):
    proc = await asyncio.create_subprocess_exec(exe, "--pin", "127.0.0.1", str(port), relay_id, key_b64,
                                                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    out, err = await asyncio.wait_for(proc.communicate(), 60)
    assert proc.returncode == 0, out.decode() + err.decode()
    return [ln for ln in out.decode().splitlines() if ln.startswith("PIN ")]


def test_device_pinned_relay_key(harness, tmp_path):
    """The device client with the relay key pinned: logs in when the relay
    proves the key, refuses (hard) a different key, and follows a rotation
    signed by the pinned key, but not one signed by another key."""
    import base64
    from sc2_relay.server import rotate_key
    from helpers import make_config
    exe = harness["sc2_relay_sc2c_client"]

    async def body():
        async with relay_server(tmp=str(tmp_path), relay_id="relay.pin") as srv:
            key = base64.b64encode(srv.relay.key.public).decode()
            assert await _pin_login(exe, srv.ports["plain"], "relay.pin", key) == ["PIN READY"]
            other = base64.b64encode(bytes(range(32))).decode()
            got = await _pin_login(exe, srv.ports["plain"], "relay.pin", other)
            assert len(got) == 1 and got[0].startswith("PIN REFUSED relay key differs from the pinned key")
        return key

    old = run(body())
    old_raw = base64.b64decode(old)
    _, new = rotate_key(make_config(str(tmp_path), relay_id="relay.pin"))

    async def body2():
        async with relay_server(tmp=str(tmp_path), relay_id="relay.pin") as srv:
            assert srv.relay.rotation is not None
            assert await _pin_login(exe, srv.ports["plain"], "relay.pin", old) == ["PIN ROTATED " + new, "PIN READY"]
            assert await _pin_login(exe, srv.ports["plain"], "relay.pin", new) == ["PIN READY"]
            # a pin that is neither the old nor the new key is still refused
            got = await _pin_login(exe, srv.ports["plain"], "relay.pin", base64.b64encode(bytes(32)).decode())
            assert got[0].startswith("PIN REFUSED")
            # a forged rotation (signed by some other key) is not followed
            srv.relay.rotation = {"from": old, "sig": base64.b64encode(bytes(64)).decode()}
            got = await _pin_login(exe, srv.ports["plain"], "relay.pin", old)
            assert got[0].startswith("PIN REFUSED")
    assert old_raw
    run(body2())


def test_device_parses_relay_wellknown(harness):
    """The device's /.well-known parser on the relay's real body: signed
    descriptor first, read as the device reads it (first 1600 bytes)."""
    import base64
    from helpers import free_port, http_get
    exe = harness["sc2_relay_sc2c_client"]
    fb_key = base64.b64encode(bytes(range(1, 33))).decode()

    async def body():
        async with relay_server(relay_id="relay.wk", http_port=free_port(), public_host="relay.example",
                                public_port=7778, public_rooms=["room-%03d" % i for i in range(200)],
                                fallback_relays=["chats://b.example:7443 " + fb_key,
                                                 "chats://c.example:7444#pin=sha256/" + "A" * 43 + "= " + fb_key]) as srv:
            st, h, b = await http_get(srv.ports["http"], "/.well-known/solaros-relay")
            assert st == 200 and len(b) > 1600  # many rooms: the device sees only the start
            proc = await asyncio.create_subprocess_exec(exe, "--wellknown", stdin=asyncio.subprocess.PIPE,
                                                        stdout=asyncio.subprocess.PIPE)
            out, _ = await asyncio.wait_for(proc.communicate(b), 30)
            lines = out.decode().splitlines()
            key = base64.b64encode(srv.relay.key.public).decode()
            assert lines[0] == "id=relay.wk key=%s host=relay.example port=7778 tls=0 pin= fallbacks=2" % key
            assert lines[1] == "fallback=chats://b.example:7443 " + fb_key
            assert lines[2].startswith("fallback=chats://c.example:7444#pin=sha256/AAA")
            # tampering with the descriptor breaks the signature
            tampered = b.replace(b'"descriptor":"c2My', b'"descriptor":"c2Mz', 1)
            proc = await asyncio.create_subprocess_exec(exe, "--wellknown", stdin=asyncio.subprocess.PIPE,
                                                        stdout=asyncio.subprocess.PIPE)
            out, _ = await asyncio.wait_for(proc.communicate(tampered), 30)
            assert out.decode().startswith("WELLKNOWN ERR")
    run(body())


# ---------------- the on-device mini-relay (chatd), host build ----------------

class MiniRelay:
    """sc2_minirelay_server: the portable mini-relay core behind a TCP loop."""

    def __init__(self, exe, relay_id, admit=None, legacy=True):
        args = [exe, relay_id, admit or "-"] + ([] if legacy else ["nolegacy"])
        self.proc = subprocess.Popen(args, stdout=subprocess.PIPE, text=True)
        head = self.proc.stdout.readline().split()
        assert head[0] == "PORT", head
        self.port, self.key, self.size = int(head[1]), head[3], int(head[5])

    def close(self):
        self.proc.kill()
        self.proc.wait()


def _lines(port, frames, want):
    import json
    import socket
    s = socket.create_connection(("127.0.0.1", port), 5)
    f = s.makefile("rw")
    out = []
    for fr in frames:
        f.write(json.dumps(fr) + "\n")
        f.flush()
    for _ in range(want):
        ln = f.readline()
        if not ln:
            break
        out.append(json.loads(ln))
    s.close()
    return out


def test_device_client_against_c_minirelay(harness):
    """The sc2-sync client against the C mini-relay that runs in chatd:
    login with the relay key proof, prekey bundles, DMs both ways, #general
    posts, an offline DM stored and delivered after a reconnect."""
    mr = MiniRelay(harness["sc2_minirelay_server"], "chatd.test")
    try:
        env = dict(os.environ, SC2C_NO_PRIVATE="1")
        r = subprocess.run([harness["sc2_relay_sc2c_client"], "127.0.0.1", str(mr.port), "chatd.test"],
                           capture_output=True, text=True, timeout=90, env=env)
        assert r.returncode == 0, r.stdout + r.stderr
        assert r.stdout.strip().endswith("SC2C-RELAY OK")
        # the relay key it announces is proven at login (pin mode)
        r = subprocess.run([harness["sc2_relay_sc2c_client"], "--pin", "127.0.0.1", str(mr.port), "chatd.test",
                            mr.key], capture_output=True, text=True, timeout=60)
        assert r.returncode == 0 and "PIN READY" in r.stdout, r.stdout + r.stderr
        import base64
        r = subprocess.run([harness["sc2_relay_sc2c_client"], "--pin", "127.0.0.1", str(mr.port), "chatd.test",
                            base64.b64encode(bytes(range(32))).decode()], capture_output=True, text=True, timeout=60)
        assert r.returncode == 0 and "PIN REFUSED" in r.stdout, r.stdout + r.stderr
    finally:
        mr.close()


def test_device_failover_to_c_minirelay(harness):
    """A device's chatd mini-relay as the fallback of a full relay: the
    same failover run as above (SPK-only X3DH there, the primary's mailbox
    after the return)."""
    mr = MiniRelay(harness["sc2_minirelay_server"], "chatd.fallback")

    async def body():
        async with relay_server(relay_id="relay.primary") as p:
            proc = await asyncio.create_subprocess_exec(harness["sc2_relay_sc2c_client"], "127.0.0.1",
                                                        str(p.ports["plain"]), "relay.primary",
                                                        str(mr.port), "chatd.fallback",
                                                        stdout=asyncio.subprocess.PIPE,
                                                        stderr=asyncio.subprocess.PIPE)
            out, err = await asyncio.wait_for(proc.communicate(), 120)
            text = out.decode()
            assert proc.returncode == 0, text + err.decode()
            assert "SC2C-MULTI OK" in text and text.strip().endswith("SC2C-RELAY OK")
    try:
        run(body())
    finally:
        mr.close()


class _Conn:
    def __init__(self, port):
        import socket
        self.s = socket.create_connection(("127.0.0.1", port), 5)
        self.f = self.s.makefile("rw")

    def send(self, fr):
        import json
        self.f.write(json.dumps(fr) + "\n")
        self.f.flush()

    def recv(self):
        import json
        ln = self.f.readline()
        return json.loads(ln) if ln else None

    def ask(self, fr):
        self.send(fr)
        return self.recv()

    def close(self):
        self.s.close()


def _login(port, relay_id, seed, admit=None):
    import base64
    from sc2proto import layouts
    from sc2_relay.crypto import SigningKey
    k = SigningKey(seed)
    c = _Conn(port)
    h = {"type": "hello", "v": 2, "proto": "sc2", "suites": [1]}
    if admit:
        h["admit"] = admit
    w = c.ask(h)
    ch = base64.b64decode(w["challenge"])
    a = c.ask({"type": "auth", "rid": "a", "ik": base64.b64encode(k.public).decode(),
               "sig": base64.b64encode(k.sign(layouts.auth_bytes(relay_id, ch, k.public))).decode()})
    return c, k, a


def test_c_minirelay_frames(harness):
    """Frame-level rules of the mini-relay: v1 hand-off (legacy on by
    default) or 426, hello first, bad auth signature, admission code,
    private rooms refused, the public history cap with sync.gap."""
    import base64
    import os as _os
    from sc2proto import layouts
    exe = harness["sc2_minirelay_server"]
    rid = "chatd.frames"
    mr = MiniRelay(exe, rid, admit="letmein")
    try:
        assert _lines(mr.port, [{"type": "hello", "user": "old"}], 1) == [{"type": "connected", "text": "v1 legacy"}]
        got = _lines(mr.port, [{"type": "sync"}], 1)
        assert got[0]["code"] == 401 and got[0]["err"] == "auth_required"
        hello = {"type": "hello", "v": 2, "proto": "sc2", "suites": [1], "nonce": base64.b64encode(bytes(16)).decode()}
        w = _lines(mr.port, [hello], 1)[0]
        assert w["type"] == "welcome" and w["relay"] == {"id": rid, "key": mr.key}
        assert w["legacy_v1"] is True and "relay_sig" in w
        assert w["limits"]["msg"] == 1024 and w["limits"]["queue"] == 12
        # bad signature, then a new device without the admission code
        c = _Conn(mr.port)
        c.ask({"type": "hello", "v": 2, "proto": "sc2"})
        e = c.ask({"type": "auth", "ik": base64.b64encode(bytes(32)).decode(),
                   "sig": base64.b64encode(bytes(64)).decode()})
        assert e["code"] == 401 and e["err"] == "bad_sig"
        c.close()
        seed = _os.urandom(32)
        c, k, a = _login(mr.port, rid, seed)
        assert a["code"] == 403 and a["err"] == "admit_required"
        c.close()
        c, k, a = _login(mr.port, rid, seed, admit="letmein")
        assert a["type"] == "authed" and a["new"] is True
        dev = a["device"]
        e = c.ask({"type": "room.join", "rid": "j", "room": "00" * 16})
        assert e["code"] == 501 and e["err"] == "not_supported"
        e = c.ask({"type": "room.join", "rid": "j", "room": "pub:other"})
        assert e["code"] == 404
        st = c.ask({"type": "room.join", "rid": "j", "room": "pub:general"})
        assert st["type"] == "room.state" and st["kind"] == "public" and st["limits"]["msg"] == 1024
        # history cap: 26 posts, 24 kept
        for i in range(26):
            post = {"s": 1, "t": "text", "from": dev, "ik": base64.b64encode(k.public).decode(),
                    "id": "%016x" % (i + 1), "ts": 1700000000 + i, "name": "t", "body": "post %d" % i}
            post["sig"] = base64.b64encode(k.sign(layouts.post_signed_bytes(rid, "pub:general", post))).decode()
            ack = c.ask({"type": "room.post", "rid": "p%d" % i, "room": "pub:general", "post": post})
            assert ack["type"] == "ack" and ack["seq"] == str(i + 1), ack
        again = c.ask({"type": "room.post", "rid": "d", "room": "pub:general", "post": post})
        assert again["seq"] == "26"  # dedup by (from, id)
        bad = dict(post, id="%016x" % 99, body="forged")
        e = c.ask({"type": "room.post", "rid": "b", "room": "pub:general", "post": bad})
        assert e["code"] == 401 and e["err"] == "bad_sig"
        c.send({"type": "sync", "rid": "y", "inbox": "0", "rooms": {"pub:general": "0"}, "max": 100})
        gap = c.recv()
        assert gap["type"] == "sync.gap" and gap["oldest"] == "3"
        seqs = []
        while True:
            fr = c.recv()
            if fr["type"] == "sync.done":
                break
            assert fr["type"] == "room.pub"
            seqs.append(int(fr["seq"]))
        assert seqs == list(range(3, 27)) and fr["rooms"] == {"pub:general": "26"} and fr["more"] is False
        # unknown recipient, DM to self stays within the caps
        e = c.ask({"type": "keys.claim", "rid": "k", "device": "ab" * 16})
        assert e["code"] == 404 and e["err"] == "unknown_device"
        c.close()
    finally:
        mr.close()
    mr = MiniRelay(exe, "chatd.nolegacy", legacy=False)
    try:
        got = _lines(mr.port, [{"type": "hello", "user": "old"}], 1)
        assert got[0]["code"] == 426 and got[0]["err"] == "upgrade_required"
        assert mr.size < 200 * 1024  # all stores, one PSRAM block
    finally:
        mr.close()
