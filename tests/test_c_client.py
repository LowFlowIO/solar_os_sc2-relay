"""Host interop test: the C protocol/sc2 core and the SolarOS SC2 engine,
built with gcc into a small harness, talk to this Python relay over TCP.
Skipped when gcc is not available.

SPDX-License-Identifier: MIT
"""

import asyncio
import os
import shutil
import subprocess

import pytest

from helpers import relay_server, run

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
SC2 = os.path.join(REPO, "protocol", "sc2")
ED = os.path.join(REPO, "src", "vendor", "meshcore", "ed25519")
WG = os.path.join(REPO, "components", "wireguard_lwip", "src")
SVC = os.path.join(REPO, "src", "services")

pytestmark = pytest.mark.skipif(shutil.which(os.environ.get("CC", "gcc")) is None, reason="no C compiler")


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
                        ("sc2_relay_sc2c_client", [os.path.join(SVC, "solar_os_sc2_client.c")])):
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
