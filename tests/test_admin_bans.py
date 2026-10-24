"""Operator admin interface: token auth, relay-signed removals, key and IP
bans with operator-set durations, mutes (self-host only), purge, tuning and
the CLI.

SPDX-License-Identifier: MIT
"""

import asyncio
import io

import sc2ref
from helpers import Clock, Device, PrivateRoom, admin, relay_server, run
from sc2_relay import admin as admin_cli
from sc2proto import b64d, frames

ROOM = "pub:general"


def relay_verify(srv, f):
    return sc2ref.ed_verify(srv.relay.key.public, frames.mod_signed_bytes_from_frame(f), b64d(f["sig"]))


def test_admin_requires_token_and_loopback():
    async def body():
        async with relay_server() as srv:
            st, b = await admin(srv, "GET", "/admin/status", token=None)
            assert st == 401
            st, b = await admin(srv, "GET", "/admin/status", token="wrong")
            assert st == 401
            st, b = await admin(srv, "GET", "/admin/status")
            assert st == 200 and b["relay_id"] == "relay.test" and b["schema"] == 5
            sock = srv.servers[-1].sockets[0].getsockname()
            assert sock[0] == "127.0.0.1"
        # the admin API is not served on the public HTTP port
        from helpers import free_port, http_get
        async with relay_server(http_port=free_port()) as srv:
            st, h, body = await http_get(srv.ports["http"], "/admin/status",
                                         {"Authorization": "Bearer test-admin-token"})
            assert st == 404
        async with relay_server(admin_token="") as srv:
            assert "admin" not in srv.ports
    run(body())


def test_remove_post_relay_signed():
    async def body():
        async with relay_server() as srv:
            port = srv.ports["plain"]
            ana, ben = Device(), Device()
            await ana.connect(port)
            await ben.connect(port)
            await ana.join(ROOM)
            await ben.join(ROOM)
            post = ana.post(ROOM, "illegal stuff")
            await ana.conn.request({"type": "room.post", "rid": "p", "room": ROOM, "post": post})
            await ben.conn.expect("room.pub")
            st, b = await admin(srv, "GET", "/admin/posts?room=general&q=illegal")
            assert st == 200 and b["posts"][0]["post"]["id"] == post["id"]
            st, b = await admin(srv, "POST", "/admin/remove", {"room": "general", "ref": post["id"]})
            assert st == 200 and b == {"removed": 1}
            mod = await ben.conn.expect("room.mod")
            assert mod["action"] == "remove" and mod["ref"] == post["id"] and mod["by"] == "relay"
            assert mod["device"] == ana.id  # message IDs are per author: the author is signed too
            assert mod["room"] == ROOM and relay_verify(srv, mod)
            assert set(mod) == {"type", "room", "seq", "action", "ts", "ref", "device", "by", "sig"}
            forged = dict(mod, ref="11" * 8)
            assert not relay_verify(srv, forged)
            assert not relay_verify(srv, dict(mod, device=ben.id))
            # removed posts disappear from sync; the signed removal is replayed instead
            items, done = await ben.sync(rooms={ROOM: "0"})
            assert [f["type"] for f in items] == ["room.mod"]
            st, b = await admin(srv, "POST", "/admin/remove", {"room": "general", "ref": post["id"]})
            assert st == 404
            st, b = await admin(srv, "POST", "/admin/remove", {"room": "general", "ref": "zz"})
            assert st == 400
    run(body())


def test_key_ban_announced_ip_ban_silent_and_expiry():
    async def body():
        clock = Clock()
        async with relay_server(clock=clock, public_rooms=["general", "solar-dev"]) as srv:
            port = srv.ports["plain"]
            bad, watcher = Device(), Device()
            await bad.connect(port)
            await watcher.connect(port)
            await bad.join(ROOM)
            await watcher.join(ROOM)
            post = bad.post(ROOM, "spam")
            await bad.conn.request({"type": "room.post", "rid": "p", "room": ROOM, "post": post})
            await watcher.conn.expect("room.pub")
            st, b = await admin(srv, "POST", "/admin/ban", {"device": bad.id, "duration": 3600, "reason": "illegal",
                                                           "remove_posts": True})
            until = int(clock()) + 3600
            assert st == 200 and b == {"until": until, "device": bad.id}
            rm = await watcher.conn.expect("room.mod", action="remove")
            assert rm["ref"] == post["id"] and rm["device"] == bad.id and relay_verify(srv, rm)
            ban = await watcher.conn.expect("room.mod", action="ban")
            assert ban["device"] == bad.id and ban["until"] == until and relay_verify(srv, ban)
            assert "ref" not in ban
            assert not relay_verify(srv, dict(ban, until=until + 1))
            e = await bad.send_post(ROOM, "more spam")
            assert e["code"] == 403 and e["err"] in ("not_member", "banned")
            e = await bad.join(ROOM)
            assert e["code"] == 403 and e["err"] == "banned" and e["until"] == until
            e = await bad.join("pub:solar-dev")
            assert e["err"] == "banned"
            # bans cover public rooms only: DMs and private rooms keep working
            room = PrivateRoom()
            ack = await room.create(bad)
            assert ack["type"] == "ack"
            await watcher.publish(3)
            bad.start_session(await bad.claim(watcher.id))
            env = bad.seal_dm(watcher.id, {"t": "text", "body": "dm still works"})
            assert (await bad.conn.request({"type": "dm.send", "rid": "d", "to": watcher.id, "env": env}))[
                "type"] == "ack"
            st, b = await admin(srv, "GET", "/admin/bans")
            assert [x["value"] for x in b["bans"]] == [bad.id]
            # expiry at until
            clock.advance(3601)
            st = await bad.join(ROOM)
            assert st["type"] == "room.state"
            assert (await bad.send_post(ROOM, "back"))["type"] == "ack"
            # an indefinite IP ban is silent and refuses every key from that address
            await watcher.conn.quiet()
            st, b = await admin(srv, "POST", "/admin/ban", {"ip": "127.0.0.1", "reason": "flood"})
            assert st == 200 and b["until"] is None
            got = await watcher.conn.quiet()
            assert not [f for f in got if f.get("type") == "room.mod"]
            fresh = Device()
            await fresh.connect(port)
            e = await fresh.join(ROOM)
            assert e["err"] == "banned" and e["until"] is None
            st, b = await admin(srv, "POST", "/admin/unban", {"ip": "127.0.0.1"})
            assert b == {"lifted": 1}
            assert (await fresh.join(ROOM))["type"] == "room.state"
            assert (await watcher.join(ROOM))["type"] == "room.state"  # the IP ban dropped it too
            # lifting a key ban early is announced like the ban (relay-signed unban)
            await admin(srv, "POST", "/admin/ban", {"device": fresh.id})
            assert (await fresh.send_post(ROOM, "x"))["code"] == 403
            ban = await watcher.conn.expect("room.mod", action="ban")
            assert ban["until"] is None and relay_verify(srv, ban)  # indefinite
            st, b = await admin(srv, "POST", "/admin/unban", {"device": fresh.id})
            assert b == {"lifted": 1}
            unban = await watcher.conn.expect("room.mod", action="unban")
            assert unban["device"] == fresh.id and "until" not in unban and "ref" not in unban
            assert relay_verify(srv, unban)
            assert (await fresh.join(ROOM))["type"] == "room.state"
            st, b = await admin(srv, "POST", "/admin/unban", {"device": fresh.id})
            assert b == {"lifted": 0}  # nothing to lift: no event
            assert not [f for f in await watcher.conn.quiet() if f.get("action") == "unban"]
            st, b = await admin(srv, "POST", "/admin/ban", {"device": fresh.id, "until": 5})
            assert st == 400
    run(body())


def test_mutes_only_when_enabled():
    async def body():
        async with relay_server() as srv:
            st, b = await admin(srv, "POST", "/admin/mute", {"device": "ab" * 16, "duration": 60})
            assert st == 501
        clock = Clock()
        async with relay_server(clock=clock, mutes=True) as srv:
            d = Device()
            await d.connect(srv.ports["plain"])
            await d.join(ROOM)
            st, b = await admin(srv, "POST", "/admin/mute", {"device": d.id, "duration": 60})
            assert st == 200
            e = await d.send_post(ROOM, "muted?")
            assert e["code"] == 403 and e["err"] == "muted" and e["until"] == int(clock()) + 60
            clock.advance(61)
            assert (await d.send_post(ROOM, "free"))["type"] == "ack"
    run(body())


def test_official_profile_rejects_mutes():
    import pytest
    from helpers import make_config
    from sc2_relay.config import ConfigError
    with pytest.raises(ConfigError):
        make_config("/tmp", profile="official", mutes=True)


def test_tune_admission_purge_rooms_and_cli():
    async def body():
        async with relay_server() as srv:
            port = srv.ports["plain"]
            st, b = await admin(srv, "POST", "/admin/tune", {"post_burst": 2, "bogus": 1})
            assert st == 400
            st, b = await admin(srv, "POST", "/admin/tune", {"post_burst": 2})
            assert st == 200 and srv.relay.cfg.post_burst == 2
            assert srv.relay.store.setting("tune.post_burst") == 2
            st, b = await admin(srv, "POST", "/admin/admission", {"mode": "code", "code": "letmein"})
            assert st == 200
            a = await Device().connect(port, sync=False)
            assert a["err"] == "admit_required"
            a = await Device().connect(port, admit="letmein")
            assert a["type"] == "authed"
            await admin(srv, "POST", "/admin/admission", {"mode": "open"})
            d = Device()
            await d.connect(port)
            await d.join(ROOM)
            st, b = await admin(srv, "GET", "/admin/rooms")
            assert {"room": "pub:general", "kind": "public", "members": 1} .items() <= b["rooms"][0].items()
            st, b = await admin(srv, "POST", "/admin/purge", {"device": d.id})
            assert st == 200
            assert await d.conn.closed()
            # the CLI talks to the same API (run in a thread: it uses blocking urllib)
            url = "http://127.0.0.1:%d" % srv.ports["admin"]
            out = io.StringIO()
            rc = await asyncio.get_running_loop().run_in_executor(
                None, lambda: admin_cli.run(["--url", url, "--token", "test-admin-token", "status"], out))
            assert rc == 0 and '"relay_id": "relay.test"' in out.getvalue()
            out = io.StringIO()
            rc = await asyncio.get_running_loop().run_in_executor(
                None, lambda: admin_cli.run(["--url", url, "--token", "nope", "bans"], out))
            assert rc == 1
            out = io.StringIO()
            rc = await asyncio.get_running_loop().run_in_executor(
                None, lambda: admin_cli.run(["--url", url, "--token", "test-admin-token", "ban", "--device",
                                             "cd" * 16, "--duration", "120", "--reason", "cli"], out))
            assert rc == 0 and srv.relay.store.ban_active("key", "cd" * 16, srv.relay.now())[0]
    run(body())
