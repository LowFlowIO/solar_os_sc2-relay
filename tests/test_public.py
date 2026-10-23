"""Public rooms: signed posts verified on ingest, dedup, author-only delete,
body limits, rate limits and slow mode, first-join notice, retention, gaps,
reports and creation policy.

SPDX-License-Identifier: MIT
"""

import sc2ref
from helpers import Clock, Device, admin, relay_server, run
from sc2_relay.core import PUBLIC_LABEL, PUBLIC_NOTICE

ROOM = "pub:general"


def test_list_join_notice_and_label():
    async def body():
        async with relay_server(public_rooms=["pub:general", "pub:solar-dev"]) as srv:
            d = Device()
            await d.connect(srv.ports["plain"])
            rid = d.rid()
            await d.conn.send({"type": "room.list", "rid": rid, "kind": "public"})
            states = [await d.conn.recv(), await d.conn.recv()]
            end = await d.conn.recv()
            assert [s["room"] for s in states] == ["pub:general", "pub:solar-dev"]
            assert all(s["type"] == "room.state" and s["kind"] == "public" and s["label"] == PUBLIC_LABEL
                       for s in states)
            assert states[0]["title"] == "#general" and states[0]["limits"] == {"msg": 1024, "per_min": 10}
            assert end == {"type": "ack", "rid": rid, "count": 2}
            st = await d.join(ROOM)
            assert st["type"] == "room.state" and st["first_join"] is True and st["notice"] == PUBLIC_NOTICE
            assert st["label"] == "PUBLIC \u00b7 not encrypted" and st["members_count"] == 1
            await d.conn.request({"type": "room.leave", "rid": "l", "room": ROOM})
            st = await d.join(ROOM)
            assert st["first_join"] is False and "notice" not in st
            e = await d.join("pub:nope")
            assert e["code"] == 404 and e["err"] == "unknown_room"
    run(body())


def test_post_ingest_pipeline():
    async def body():
        async with relay_server() as srv:
            port = srv.ports["plain"]
            ana, ben = Device(), Device()
            await ana.connect(port)
            await ben.connect(port)
            e = await ana.send_post(ROOM, "not joined yet")
            assert e["code"] == 403 and e["err"] == "not_member"
            await ana.join(ROOM)
            await ben.join(ROOM)
            post = ana.post(ROOM, "hello #general")
            ack = await ana.conn.request({"type": "room.post", "rid": "p", "room": ROOM, "post": post})
            assert ack["type"] == "ack" and ack["seq"] == "1"
            pub = await ben.conn.expect("room.pub")
            assert pub == {"type": "room.pub", "room": ROOM, "seq": "1", "post": post}
            assert sc2ref.ed_verify(sc2ref.unb64(post["ik"]), sc2ref.post_signed_bytes("relay.test", ROOM, post),
                                    sc2ref.unb64(post["sig"]))
            # dedup (from, id): the same post is acked with its first seq and not fanned out again
            again = await ana.conn.request({"type": "room.post", "rid": "p2", "room": ROOM, "post": post})
            assert again["seq"] == "1"
            assert not [f for f in await ben.conn.quiet() if f.get("type") == "room.pub"]
            # signature bound to the relay ID and the room
            e = await ana.send_post(ROOM, "for another relay", relay_id="other.relay")
            assert e["code"] == 401 and e["err"] == "bad_sig"
            p = ana.post("pub:other", "for another room")
            e = await ana.conn.request({"type": "room.post", "rid": "r", "room": ROOM, "post": p})
            assert e["code"] == 401
            tampered = dict(ana.post(ROOM, "original"), body="tampered")
            e = await ana.conn.request({"type": "room.post", "rid": "t", "room": ROOM, "post": tampered})
            assert e["err"] == "bad_sig"
            # from must match ik, and the key must be the session's own
            p = ana.post(ROOM, "x")
            p["from"] = ben.id
            e = await ana.conn.request({"type": "room.post", "rid": "f", "room": ROOM, "post": p})
            assert e["code"] == 400
            e = await ana.conn.request({"type": "room.post", "rid": "o", "room": ROOM, "post": ben.post(ROOM, "x")})
            assert e["code"] == 403
            # unknown post type
            e = await ana.conn.request({"type": "room.post", "rid": "u", "room": ROOM,
                                        "post": dict(ana.post(ROOM, "x"), t="edit")})
            assert e["code"] == 400
            # del is honoured only for the author
            e = await ben.conn.request({"type": "room.post", "rid": "d0", "room": ROOM,
                                        "post": ben.post(ROOM, "", t="del", ref=post["id"])})
            assert e["code"] == 403
            ack = await ana.conn.request({"type": "room.post", "rid": "d1", "room": ROOM,
                                          "post": ana.post(ROOM, "", t="del", ref=post["id"])})
            assert ack["type"] == "ack"
            dl = await ben.conn.expect("room.pub")
            assert dl["post"]["t"] == "del" and dl["post"]["ref"] == post["id"]
            # unknown fields are dropped before storing and forwarding
            p = dict(ana.post(ROOM, "clean"), extra="unsigned junk")
            await ana.conn.request({"type": "room.post", "rid": "j", "room": ROOM, "post": p})
            got = await ben.conn.expect("room.pub")
            assert "extra" not in got["post"]
    run(body())


def test_body_limit_and_slow_mode_for_young_keys():
    async def body():
        clock = Clock()
        async with relay_server(clock=clock, slow_key_minutes=10) as srv:
            port = srv.ports["plain"]
            d = Device()
            await d.connect(port)
            st = await d.join(ROOM)
            assert st["limits"] == {"msg": 256, "per_min": 2}  # young key
            e = await d.send_post(ROOM, "x" * 257)
            assert e["code"] == 413 and e["limit"] == 256
            assert (await d.send_post(ROOM, "first"))["type"] == "ack"
            e = await d.send_post(ROOM, "second")  # slow burst is 1
            assert e["code"] == 429 and e["err"] == "rate_limited" and e["retry_ms"] > 0
            clock.advance(11 * 60)
            st = await d.conn.request({"type": "room.members", "rid": "m", "room": ROOM})
            assert st["limits"] == {"msg": 1024, "per_min": 10}
            assert (await d.send_post(ROOM, "y" * 1024))["type"] == "ack"
            e = await d.send_post(ROOM, "y" * 1025)
            assert e["code"] == 413
            # body bytes are counted in UTF-8
            e = await d.send_post(ROOM, "\u00e9" * 513)
            assert e["code"] == 413
    run(body())


def test_rate_limits_per_key_and_room_slow_mode():
    async def body():
        clock = Clock()
        async with relay_server(clock=clock) as srv:
            port = srv.ports["plain"]
            d = Device()
            await d.connect(port)
            await d.join(ROOM)
            results = [(await d.send_post(ROOM, "m%d" % i))["type"] for i in range(6)]
            assert results == ["ack"] * 5 + ["error"]  # burst 5
            clock.advance(6)  # 10/min -> one token per 6 s
            assert (await d.send_post(ROOM, "later"))["type"] == "ack"
            # operator slow mode for the whole room
            st, b = await admin(srv, "POST", "/admin/slowmode", {"room": "general", "on": True})
            assert st == 200 and b == {"room": "pub:general", "slow": True}
            clock.advance(3600)
            assert (await d.send_post(ROOM, "slow 1"))["type"] == "ack"
            e = await d.send_post(ROOM, "slow 2")
            assert e["code"] == 429
            e2 = await d.send_post(ROOM, "z" * 300)
            assert e2["code"] == 413
            await admin(srv, "POST", "/admin/slowmode", {"room": "general", "on": False})
            clock.advance(3600)
            assert (await d.send_post(ROOM, "normal again"))["type"] == "ack"
            # per-IP limit covers many keys from one address
            await admin(srv, "POST", "/admin/tune", {"ip_post_burst": 3, "ip_post_per_min": 3})
            srv.relay.post_ip.buckets.clear()
            clock.advance(3600)
            keys = [Device() for _ in range(4)]
            out = []
            for k in keys:
                await k.connect(port)
                await k.join(ROOM)
                out.append((await k.send_post(ROOM, "hi"))["type"])
            assert out == ["ack", "ack", "ack", "error"]
    run(body())


def test_public_retention_cap_and_sync_gap():
    async def body():
        clock = Clock()
        async with relay_server(clock=clock, public_log_max=5, post_burst=100, ip_post_burst=100) as srv:
            port = srv.ports["plain"]
            d = Device()
            await d.connect(port)
            await d.join(ROOM)
            for i in range(8):
                await d.send_post(ROOM, "p%d" % i)
            srv.relay.retention()
            r = Device()
            await r.connect(port)
            await r.join(ROOM)
            items, done = await r.sync(rooms={ROOM: "1"})
            gap = [f for f in items if f["type"] == "sync.gap"]
            assert gap == [{"type": "sync.gap", "room": ROOM, "from": "1", "oldest": "4"}]
            pubs = [f for f in items if f["type"] == "room.pub"]
            assert [p["seq"] for p in pubs] == ["4", "5", "6", "7", "8"]
            assert done["rooms"] == {ROOM: "8"}
            # TTL: 7 days
            clock.advance(7 * 86400 + 5)
            srv.relay.retention()
            items, done = await r.sync(rooms={ROOM: "8"})
            assert [f for f in items if f["type"] == "room.pub"] == []
            assert srv.relay.store.scalar("SELECT COUNT(*) FROM public_log") == 0
    run(body())


def test_public_history_for_newcomers_and_paging():
    async def body():
        async with relay_server(post_burst=100, ip_post_burst=100) as srv:
            port = srv.ports["plain"]
            d = Device()
            await d.connect(port)
            await d.join(ROOM)
            for i in range(5):
                await d.send_post(ROOM, "p%d" % i)
            n = Device()
            await n.connect(port)
            await n.join(ROOM)
            items, done = await n.sync(rooms={ROOM: "0"}, max_=3)
            assert [f["seq"] for f in items if f["type"] == "room.pub"] == ["1", "2", "3"] and done["more"]
            items, done = await n.sync(rooms={ROOM: done["rooms"][ROOM]})
            assert [f["seq"] for f in items if f["type"] == "room.pub"] == ["4", "5"] and not done["more"]
    run(body())


def test_reports_and_creation_policy():
    async def body():
        async with relay_server() as srv:
            port = srv.ports["plain"]
            d = Device()
            await d.connect(port)
            await d.join(ROOM)
            post = d.post(ROOM, "report me")
            await d.conn.request({"type": "room.post", "rid": "p", "room": ROOM, "post": post})
            ack = await d.conn.request({"type": "room.report", "rid": "r", "room": ROOM, "ref": post["id"],
                                        "reason": "illegal"})
            assert ack["type"] == "ack"
            e = await d.conn.request({"type": "room.report", "rid": "r2", "room": ROOM, "ref": "00" * 8})
            assert e["code"] == 400
            st, b = await admin(srv, "GET", "/admin/reports")
            assert st == 200 and b["reports"][0]["ref"] == post["id"] and b["reports"][0]["reason"] == "illegal"
            st, b = await admin(srv, "POST", "/admin/reports/resolve", {"id": b["reports"][0]["id"]})
            assert st == 200
            assert (await admin(srv, "GET", "/admin/reports"))[1]["reports"] == []
            e = await d.conn.request({"type": "room.create", "rid": "c", "room": "pub:mine", "kind": "public"})
            assert e["code"] == 403 and e["err"] == "forbidden"
        async with relay_server(public_room_create="any") as srv:
            d = Device()
            await d.connect(srv.ports["plain"])
            ack = await d.conn.request({"type": "room.create", "rid": "c", "room": "pub:mine", "kind": "public",
                                        "title": "#mine"})
            assert ack["type"] == "ack"
            st = await d.join("pub:mine")
            assert st["title"] == "#mine" and st["first_join"]
            # the creator gets no moderation powers: admin API is the only remover
            assert srv.relay.store.room("pub:mine")["kind"] == "public"
    run(body())
