"""Legacy v1 (chatd-compatible) chat: protocol behaviour, separate namespace,
426 on the official profile.

SPDX-License-Identifier: MIT
"""

from helpers import Conn, Device, relay_server, run

ROOM = "pub:general"


async def v1_client(port, user="ana", device="sol1", token=None):
    c = await Conn.open(port)
    hello = {"type": "hello", "user": user, "device": device}
    if token is not None:
        hello["token"] = token
    await c.send(hello)
    return c


def test_v1_connect_join_history_and_broadcast():
    async def body():
        async with relay_server() as srv:
            port = srv.ports["plain"]
            a = await v1_client(port)
            hello = await a.recv()
            assert hello["type"] == "connected" and hello["from"] == "chatd" and hello["text"] == "connected"
            assert isinstance(hello["ts"], int) and hello["ts"] == int(srv.relay.clock() * 1000)
            assert await a.recv() == {"type": "channel", "name": "general"}
            await a.send({"type": "join", "channel": "general"})
            assert await a.recv() == {"type": "channel", "name": "general"}
            j = await a.recv()
            assert j["type"] == "joined" and j["channel"] == "general" and j["from"] == "ana@sol1"
            await a.send({"type": "msg", "channel": "general", "text": "hello v1"})
            m = await a.recv()  # echoed back to the sender too
            assert m["type"] == "msg" and m["text"] == "hello v1" and m["from"] == "ana@sol1" and m["id"] == 1
            b = await v1_client(port, "ben", "")
            await b.expect("connected")
            await b.send({"type": "join", "channel": "general", "cursor": 0})
            j = await b.expect("joined")
            assert j["from"] == "ben"
            hist = await b.expect("msg")
            assert hist["text"] == "hello v1" and hist["id"] == 1
            p = await a.expect("presence")
            assert p["text"] == "joined" and p["from"] == "ben" and p["channel"] == "general"
            # cursor skips what the client already has
            c = await v1_client(port, "cat", "x")
            await c.expect("connected")
            await c.send({"type": "join", "channel": "general", "cursor": 1})
            await c.expect("joined")
            assert not [f for f in await c.quiet() if f["type"] == "msg"]
            await b.send({"type": "msg", "channel": "general", "text": "from ben"})
            assert (await a.expect("msg"))["text"] == "from ben"
            assert (await c.expect("msg"))["id"] == 2
            # new channels are announced to everyone
            await b.send({"type": "join", "channel": "dev"})
            assert (await a.expect("channel", name="dev"))
            await b.send({"type": "leave", "channel": "dev"})
            assert (await b.expect("left"))["channel"] == "dev"
            await b.send({"type": "delete", "channel": "dev"})
            d = await a.expect("deleted")
            assert d["channel"] == "dev" and d["from"] == "ben"
            # disconnect -> presence left
            c.close()
            assert (await a.expect("presence", text="left"))["from"] == "cat@x"
    run(body())


def test_v1_errors_match_chatd():
    async def body():
        async with relay_server() as srv:
            port = srv.ports["plain"]
            a = await v1_client(port)
            await a.expect("connected")
            await a.quiet()
            cases = [
                ({"type": "msg", "channel": "general"}, 400, "missing text"),
                ({"type": "msg", "channel": "general", "text": "x"}, 403, "not joined"),
                ({"type": "msg", "channel": "zzz", "text": "x"}, 404, "unknown channel"),
                ({"type": "leave", "channel": "zzz"}, 404, "unknown channel"),
                ({"type": "delete"}, 400, "missing channel"),
                ({"type": "delete", "channel": "general"}, 403, "default channel cannot be deleted"),
                ({"type": "join", "channel": "bad name"}, 400, "invalid or full channel"),
                ({"type": "join", "channel": "a/b"}, 400, "invalid or full channel"),
                ({"type": "frobnicate"}, 400, "unknown type"),
                ({"channel": "x"}, 400, "missing type"),
                ({"type": "auth", "ik": "x"}, 400, "unknown type"),  # a v2 frame on v1 is unknown
                ({"type": "msg", "channel": "general", "text": "x" * 4096}, 400, "missing text"),
            ]
            for frame, code, text in cases:
                await a.send(frame)
                e = await a.recv()
                assert e["type"] == "error" and e["code"] == code and e["text"] == text, (frame, e)
            await a.send("not json")
            assert (await a.recv())["text"] == "missing type"
            # line too long -> 413 and close
            await a.send(b"x" * 26000 + b"\n")
            e = await a.recv()
            assert e["code"] == 413 and e["text"] == "line too long"
            assert await a.closed()
    run(body())


def test_v1_token_and_hello_required():
    async def body():
        async with relay_server(legacy_v1_token="t0ken") as srv:
            port = srv.ports["plain"]
            a = await v1_client(port, token="wrong")
            e = await a.recv()
            assert e == {"type": "error", "text": "auth failed", "code": 401}
            assert await a.closed()
            a = await v1_client(port, token="t0ken")
            assert (await a.recv())["type"] == "connected"
            c = await Conn.open(port)
            await c.send({"type": "join", "channel": "general"})
            e = await c.recv()
            assert e["code"] == 401 and e["text"] == "hello required"
            assert await c.closed()
    run(body())


def test_v1_and_v2_namespaces_are_never_bridged():
    async def body():
        async with relay_server() as srv:
            port = srv.ports["plain"]
            v1 = await v1_client(port)
            await v1.expect("connected")
            await v1.send({"type": "join", "channel": "general"})
            await v1.expect("joined")
            d = Device()
            await d.connect(port)
            await d.join(ROOM)
            await v1.send({"type": "msg", "channel": "general", "text": "v1 text"})
            await v1.expect("msg")
            assert not [f for f in await d.conn.quiet() if f.get("type") in ("room.pub", "msg")]
            ack = await d.send_post(ROOM, "v2 signed text")
            assert ack["type"] == "ack"
            assert not [f for f in await v1.quiet() if f.get("type") == "msg"]
            items, done = await d.sync(rooms={ROOM: "0"})
            assert [f["post"]["body"] for f in items if f["type"] == "room.pub"] == ["v2 signed text"]
            assert srv.relay.store.scalar("SELECT COUNT(*) FROM v1_log") == 1
            assert srv.relay.store.scalar("SELECT COUNT(*) FROM public_log") == 1
    run(body())


def test_v1_disabled_answers_426():
    async def body():
        async with relay_server(profile="official", legacy_v1=False, web_view=True) as srv:
            port = srv.ports["plain"]
            a = await v1_client(port)
            e = await a.recv()
            assert e["type"] == "error" and e["code"] == 426 and e["err"] == "upgrade_required"
            assert await a.closed()
            d = Device()
            await d.connect(port)
            assert d.welcome["legacy_v1"] is False
        async with relay_server(legacy_v1=False) as srv:
            a = await v1_client(srv.ports["plain"])
            assert (await a.recv())["code"] == 426
    run(body())


def test_v1_history_retention():
    async def body():
        async with relay_server(v1_history=3) as srv:
            a = await v1_client(srv.ports["plain"])
            await a.expect("connected")
            await a.send({"type": "join"})
            await a.expect("joined")
            for i in range(5):
                await a.send({"type": "msg", "text": "m%d" % i})
                await a.expect("msg", text="m%d" % i)
            b = await v1_client(srv.ports["plain"], "b")
            await b.expect("connected")
            await b.send({"type": "join"})
            await b.expect("joined")
            got = [f["text"] for f in await b.quiet() if f["type"] == "msg"]
            assert got == ["m2", "m3", "m4"]
            srv.relay.retention()
            assert srv.relay.store.scalar("SELECT COUNT(*) FROM v1_log") == 3
    run(body())
