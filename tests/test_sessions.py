"""Connection slots: one session per device key, idle sessions (pings do not
count), eviction of idle sessions when the relay is full, and the optional
session lifetime.

SPDX-License-Identifier: MIT
"""

from helpers import Clock, Conn, Device, relay_server, run


async def _closed_with(conn, code, err):
    f = await conn.expect("error", code=code)
    assert f["err"] == err, f
    assert await conn.closed()
    return f


def test_new_login_replaces_the_old_session():
    async def body():
        async with relay_server() as srv:
            port = srv.ports["plain"]
            a = Device()
            await a.connect(port)
            old = a.conn
            await a.connect(port)
            f = await _closed_with(old, 409, "replaced")
            assert "newer login" in f["text"]
            assert len(srv.relay.by_device[a.id]) == 1
            assert (await a.conn.request({"type": "ping", "rid": "p"}))["type"] == "pong"
            assert srv.relay.metrics["sessions_replaced_total"] == 1
            # another device is not affected
            b = Device()
            await b.connect(port)
            assert (await a.conn.request({"type": "ping", "rid": "p2"}))["type"] == "pong"
    run(body())


def test_pings_do_not_keep_a_session_alive():
    async def body():
        clock = Clock()
        async with relay_server(clock=clock, idle_timeout=300) as srv:
            port = srv.ports["plain"]
            a, b = Device(), Device()
            await a.connect(port)
            await b.connect(port)
            for i in range(5):
                clock.advance(100)
                assert (await a.conn.request({"type": "ping", "rid": "p%d" % i}))["type"] == "pong"
                # b stays active with real requests
                assert (await b.conn.request({"type": "room.list", "rid": "l%d" % i, "kind": "private"}))[
                    "type"] == "ack"
                srv.relay.sweep()
                if 100 * (i + 1) >= 300:
                    break
            await _closed_with(a.conn, 408, "idle")
            assert srv.relay.metrics["sessions_idle_closed_total"] == 1
            assert (await b.conn.request({"type": "ping", "rid": "pb"}))["type"] == "pong"
            assert a.id not in srv.relay.by_device
            # reconnecting works and starts a fresh idle period
            await a.connect(port)
            assert srv.relay.sweep() == 0
    run(body())


def test_auth_timeout_unchanged_for_pending_sessions():
    async def body():
        clock = Clock()
        async with relay_server(clock=clock, auth_timeout=1) as srv:
            c = await Conn.open(srv.ports["plain"])
            await c.send({"type": "hello", "v": 2, "proto": "sc2", "suites": [1], "client": "pytest/1"})
            assert (await c.recv())["type"] == "welcome"
            clock.advance(10000)
            assert srv.relay.sweep() == 0  # the sweep only handles established sessions
            assert await c.closed(timeout=5)
    run(body())


def test_full_relay_evicts_the_longest_idle_session_at_auth():
    async def body():
        clock = Clock()
        async with relay_server(clock=clock, max_connections=2, evict_min_idle=60) as srv:
            port = srv.ports["plain"]
            a, b, c = Device(), Device(), Device()
            await a.connect(port)
            clock.advance(10)
            await b.connect(port)
            # nobody idle long enough: refused at accept, as before
            x = await Conn.open(port)
            f = await x.recv()
            assert f["code"] == 503 and f["err"] == "server_full"
            assert await x.closed()
            # a has been idle the longest; it is closed only once c has authenticated
            clock.advance(100)
            assert (await b.conn.request({"type": "room.list", "rid": "l", "kind": "private"}))["type"] == "ack"
            raw = await Conn.open(port)
            await raw.send({"type": "hello", "v": 2, "proto": "sc2", "suites": [1], "client": "pytest/1"})
            assert (await raw.recv())["type"] == "welcome"
            assert len(srv.relay.by_device) == 2  # a handshake alone evicts no one
            raw.close()
            assert (await c.connect(port))["type"] == "authed"
            await _closed_with(a.conn, 503, "evicted")
            assert srv.relay.metrics["sessions_evicted_total"] == 1
            assert set(srv.relay.by_device) == {b.id, c.id}
            assert (await b.conn.request({"type": "ping", "rid": "pb"}))["type"] == "pong"
    run(body())


def test_full_relay_refuses_at_auth_when_everyone_is_active():
    async def body():
        clock = Clock()
        async with relay_server(clock=clock, max_connections=2, evict_min_idle=60) as srv:
            port = srv.ports["plain"]
            a, b, c = Device(), Device(), Device()
            await a.connect(port)
            await b.connect(port)
            clock.advance(100)
            raw = await Conn.open(port)  # admitted: a and b are idle long enough
            await a.conn.request({"type": "room.list", "rid": "la", "kind": "private"})
            await b.conn.request({"type": "room.list", "rid": "lb", "kind": "private"})
            f = await c.connect(port, conn=raw)
            assert f["code"] == 503 and f["err"] == "server_full"
            assert await raw.closed()
            assert set(srv.relay.by_device) == {a.id, b.id}
    run(body())


def test_per_ip_cap_evicts_from_the_same_ip():
    async def body():
        clock = Clock()
        async with relay_server(clock=clock, max_conn_per_ip=2, evict_min_idle=60) as srv:
            port = srv.ports["plain"]
            a, b, c = Device(), Device(), Device()
            await a.connect(port)
            await b.connect(port)
            clock.advance(61)
            await b.conn.request({"type": "room.list", "rid": "lb", "kind": "private"})
            assert (await c.connect(port))["type"] == "authed"
            await _closed_with(a.conn, 503, "evicted")
    run(body())


def test_max_session_lifetime():
    async def body():
        clock = Clock()
        async with relay_server(clock=clock, max_session_seconds=3600) as srv:
            a = Device()
            await a.connect(srv.ports["plain"])
            for i in range(3):
                clock.advance(1000)
                await a.conn.request({"type": "room.list", "rid": "l%d" % i, "kind": "private"})
                assert srv.relay.sweep() == 0
            clock.advance(700)
            await a.conn.request({"type": "room.list", "rid": "l9", "kind": "private"})
            assert srv.relay.sweep() == 1
            await _closed_with(a.conn, 503, "reconnect")
            assert srv.relay.metrics["sessions_expired_total"] == 1
        async with relay_server(clock=clock) as srv:  # off by default
            a = Device()
            await a.connect(srv.ports["plain"])
            clock.advance(10 ** 6)
            srv.relay.cfg.idle_timeout = 10 ** 7
            assert srv.relay.sweep() == 0
    run(body())


def test_legacy_v1_sessions_idle_out_with_a_v1_error():
    async def body():
        clock = Clock()
        async with relay_server(clock=clock, idle_timeout=300) as srv:
            c = await Conn.open(srv.ports["plain"])
            await c.send({"type": "hello", "user": "ana", "device": "sol"})
            assert (await c.recv())["type"] == "connected"
            clock.advance(299)
            assert srv.relay.sweep() == 0
            clock.advance(1)
            assert srv.relay.sweep() == 1
            f = await c.expect("error")
            assert f["code"] == 408 and "err" not in f
            assert await c.closed()
    run(body())
