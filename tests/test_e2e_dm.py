"""End-to-end DMs through the relay with sc2ref devices: handshake, key
directory, X3DH + double ratchet, store-and-forward, quotas, TTL.

SPDX-License-Identifier: MIT
"""

from helpers import Clock, Conn, Device, b64d, b64e, layouts, relay_server, run
import sc2ref


def test_handshake_welcome_and_authed():
    async def body():
        async with relay_server() as srv:
            d = Device()
            a = await d.connect(srv.ports["plain"])
            assert a["type"] == "authed" and a["device"] == d.id and a["new"] is True
            assert a["server_time"] == int(srv.relay.clock())
            w = d.welcome
            assert w["v"] == 2 and w["proto"] == "sc2" and w["suite"] == 1
            assert w["relay"] == {"id": "relay.test", "key": b64e(srv.relay.key.public)}
            assert len(b64d(w["challenge"])) == 32
            assert w["legacy_v1"] is True
            assert w["limits"] == {"line": 16384, "msg": 4096, "rooms": 64, "members": 32, "queue": 500,
                                   "queue_bytes": 5242880, "ttl_days": 7}
            d.conn.close()
            d2 = Device()
            d2.ident = d.ident
            d2.id = d.id
            a = await d2.connect(srv.ports["plain"])
            assert a["new"] is False
            pong = await d2.conn.request({"type": "ping", "rid": "p"})
            assert pong == {"type": "pong", "rid": "p"}
    run(body())


def test_auth_failures():
    async def body():
        async with relay_server() as srv:
            port = srv.ports["plain"]
            # bad challenge signature -> 401 bad_sig and close
            c = await Conn.open(port)
            await c.send({"type": "hello", "v": 2, "proto": "sc2", "suites": [1]})
            w = await c.recv()
            d = Device()
            bad = d.sign(b"not the challenge")
            await c.send({"type": "auth", "ik": b64e(d.ident.ik_pub), "sig": b64e(bad)})
            e = await c.recv()
            assert e["type"] == "error" and e["code"] == 401 and e["err"] == "bad_sig"
            assert await c.closed()
            # a signature for another relay id is rejected too
            c = await Conn.open(port)
            await c.send({"type": "hello", "v": 2, "proto": "sc2", "suites": [1]})
            w = await c.recv()
            sig = d.sign(sc2ref.auth_bytes("other.relay", b64d(w["challenge"]), d.ident.ik_pub))
            await c.send({"type": "auth", "ik": b64e(d.ident.ik_pub), "sig": b64e(sig)})
            assert (await c.recv())["err"] == "bad_sig"
            # frames before auth -> 401 auth_required (connection stays open)
            c = await Conn.open(port)
            await c.send({"type": "hello", "v": 2, "proto": "sc2", "suites": [1]})
            await c.recv()
            e = await c.request({"type": "keys.claim", "rid": "x", "device": "00" * 16})
            assert e["code"] == 401 and e["err"] == "auth_required"
            # no common suite
            c = await Conn.open(port)
            await c.send({"type": "hello", "v": 2, "proto": "sc2", "suites": [9]})
            e = await c.recv()
            assert e["code"] == 501 and e["err"] == "not_supported"
            # first frame not a hello
            c = await Conn.open(port)
            await c.send({"type": "auth", "ik": "x", "sig": "y"})
            e = await c.recv()
            assert e["code"] == 401 and e["text"] == "hello required"
            assert await c.closed()
    run(body())


def test_admission_code_and_allowlist():
    async def body():
        async with relay_server(admission="code", admit_code="sesame") as srv:
            d = Device()
            a = await d.connect(srv.ports["plain"], sync=False)
            assert a["code"] == 403 and a["err"] == "admit_required"
            a = await Device().connect(srv.ports["plain"], admit="wrong", sync=False)
            assert a["err"] == "admit_required"
            a = await d.connect(srv.ports["plain"], admit="sesame")
            assert a["type"] == "authed" and a["new"]
            # registered devices no longer need the code
            a = await d.connect(srv.ports["plain"])
            assert a["type"] == "authed" and not a["new"]
        ok = Device()
        async with relay_server(admission="allowlist", allowlist=[ok.id]) as srv:
            assert (await ok.connect(srv.ports["plain"]))["type"] == "authed"
            a = await Device().connect(srv.ports["plain"], sync=False)
            assert a["err"] == "admit_required"
    run(body())


def test_dm_roundtrip_offline_and_live():
    async def body():
        async with relay_server() as srv:
            port = srv.ports["plain"]
            alice, bob = Device(), Device()
            await alice.connect(port)
            await bob.connect(port)
            ack = await bob.publish(10)
            assert ack == {"type": "ack", "rid": ack["rid"], "opks": 10}
            ack = await alice.publish(10)
            bob.conn.close()

            bundle = await alice.claim(bob.id)
            assert bundle["type"] == "keys.bundle" and bundle["device"] == bob.id
            assert bundle["opk"]["id"] == 100  # lowest OPK first
            alice.start_session(bundle)
            env = alice.seal_dm(bob.id, {"t": "text", "id": "0123456789abcdef", "body": "hi bob", "ts": 1})
            ack = await alice.conn.request({"type": "dm.send", "rid": "d1", "to": bob.id, "env": env})
            assert ack["type"] == "ack" and ack["seq"] == "1"
            # resend of the same envelope is deduplicated by (from, rk, n)
            again = await alice.conn.request({"type": "dm.send", "rid": "d2", "to": bob.id, "env": env})
            assert again["seq"] == "1"

            # bob comes back: sync streams the inbox
            await bob.connect(port, sync=False)
            items, done = await bob.sync()
            assert [f["type"] for f in items] == ["dm.msg"]
            assert items[0]["seq"] == "1" and items[0]["env"] == env
            assert done["inbox"] == "1" and done["more"] is False
            a_bundle = await bob.claim(alice.id)
            peer = {"ik": b64d(a_bundle["ik"]), "dk": b64d(a_bundle["dk"]), "dk_sig": b64d(a_bundle["dk_sig"])}
            inner = bob.open_dm(items[0]["env"], peer)
            assert inner["body"] == "hi bob"
            await bob.conn.send({"type": "ack", "inbox": "1"})
            items, done = await bob.sync()
            assert items == [] and done["inbox"] == "0"

            # live delivery after sync: bob replies, alice gets dm.msg pushed
            env2 = bob.seal_dm(alice.id, {"t": "text", "id": "1111111111111111", "body": "hi alice", "ts": 2})
            ack = await bob.conn.request({"type": "dm.send", "rid": "d3", "to": alice.id, "env": env2})
            assert ack["seq"] == "1"
            msg = await alice.conn.expect("dm.msg")
            assert alice.open_dm(msg["env"])["body"] == "hi alice"
            # ratchet keeps going both ways
            env3 = alice.seal_dm(bob.id, {"t": "text", "id": "2222222222222222", "body": "again", "ts": 3})
            await alice.conn.request({"type": "dm.send", "rid": "d4", "to": bob.id, "env": env3})
            msg = await bob.conn.expect("dm.msg")
            assert bob.open_dm(msg["env"])["body"] == "again"
            # the relay stored only the opaque envelope
            rows = srv.relay.store.all("SELECT data FROM inbox")
            assert all("hi bob" not in r["data"] and "again" not in r["data"] for r in rows)
    run(body())


def test_dm_rejections():
    async def body():
        async with relay_server() as srv:
            port = srv.ports["plain"]
            a, b = Device(), Device()
            await a.connect(port)
            await b.connect(port)
            await b.publish(1)
            a.start_session(await a.claim(b.id))
            env = a.seal_dm(b.id, {"t": "text", "body": "x"})
            e = await a.conn.request({"type": "dm.send", "rid": "u", "to": "ab" * 16, "env": env})
            assert e["code"] == 404 and e["err"] == "unknown_device"
            forged = dict(env, **{"from": b.id})
            e = await a.conn.request({"type": "dm.send", "rid": "f", "to": b.id, "env": forged})
            assert e["code"] == 403
            bad = dict(env, ct=b64e(b"\x00" * 100))
            e = await a.conn.request({"type": "dm.send", "rid": "c", "to": b.id, "env": bad})
            assert e["code"] == 400
            e = await a.conn.request({"type": "dm.send", "rid": "c2", "to": b.id,
                                      "env": dict(env, ct=b64e(b"\x00" * (8192 + 17)))})
            assert e["code"] == 413 and e["err"] == "too_large"
            e = await a.conn.request({"type": "nope", "rid": "n"})
            assert e["code"] == 400 and e["err"] == "bad_request"
            e = await a.conn.request({"type": "keys.publish", "rid": "k", "dk": b64e(a.ident.dk_pub),
                                      "dk_sig": b64e(bytes(64)),
                                      "spk": {"id": 1, "pub": b64e(a.spk.pub), "sig": b64e(a.spk.sig)}})
            assert e["code"] == 401 and e["err"] == "bad_sig"
    run(body())


def test_prekey_exhaustion_and_keys_low():
    async def body():
        async with relay_server() as srv:
            port = srv.ports["plain"]
            a, b = Device(), Device()
            await a.connect(port)
            await b.connect(port)
            await b.publish(1)
            first = await a.claim(b.id)
            assert "opk" in first
            low = await b.conn.expect("keys.low")
            assert low == {"type": "keys.low", "remaining": 0}
            rid = a.rid()
            await a.conn.send({"type": "keys.claim", "rid": rid, "device": b.id})
            bundle = await a.conn.recv()
            assert bundle["type"] == "keys.bundle" and "opk" not in bundle  # SPK-only fallback
            err = await a.conn.recv()
            assert err["type"] == "error" and err["code"] == 410 and err["err"] == "prekey_exhausted"
            assert err["rid"] == rid
            # SPK-only X3DH still works end to end
            a.start_session(bundle)
            env = a.seal_dm(b.id, {"t": "text", "body": "spk only"})
            await a.conn.request({"type": "dm.send", "rid": "d", "to": b.id, "env": env})
            msg = await b.conn.expect("dm.msg")
            peer = await b.claim(a.id)
            assert peer["code"] == 404  # a never published a bundle
            await a.publish(0)
            peer = await b.claim(a.id)
            assert b.open_dm(msg["env"], {"ik": b64d(peer["ik"]), "dk": b64d(peer["dk"]),
                                          "dk_sig": b64d(peer["dk_sig"])})["body"] == "spk only"
            # on reconnect a device below the threshold gets keys.low after authed
            b.conn.close()
            await b.connect(port, sync=False)
            assert (await b.conn.expect("keys.low"))["remaining"] == 0
            # the OPK cap is 100 per device
            e = await b.conn.request({"type": "keys.publish", "rid": "big", "dk": b64e(b.ident.dk_pub),
                                      "dk_sig": b64e(b.ident.dk_sig),
                                      "spk": {"id": 1, "pub": b64e(b.spk.pub), "sig": b64e(b.spk.sig)},
                                      "opks": [{"id": i, "pub": b64e(bytes(32))} for i in range(101)]})
            assert e["code"] == 413
            for _ in range(3):
                ack = await b.publish(40)
            assert ack["opks"] == 100
    run(body())


def test_inbox_full_507_and_bytes_cap():
    async def body():
        async with relay_server(max_queue=3) as srv:
            port = srv.ports["plain"]
            a, b = Device(), Device()
            await a.connect(port)
            await b.connect(port)
            await b.publish(1)
            b.conn.close()
            a.start_session(await a.claim(b.id))
            for i in range(3):
                env = a.seal_dm(b.id, {"t": "text", "body": "m%d" % i})
                assert (await a.conn.request({"type": "dm.send", "rid": "s%d" % i, "to": b.id, "env": env}))[
                    "type"] == "ack"
            env = a.seal_dm(b.id, {"t": "text", "body": "overflow"})
            e = await a.conn.request({"type": "dm.send", "rid": "s9", "to": b.id, "env": env})
            assert e["code"] == 507 and e["err"] == "inbox_full" and e["to"] == b.id
            # after bob acks, the sender's retry goes through
            await b.connect(port, sync=False)
            items, done = await b.sync()
            assert len(items) == 3
            await b.conn.send({"type": "ack", "inbox": done["inbox"]})
            await b.conn.request({"type": "ping", "rid": "sync-point"})
            ok = await a.conn.request({"type": "dm.send", "rid": "s10", "to": b.id, "env": env})
            assert ok["type"] == "ack" and ok["seq"] == "4"
        async with relay_server(max_queue_bytes=4096) as srv:
            port = srv.ports["plain"]
            a, b = Device(), Device()
            await a.connect(port)
            await b.connect(port)
            await b.publish(1)
            b.conn.close()
            a.start_session(await a.claim(b.id))
            sent = 0
            while True:
                env = a.seal_dm(b.id, {"t": "text", "body": "x" * 600})
                f = await a.conn.request({"type": "dm.send", "rid": "b%d" % sent, "to": b.id, "env": env})
                if f["type"] == "error":
                    assert f["code"] == 507
                    break
                sent += 1
            n, size = srv.relay.store.inbox_stats(b.id)
            assert n == sent and size <= 4096 and sent >= 1
    run(body())


def test_inbox_ttl_expiry_and_sync_paging():
    async def body():
        clock = Clock()
        async with relay_server(clock=clock) as srv:
            port = srv.ports["plain"]
            a, b = Device(), Device()
            await a.connect(port)
            await b.connect(port)
            await b.publish(1)
            b.conn.close()
            a.start_session(await a.claim(b.id))
            for i in range(5):
                env = a.seal_dm(b.id, {"t": "text", "body": "m%d" % i})
                await a.conn.request({"type": "dm.send", "rid": "s%d" % i, "to": b.id, "env": env})
            await b.connect(port, sync=False)
            items, done = await b.sync(max_=2)
            assert [f["seq"] for f in items] == ["1", "2"] and done["more"] is True and done["inbox"] == "2"
            items, done = await b.sync(inbox="2", max_=2)
            assert [f["seq"] for f in items] == ["3", "4"] and done["more"] is True
            b.conn.close()
            clock.advance(7 * 86400 + 1)
            out = srv.relay.retention()
            assert out["inbox"] == 5
            await b.connect(port, sync=False)
            items, done = await b.sync(inbox="4")
            assert items == [] and done["more"] is False
    run(body())


def test_purged_device_is_refused():
    async def body():
        async with relay_server() as srv:
            d = Device()
            await d.connect(srv.ports["plain"])
            srv.relay.purge_device(d.id)
            assert await d.conn.closed()
            a = await d.connect(srv.ports["plain"], sync=False)
            assert a["code"] == 403
    run(body())


def test_auth_signed_bytes_match_layouts():
    d = Device()
    ch = bytes(range(32))
    assert sc2ref.auth_bytes("relay.x", ch, d.ident.ik_pub) == layouts.auth_bytes("relay.x", ch, d.ident.ik_pub)
