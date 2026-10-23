"""Private rooms: genesis and admin-signed commits, invites and join
requests, ciphertext-only routing, no history for newcomers, removal notices,
leave rules and the member cap.

SPDX-License-Identifier: MIT
"""

import os

import sc2ref
from helpers import Device, PrivateRoom, b64e, layouts, relay_server, run
from sc2proto import b64d


async def setup_room(port, n_members=1):
    admin = Device()
    await admin.connect(port)
    others = []
    for _ in range(n_members - 1):
        d = Device()
        await d.connect(port)
        others.append(d)
    room = PrivateRoom()
    g = room.genesis(admin, [d.id for d in others])
    ack = await admin.conn.request({"type": "room.create", "rid": "c", "room": room.room, "kind": "private",
                                    "policy": {"max": 32}, "commit": g})
    assert ack["type"] == "ack" and ack["epoch"] == 1, ack
    room.accept(g)
    return admin, others, room


def test_create_send_and_fanout_ciphertext_only():
    async def body():
        async with relay_server() as srv:
            port = srv.ports["plain"]
            admin, (bob,), room = await setup_room(port, 2)
            commit = await admin.conn.expect("room.commit")
            assert commit["seq"] == "1" and commit["commit"]["epoch"] == 1
            st = await admin.conn.request({"type": "room.members", "rid": "m", "room": room.room})
            assert st["type"] == "room.state" and st["kind"] == "private" and st["epoch"] == 1
            assert sorted(st["members"]) == sorted([admin.id, bob.id]) and st["admins"] == [admin.id]
            env = room.seal(admin, {"t": "text", "id": "0123456789abcdef", "body": "secret words", "ts": 1})
            ack = await admin.conn.request({"type": "room.send", "rid": "s", "room": room.room, "env": env})
            assert ack["type"] == "ack"
            msg = await bob.conn.expect("room.msg")
            assert msg["env"] == env and msg["seq"] == ack["seq"]
            # the relay keeps ciphertext only
            rows = srv.relay.store.all("SELECT data FROM room_log")
            assert rows and all("secret words" not in r["data"] for r in rows)
            # dedup by (from, epoch, n)
            again = await admin.conn.request({"type": "room.send", "rid": "s2", "room": room.room, "env": env})
            assert again["seq"] == ack["seq"]
            # the relay verifies the room signature
            bad = dict(env, n=env["n"] + 5)
            e = await admin.conn.request({"type": "room.send", "rid": "b", "room": room.room, "env": bad})
            assert e["code"] == 401 and e["err"] == "bad_sig"
            forged = room.seal(bob, {"t": "text", "body": "x"})
            e = await admin.conn.request({"type": "room.send", "rid": "f", "room": room.room, "env": forged})
            assert e["code"] == 403
            # sending under an old epoch -> 409 stale_epoch
            old = room.seal(admin, {"t": "text", "body": "old"}, epoch=1)
            c = room.commit(admin)  # rotation: empty commit, new epoch
            ack = await admin.conn.request({"type": "room.commit", "rid": "rot", "room": room.room, "commit": c})
            assert ack["epoch"] == 2
            room.accept(c)
            e = await admin.conn.request({"type": "room.send", "rid": "o", "room": room.room, "env": old})
            assert e["code"] == 409 and e["err"] == "stale_epoch" and e["epoch"] == 2
            # non-members are refused, unknown rooms are 404
            eve = Device()
            await eve.connect(port)
            e = await eve.conn.request({"type": "room.send", "rid": "e", "room": room.room,
                                        "env": room.seal(eve, {"t": "text"})})
            assert e["code"] == 403 and e["err"] == "not_member"
            e = await eve.conn.request({"type": "room.members", "rid": "e2", "room": "ab" * 16})
            assert e["code"] == 404 and e["err"] == "unknown_room"
    run(body())


def test_commit_rules():
    async def body():
        async with relay_server() as srv:
            port = srv.ports["plain"]
            admin, (bob,), room = await setup_room(port, 2)
            carol = Device()
            await carol.connect(port)
            # non-admin commit -> 403
            c = room.commit(bob, add=[carol.id])
            e = await bob.conn.request({"type": "room.commit", "rid": "1", "room": room.room, "commit": c})
            assert e["code"] == 403
            # wrong prev -> 409 epoch_conflict with the current epoch
            c = room.commit(admin, add=[carol.id])
            c2 = dict(c, prev=5, epoch=6)
            c2["sig"] = b64e(admin.sign(__import__("sc2proto").frames.commit_signed_bytes(room.room, c2)))
            e = await admin.conn.request({"type": "room.commit", "rid": "2", "room": room.room, "commit": c2})
            assert e["code"] == 409 and e["err"] == "epoch_conflict" and e["epoch"] == 1
            # bad signature -> 401
            bad = dict(c, sig=b64e(bytes(64)))
            e = await admin.conn.request({"type": "room.commit", "rid": "3", "room": room.room, "commit": bad})
            assert e["code"] == 401 and e["err"] == "bad_sig"
            # members_hash must match
            wrong = dict(c, members_hash=b64e(bytes(32)))
            e = await admin.conn.request({"type": "room.commit", "rid": "4", "room": room.room, "commit": wrong})
            assert e["code"] == 400
            # unsorted lists are not canonical
            unsorted = dict(c, add=sorted([carol.id, "00" * 16], reverse=True))
            e = await admin.conn.request({"type": "room.commit", "rid": "5", "room": room.room, "commit": unsorted})
            assert e["code"] == 400 and "sorted" in e["text"]
            # adding an unregistered device -> 404
            ghost = room.commit(admin, add=["ab" * 16])
            e = await admin.conn.request({"type": "room.commit", "rid": "6", "room": room.room, "commit": ghost})
            assert e["code"] == 404
            # a valid commit goes through; replaying it now conflicts
            ok = await admin.conn.request({"type": "room.commit", "rid": "7", "room": room.room, "commit": c})
            assert ok["type"] == "ack" and ok["epoch"] == 2
            room.accept(c)
            e = await admin.conn.request({"type": "room.commit", "rid": "8", "room": room.room, "commit": c})
            assert e["code"] == 409 and e["epoch"] == 2
            # admin changes are commits; the new admin can then commit
            p = room.commit(admin, admins=[admin.id, bob.id])
            assert (await admin.conn.request({"type": "room.commit", "rid": "9", "room": room.room,
                                              "commit": p}))["epoch"] == 3
            room.accept(p)
            r = room.commit(bob, remove=[carol.id])
            assert (await bob.conn.request({"type": "room.commit", "rid": "10", "room": room.room,
                                            "commit": r}))["epoch"] == 4
            # the commit log is stored in order
            assert [x["epoch"] for x in srv.relay.store.commits(room.room)] == [1, 2, 3, 4]
            # genesis must be signed by the creator and list the creator as admin
            room2 = PrivateRoom()
            g = room2.genesis(admin)
            e = await bob.conn.request({"type": "room.create", "rid": "g", "room": room2.room, "kind": "private",
                                        "commit": g})
            assert e["code"] == 403
            e = await admin.conn.request({"type": "room.create", "rid": "g2", "room": room.room, "kind": "private",
                                          "commit": g})
            assert e["code"] == 403  # room exists
    run(body())


def test_invite_join_request_add_and_no_history():
    async def body():
        async with relay_server() as srv:
            port = srv.ports["plain"]
            admin, (bob,), room = await setup_room(port, 2)
            # some history before the newcomer arrives
            for i in range(3):
                env = room.seal(bob, {"t": "text", "body": "before %d" % i})
                await bob.conn.request({"type": "room.send", "rid": "h%d" % i, "room": room.room, "env": env})
            secret = os.urandom(16)
            key = layouts.invite_key(secret, bytes.fromhex(room.room))
            e = await bob.conn.request({"type": "room.invite", "rid": "i0", "room": room.room, "key": b64e(key)})
            assert e["code"] == 403  # only admins register invites
            ack = await admin.conn.request({"type": "room.invite", "rid": "i", "room": room.room, "key": b64e(key)})
            assert ack["type"] == "ack"
            carol = Device()
            await carol.connect(port)
            e = await carol.join(room.room)
            assert e["code"] == 403  # invite required
            e = await carol.join(room.room, b64e(os.urandom(32)))
            assert e["code"] == 403
            proof = layouts.invite_proof(key, bytes.fromhex(carol.id))
            ack = await carol.join(room.room, b64e(proof))
            assert ack == {"type": "ack", "rid": ack["rid"], "status": "requested"}
            req = await admin.conn.expect("room.event", event="join_request")
            assert req["device"] == carol.id and req["room"] == room.room
            # join requests go to admins only
            got = await bob.conn.quiet()
            assert not [f for f in got if f.get("event") == "join_request"]
            # the admin commits the add
            c = room.commit(admin, add=[carol.id])
            ack = await admin.conn.request({"type": "room.commit", "rid": "a", "room": room.room, "commit": c})
            room.accept(c)
            join_seq = int(ack["seq"])
            ev = await bob.conn.expect("room.event", event="joined")
            assert ev["device"] == carol.id
            # the newcomer gets no history from before the add
            items, done = await carol.sync(rooms={room.room: "0"})
            seqs = [int(f["seq"]) for f in items]
            assert seqs and min(seqs) == join_seq
            assert {f["type"] for f in items} <= {"room.commit", "room.event"}
            assert not any(f.get("event") == "join_request" for f in items)
            # new messages reach the newcomer
            env = room.seal(bob, {"t": "text", "body": "welcome"})
            await bob.conn.request({"type": "room.send", "rid": "w", "room": room.room, "env": env})
            msg = await carol.conn.expect("room.msg")
            assert msg["env"] == env
            # an existing member syncing from 0 sees the full log
            items, done = await bob.sync(rooms={room.room: "0"})
            assert len([f for f in items if f["type"] == "room.msg"]) == 4
            assert not any(f.get("event") == "join_request" for f in items)
            items, done = await admin.sync(rooms={room.room: "0"})
            assert any(f.get("event") == "join_request" for f in items)
    run(body())


def test_remove_notice_and_routing_stops():
    async def body():
        async with relay_server() as srv:
            port = srv.ports["plain"]
            admin, (bob, carol), room = await setup_room(port, 3)
            carol.conn.close()
            c = room.commit(admin, remove=[carol.id])
            await admin.conn.request({"type": "room.commit", "rid": "r", "room": room.room, "commit": c})
            room.accept(c)
            ev = await bob.conn.expect("room.event", event="removed")
            assert ev["device"] == carol.id
            # carol was offline: the removed notice waits in her inbox
            await carol.connect(port, sync=False)
            items, done = await carol.sync()
            notes = [f for f in items if f["type"] == "room.event"]
            assert notes and notes[0]["event"] == "removed" and notes[0]["room"] == room.room
            assert notes[0]["device"] == carol.id
            # and the relay stops routing to her
            env = room.seal(carol, {"t": "text", "body": "still here?"}, epoch=room.state.epoch)
            e = await carol.conn.request({"type": "room.send", "rid": "x", "room": room.room, "env": env})
            assert e["code"] == 403 and e["err"] == "not_member"
            env = room.seal(bob, {"t": "text", "body": "after removal"})
            await bob.conn.request({"type": "room.send", "rid": "y", "room": room.room, "env": env})
            got = await carol.conn.quiet()
            assert not [f for f in got if f.get("type") == "room.msg"]
            e = await carol.conn.request({"type": "sync", "rid": "z", "rooms": {room.room: "0"}})
            assert e["code"] == 403 and e["err"] == "not_member"
    run(body())


def test_leave_rules():
    async def body():
        async with relay_server() as srv:
            port = srv.ports["plain"]
            admin, (bob,), room = await setup_room(port, 2)
            e = await admin.conn.request({"type": "room.leave", "rid": "l", "room": room.room})
            assert e["code"] == 403 and "last admin" in e["text"]
            ack = await bob.conn.request({"type": "room.leave", "rid": "l2", "room": room.room})
            assert ack["type"] == "ack"
            ev = await admin.conn.expect("room.event", event="left")
            assert ev["device"] == bob.id
            st = await admin.conn.request({"type": "room.members", "rid": "m", "room": room.room})
            assert st["members"] == [admin.id]
            # the admin then commits the matching remove
            c = room.commit(admin, remove=[bob.id])
            assert (await admin.conn.request({"type": "room.commit", "rid": "c", "room": room.room,
                                              "commit": c}))["type"] == "ack"
            # promote-then-leave works for admins
            carol = Device()
            await carol.connect(port)
            room.accept(c)
            c = room.commit(admin, add=[carol.id], admins=[admin.id, carol.id])
            await admin.conn.request({"type": "room.commit", "rid": "c2", "room": room.room, "commit": c})
            ack = await admin.conn.request({"type": "room.leave", "rid": "l3", "room": room.room})
            assert ack["type"] == "ack"
    run(body())


def test_member_cap():
    async def body():
        async with relay_server(room_members_max=4) as srv:
            port = srv.ports["plain"]
            admin, others, room = await setup_room(port, 4)
            extra = Device()
            await extra.connect(port)
            c = room.commit(admin, add=[extra.id])
            e = await admin.conn.request({"type": "room.commit", "rid": "x", "room": room.room, "commit": c})
            assert e["code"] == 403 and "full" in e["text"]
        async with relay_server() as srv:
            # the advertised default cap is 32 members
            port = srv.ports["plain"]
            admin, others, room = await setup_room(port, 32)
            extra = Device()
            await extra.connect(port)
            c = room.commit(admin, add=[extra.id])
            e = await admin.conn.request({"type": "room.commit", "rid": "y", "room": room.room, "commit": c})
            assert e["code"] == 403
    run(body())


def test_presence_only_to_shared_rooms():
    async def body():
        async with relay_server() as srv:
            port = srv.ports["plain"]
            admin, (bob,), room = await setup_room(port, 2)
            stranger = Device()
            await stranger.connect(port)
            await admin.conn.send({"type": "presence.set", "state": "online"})
            p = await bob.conn.expect("presence")
            assert p == {"type": "presence", "device": admin.id, "state": "online", "rooms": [room.room]}
            assert not [f for f in await stranger.conn.quiet() if f.get("type") == "presence"]
            await admin.conn.send({"type": "presence.set", "state": "hidden"})
            assert (await bob.conn.expect("presence"))["state"] == "offline"
            await admin.conn.send({"type": "presence.set", "state": "away"})
            assert (await bob.conn.expect("presence"))["state"] == "away"
            admin.conn.close()
            assert (await bob.conn.expect("presence"))["state"] == "offline"
    run(body())


def test_epoch_key_travels_as_dm():
    """An admin hands the epoch key to a member over a sealed DM; the member
    can then open room messages. The relay only ever sees ciphertext."""
    async def body():
        async with relay_server() as srv:
            port = srv.ports["plain"]
            admin, (bob,), room = await setup_room(port, 2)
            await bob.publish(5)
            admin.start_session(await admin.claim(bob.id))
            ek = room.epoch_keys[room.state.epoch]
            env = admin.seal_dm(bob.id, {"t": "epoch_key", "room": room.room, "epoch": room.state.epoch,
                                         "key": b64e(ek)})
            await admin.conn.request({"type": "dm.send", "rid": "k", "to": bob.id, "env": env})
            msg = await bob.conn.expect("dm.msg")
            await admin.publish(1)
            pb = await bob.claim(admin.id)
            inner = bob.open_dm(msg["env"], {"ik": b64d(pb["ik"]), "dk": b64d(pb["dk"]), "dk_sig": b64d(pb["dk_sig"])})
            got_key = b64d(inner["key"])
            renv = room.seal(admin, {"t": "text", "body": "sealed"})
            await admin.conn.request({"type": "room.send", "rid": "s", "room": room.room, "env": renv})
            m = await bob.conn.expect("room.msg")
            e = m["env"]
            room_b = bytes.fromhex(room.room)
            ck = sc2ref.room_chain(got_key, room_b, e["e"], bytes.fromhex(e["from"]))
            for _ in range(e["n"]):
                _, ck = sc2ref.chain_step(ck)
            mk, _ = sc2ref.chain_step(ck)
            hdr = sc2ref.room_header(room_b, e["e"], bytes.fromhex(e["from"]), e["n"])
            pt = sc2ref.unpad(sc2ref.aead_open(mk, b64d(e["nonce"]), b64d(e["ct"]), hdr))
            assert b"sealed" in pt
    run(body())
