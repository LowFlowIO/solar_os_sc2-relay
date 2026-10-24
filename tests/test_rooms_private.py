"""Private rooms: genesis and admin-signed fixed-size commits (one change
each, chained by commit ID), invites and join requests, ciphertext-only
routing, no history for newcomers, removal notices, leave rules and the
member cap.

SPDX-License-Identifier: MIT
"""

import os

import sc2ref
from helpers import Device, PrivateRoom, b64e, layouts, relay_server, run
from sc2proto import b64d
from sc2proto.rooms import make_commit


async def setup_room(port, n_members=1):
    """Genesis (epoch 1) and then one add commit per extra member, so the
    room ends at epoch n_members."""
    admin = Device()
    await admin.connect(port)
    others = []
    for _ in range(n_members - 1):
        d = Device()
        await d.connect(port)
        others.append(d)
    room = PrivateRoom()
    ack = await room.create(admin, {"max": 32})
    assert ack["type"] == "ack" and ack["epoch"] == 1 and ack["head"] == room.state.head, ack
    for d in others:
        ack = await room.change(admin, "add", d.id)
        assert ack["type"] == "ack", ack
    assert room.state.epoch == n_members
    return admin, others, room


def frame(room, c, rid):
    return dict({"type": "room.commit", "rid": rid, "room": room.room}, **c)


def test_create_send_and_fanout_ciphertext_only():
    async def body():
        async with relay_server() as srv:
            port = srv.ports["plain"]
            admin, (bob,), room = await setup_room(port, 2)
            commit = await admin.conn.expect("room.commit")
            assert commit["seq"] == "1" and layouts.commit_parse(b64d(commit["commit"]))["op"] == "create"
            assert set(commit) == {"type", "room", "seq", "commit", "sig"}
            st = await admin.conn.request({"type": "room.members", "rid": "m", "room": room.room})
            assert st["type"] == "room.state" and st["kind"] == "private" and st["epoch"] == 2
            assert st["head"] == room.state.head
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
            ack = await room.change(admin, "rotate")  # rotation: roster unchanged, new epoch
            assert ack["epoch"] == 3
            e = await admin.conn.request({"type": "room.send", "rid": "o", "room": room.room, "env": old})
            assert e["code"] == 409 and e["err"] == "stale_epoch" and e["epoch"] == 3
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
            e = await bob.conn.request(frame(room, room.commit(bob, "add", carol.id), "1"))
            assert e["code"] == 403
            c = room.commit(admin, "add", carol.id)
            # a commit that does not extend the head -> 409 epoch_conflict with epoch and head
            ahead = room.state.copy()
            ahead.epoch += 3
            rec, sig = make_commit(ahead, admin.id, "add", carol.id, sign=admin.sign)
            e = await admin.conn.request(frame(room, {"commit": b64e(rec), "sig": b64e(sig)}, "2"))
            assert e["code"] == 409 and e["err"] == "epoch_conflict" and e["epoch"] == 2
            assert e["head"] == room.state.head
            stale = room.state.copy()
            stale.head = "00" * 32
            rec, sig = make_commit(stale, admin.id, "add", carol.id, sign=admin.sign)
            e = await admin.conn.request(frame(room, {"commit": b64e(rec), "sig": b64e(sig)}, "2b"))
            assert e["code"] == 409 and e["err"] == "epoch_conflict"
            # bad signature -> 401
            e = await admin.conn.request(frame(room, dict(c, sig=b64e(bytes(64))), "3"))
            assert e["code"] == 401 and e["err"] == "bad_sig"
            # roster_hash and count must match the roster after the change
            rec = bytearray(b64d(c["commit"]))
            rec[98] ^= 1
            e = await admin.conn.request(frame(room, dict(c, commit=b64e(bytes(rec))), "4"))
            assert e["code"] == 400 and "roster" in e["text"]
            rec = bytearray(b64d(c["commit"]))
            rec[97] += 1
            e = await admin.conn.request(frame(room, dict(c, commit=b64e(bytes(rec))), "4b"))
            assert e["code"] == 400
            # malformed records are refused before any roster check
            for bad in (b64e(b64d(c["commit"])[:-1]), b64e(b"X" + b64d(c["commit"])[1:]), "not base64"):
                e = await admin.conn.request(frame(room, dict(c, commit=bad), "5"))
                assert e["code"] == 400
            # a commit for another room is refused
            other = PrivateRoom()
            other.state = room.state.copy()
            other.state.room = other.room
            e = await admin.conn.request(frame(room, other.commit(admin, "add", carol.id), "5b"))
            assert e["code"] == 400 and "another room" in e["text"]
            # only room.create carries a genesis
            e = await admin.conn.request(frame(room, room.commit(admin, "create"), "5c"))
            assert e["code"] == 400
            # adding an unregistered device -> 404
            e = await admin.conn.request(frame(room, room.commit(admin, "add", "ab" * 16), "6"))
            assert e["code"] == 404
            # a valid commit goes through; replaying it now conflicts
            ok = await admin.conn.request(frame(room, c, "7"))
            assert ok["type"] == "ack" and ok["epoch"] == 3
            room.accept(c)
            assert ok["head"] == room.state.head
            e = await admin.conn.request(frame(room, c, "8"))
            assert e["code"] == 409 and e["epoch"] == 3
            # roster rules: no double add, no remove of non-members, no demote of non-admins
            for op, tgt in (("add", carol.id), ("remove", "cd" * 16), ("demote", bob.id), ("promote", admin.id)):
                e = await admin.conn.request(frame(room, room.commit(admin, op, tgt), "r" + op))
                assert e["code"] == 400, (op, e)
            # the last admin can be neither removed nor demoted
            for op in ("remove", "demote"):
                e = await admin.conn.request(frame(room, room.commit(admin, op, admin.id), "l" + op))
                assert e["code"] == 400 and "last admin" in e["text"]
            # admin changes are commits; the new admin can then commit
            assert (await room.change(admin, "promote", bob.id))["epoch"] == 4
            assert (await room.change(bob, "remove", carol.id))["epoch"] == 5
            assert (await room.change(bob, "demote", admin.id))["epoch"] == 6
            st = await bob.conn.request({"type": "room.members", "rid": "m", "room": room.room})
            assert st["admins"] == [bob.id] and st["epoch"] == 6 and st["head"] == room.state.head
            e = await admin.conn.request(frame(room, room.commit(admin, "rotate"), "9"))
            assert e["code"] == 403  # no longer an admin
            # the commit log is stored in order
            assert [x["epoch"] for x in srv.relay.store.commits(room.room)] == [1, 2, 3, 4, 5, 6]
            # genesis must be signed by the creator
            room2 = PrivateRoom()
            g = room2.genesis(admin)
            e = await bob.conn.request(dict({"type": "room.create", "rid": "g", "room": room2.room,
                                             "kind": "private"}, **g))
            assert e["code"] == 403
            # a genesis must be a create; a create must be a genesis
            e = await admin.conn.request(dict({"type": "room.create", "rid": "g1", "room": room2.room,
                                               "kind": "private"}, **room2.commit(admin, "rotate")))
            assert e["code"] == 400
            e = await admin.conn.request(dict({"type": "room.create", "rid": "g2", "room": room.room,
                                               "kind": "private"}, **g))
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
            ack = await room.change(admin, "add", carol.id)
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
            await room.change(admin, "remove", carol.id)
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
            assert (await room.change(admin, "remove", bob.id))["type"] == "ack"
            # promote-then-leave works for admins (two commits: add, then promote)
            carol = Device()
            await carol.connect(port)
            assert (await room.change(admin, "add", carol.id))["type"] == "ack"
            assert (await room.change(admin, "promote", carol.id))["type"] == "ack"
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
            e = await room.change(admin, "add", extra.id)
            assert e["code"] == 403 and "full" in e["text"]
        async with relay_server() as srv:
            # the advertised default cap is 32 members
            port = srv.ports["plain"]
            admin, others, room = await setup_room(port, 32)
            extra = Device()
            await extra.connect(port)
            # a 33rd member cannot even be encoded: count is 1..32 in the record
            e = await room.change(admin, "add", extra.id)
            assert e["code"] == 400 and "count" in e["text"]
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


def test_removal_notices_are_bounded_per_room_and_by_the_inbox_limit():
    async def body():
        async with relay_server(max_queue=3) as srv:
            port = srv.ports["plain"]
            admin, (carol,), room = await setup_room(port, 2)
            carol.conn.close()
            st = srv.relay.store
            # repeated remove/add while carol is offline: one pending notice, no growth
            for i in range(5):
                assert (await room.change(admin, "remove", carol.id))["type"] == "ack"
                assert st.inbox_stats(carol.id)[0] == 1
                assert (await room.change(admin, "add", carol.id))["type"] == "ack"
                assert st.inbox_stats(carol.id)[0] == 0  # re-added: the old notice is stale and dropped
            assert (await room.change(admin, "remove", carol.id))["type"] == "ack"
            # a second room's removal is its own notice
            room2 = PrivateRoom()
            await room2.create(admin, {"max": 32})
            await room2.change(admin, "add", carol.id)
            await room2.change(admin, "remove", carol.id)
            assert st.inbox_stats(carol.id)[0] == 2
            # fill carol's inbox to the limit with a DM; a third room's notice is skipped
            await carol.connect(port, sync=False)
            await carol.publish(1)
            carol.conn.close()
            admin.start_session(await admin.claim(carol.id))
            env = admin.seal_dm(carol.id, {"t": "text", "body": "hi"})
            assert (await admin.conn.request({"type": "dm.send", "rid": "d", "to": carol.id, "env": env}))[
                "type"] == "ack"
            room3 = PrivateRoom()
            await room3.create(admin, {"max": 32})
            await room3.change(admin, "add", carol.id)
            await room3.change(admin, "remove", carol.id)
            assert st.inbox_stats(carol.id)[0] == 3
            assert srv.relay.metrics["removal_notices_skipped_total"] == 1
            # carol still learns it: sync replays the room's removal event before 403
            await carol.connect(port, sync=False)
            items, done = await carol.sync(rooms={room3.room: "0"})
            ev = [f for f in items if f.get("type") == "room.event"]
            assert [(f["room"], f["event"], f["device"]) for f in ev if "room_seq" not in f] == [
                (room3.room, "removed", carol.id)]
            err = [f for f in items if f.get("type") == "error"]
            assert err and err[0]["code"] == 403 and err[0]["room"] == room3.room
    run(body())
