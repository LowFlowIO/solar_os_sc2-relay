"""Test clients for the relay. Devices use protocol/sc2/tools/sc2ref.py (the
independent Phase 1 reference) for every key, signature and ratchet step.

SPDX-License-Identifier: MIT
"""

import asyncio
import contextlib
import json
import os
import ssl
import struct
import tempfile
import time

import sc2ref
from sc2proto import b64d, b64e, frames, hexe, layouts
from sc2proto.rooms import RoomState, make_commit
from sc2_relay.config import Config
from sc2_relay.server import RelayServer

ADMIN_TOKEN = "test-admin-token"


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, 60))


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


def free_port():
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def rng(n):
    return os.urandom(n)


def make_config(tmp, **kw):
    base = dict(data_dir=tmp, relay_id="relay.test", bind="127.0.0.1", plain=True, plain_port=0, http_port=0,
                admin_listen="127.0.0.1:0", admin_token=ADMIN_TOKEN, retention_interval=3600,
                slow_key_minutes=0, register_per_hour=10000, claim_per_min=1000, send_per_min=10000,
                send_burst=1000, max_conn_per_ip=1000)
    base.update(kw)
    return Config(**base)


@contextlib.asynccontextmanager
async def relay_server(clock=None, tmp=None, **kw):
    own = None
    if tmp is None:
        own = tempfile.TemporaryDirectory()
        tmp = own.name
    cfg = make_config(tmp, **kw)
    srv = RelayServer(cfg, clock=clock or Clock())
    await srv.start()
    try:
        yield srv
    finally:
        await srv.close()
        if own is not None:
            own.cleanup()


class Conn:
    """One NDJSON connection."""

    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.backlog = []

    @classmethod
    async def open(cls, port, host="127.0.0.1", ssl_ctx=None):
        r, w = await asyncio.open_connection(host, port, ssl=ssl_ctx, limit=1 << 20)
        return cls(r, w)

    async def send(self, obj):
        if isinstance(obj, (bytes, bytearray)):
            self.writer.write(bytes(obj))
        else:
            self.writer.write((obj if isinstance(obj, str) else sc2ref.dumps(obj)).encode() + b"\n")
        await self.writer.drain()

    async def recv(self, timeout=5.0):
        if self.backlog:
            return self.backlog.pop(0)
        line = await asyncio.wait_for(self.reader.readline(), timeout)
        if not line:
            raise EOFError("connection closed")
        return json.loads(line)

    async def expect(self, type_, timeout=5.0, **match):
        """Next frame of this type (others are kept in the backlog)."""
        deadline = time.monotonic() + timeout
        for i, f in enumerate(self.backlog):
            if f.get("type") == type_ and all(f.get(k) == v for k, v in match.items()):
                return self.backlog.pop(i)
        skipped = []
        try:
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise asyncio.TimeoutError("no %s frame; got %r" % (type_, skipped))
                line = await asyncio.wait_for(self.reader.readline(), left)
                if not line:
                    raise EOFError("closed while waiting for %s; got %r" % (type_, skipped))
                f = json.loads(line)
                if f.get("type") == type_ and all(f.get(k) == v for k, v in match.items()):
                    return f
                skipped.append(f)
        finally:
            self.backlog.extend(skipped)

    async def quiet(self, timeout=0.3):
        """Assert nothing arrives within timeout (returns any frames seen)."""
        got = list(self.backlog)
        self.backlog = []
        try:
            while True:
                line = await asyncio.wait_for(self.reader.readline(), timeout)
                if not line:
                    break
                got.append(json.loads(line))
        except asyncio.TimeoutError:
            pass
        return got

    async def closed(self, timeout=3.0):
        try:
            while True:
                line = await asyncio.wait_for(self.reader.readline(), timeout)
                if not line:
                    return True
        except (asyncio.TimeoutError, ConnectionError):
            return False

    async def request(self, obj, timeout=5.0):
        """Send and return the first frame echoing this rid."""
        await self.send(obj)
        rid = obj["rid"]
        deadline = time.monotonic() + timeout
        skipped = []
        try:
            for i, f in enumerate(self.backlog):
                if f.get("rid") == rid:
                    return self.backlog.pop(i)
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise asyncio.TimeoutError("no reply for rid %s; got %r" % (rid, skipped))
                line = await asyncio.wait_for(self.reader.readline(), left)
                if not line:
                    raise EOFError("closed waiting for rid %s; got %r" % (rid, skipped))
                f = json.loads(line)
                if f.get("rid") == rid:
                    return f
                skipped.append(f)
        finally:
            self.backlog.extend(skipped)

    def close(self):
        try:
            self.writer.close()
        except Exception:
            pass


class Device:
    """An SC2 device built on sc2ref."""

    _rid = 0

    def __init__(self, seed=None):
        if seed is None:
            self.ident = sc2ref.Identity(rng)
        else:
            self.ident = sc2ref.Identity(sc2ref.Rng(seed + os.urandom(32)))
            self.ident.ik_seed = seed[:32]
            self.ident.ik_pub = sc2ref.ed_public(self.ident.ik_seed)
            self.ident.dk_sig = sc2ref.ed_sign(self.ident.ik_seed, sc2ref.L_DK + self.ident.dk_pub)
            self.ident.id = sc2ref.device_id(self.ident.ik_pub)
        self.id = self.ident.id.hex()
        self.spk = sc2ref.Spk(1, self.ident, rng)
        self.opks = {}
        self.next_opk = 100
        self.sessions = {}
        self.conn = None
        self.relay_id = None
        self.welcome = None
        self.notes = []

    def rid(self):
        Device._rid += 1
        return "r%d" % Device._rid

    def sign(self, msg):
        return sc2ref.ed_sign(self.ident.ik_seed, msg)

    async def connect(self, port, admit=None, sync=True, ssl_ctx=None, conn=None):
        self.conn = conn or await Conn.open(port, ssl_ctx=ssl_ctx)
        hello = {"type": "hello", "v": 2, "proto": "sc2", "suites": [1], "client": "pytest/1"}
        if admit is not None:
            hello["admit"] = admit
        await self.conn.send(hello)
        w = await self.conn.recv()
        assert w["type"] == "welcome", w
        self.welcome = w
        self.relay_id = w["relay"]["id"]
        sig = self.sign(sc2ref.auth_bytes(self.relay_id, b64d(w["challenge"], 32), self.ident.ik_pub))
        rid = self.rid()
        a = await self.conn.request({"type": "auth", "rid": rid, "ik": b64e(self.ident.ik_pub), "sig": b64e(sig),
                                     "resume": True})
        self.authed = a
        if a["type"] == "authed" and sync:
            await self.sync()
        return a

    async def sync(self, inbox="0", rooms=None, max_=100):
        rid = self.rid()
        await self.conn.send({"type": "sync", "rid": rid, "inbox": inbox, "rooms": rooms or {}, "max": max_})
        items = []
        while True:
            f = await self.conn.recv()
            if f.get("type") == "sync.done" and f.get("rid") == rid:
                return items, f
            if f.get("type") in ("keys.low", "presence"):
                self.notes.append(f)  # unsolicited, not part of the backlog
                continue
            items.append(f)

    async def publish(self, n_opks=5):
        opks = []
        for _ in range(n_opks):
            o = sc2ref.Opk(self.next_opk, rng)
            self.opks[o.id] = o
            opks.append({"id": o.id, "pub": b64e(o.pub)})
            self.next_opk += 1
        return await self.conn.request({
            "type": "keys.publish", "rid": self.rid(), "dk": b64e(self.ident.dk_pub), "dk_sig": b64e(self.ident.dk_sig),
            "spk": {"id": self.spk.id, "pub": b64e(self.spk.pub), "sig": b64e(self.spk.sig)}, "opks": opks})

    async def claim(self, peer_id):
        return await self.conn.request({"type": "keys.claim", "rid": self.rid(), "device": peer_id})

    # ---- DMs via sc2ref (X3DH + double ratchet) ----

    def start_session(self, bundle):
        b = {"ik": b64d(bundle["ik"]), "dk": b64d(bundle["dk"]), "dk_sig": b64d(bundle["dk_sig"]),
             "spk_id": bundle["spk"]["id"], "spk": b64d(bundle["spk"]["pub"]), "spk_sig": b64d(bundle["spk"]["sig"]),
             "opk_id": bundle["opk"]["id"] if "opk" in bundle else sc2ref.NO_OPK,
             "opk": b64d(bundle["opk"]["pub"]) if "opk" in bundle else None}
        sk, ad, x3dh = sc2ref.x3dh_initiate(self.ident, b, rng)
        peer = bytes.fromhex(bundle["device"])
        self.sessions[bundle["device"]] = sc2ref.Ratchet.initiator(sk, ad, self.ident.id, peer, b["spk"], x3dh, rng)
        self.peer_bundles = getattr(self, "peer_bundles", {})
        self.peer_bundles[bundle["device"]] = b

    def seal_dm(self, peer_id, inner):
        r = self.sessions[peer_id]
        h, nonce, ct = r.encrypt(sc2ref.dumps(inner).encode(), rng)
        return sc2ref.dm_env(self.ident.id, h, nonce, ct)

    def open_dm(self, env, peer_ident=None, now=None):
        frm = env["from"]
        h = {"dh": b64d(env["rk"]), "pn": env["pn"], "n": env["n"], "x3dh": None}
        if "x3dh" in env:
            h["x3dh"] = {"ek": b64d(env["x3dh"]["ek"]), "spk_id": env["x3dh"]["spk"],
                         "opk_id": env["x3dh"].get("opk", sc2ref.NO_OPK)}
        if frm not in self.sessions:
            assert peer_ident is not None, "responder needs the initiator's directory entry"
            opk = self.opks.get(h["x3dh"]["opk_id"]) if h["x3dh"]["opk_id"] != sc2ref.NO_OPK else None
            sk, ad = sc2ref.x3dh_respond(self.ident, self.spk, opk, peer_ident["ik"], peer_ident["dk"],
                                         peer_ident["dk_sig"], h["x3dh"])
            self.sessions[frm] = sc2ref.Ratchet.responder(sk, ad, self.ident.id, bytes.fromhex(frm), self.spk)
        pt = self.sessions[frm].decrypt(h, b64d(env["nonce"]), b64d(env["ct"]), now or int(time.time()), rng)
        return json.loads(pt)

    # ---- public posts ----

    def post(self, room, body, name="Ana", t="text", ref=None, msg_id=None, relay_id=None, ts=1760889600):
        return sc2ref.post_make(relay_id or self.relay_id, room, self.ident.ik_seed, t, msg_id or os.urandom(8),
                                ts, name, body, bytes.fromhex(ref) if ref else None)

    async def send_post(self, room, body, **kw):
        return await self.conn.request({"type": "room.post", "rid": self.rid(), "room": room,
                                        "post": self.post(room, body, **kw)})

    async def join(self, room, invite=None):
        f = {"type": "room.join", "rid": self.rid(), "room": room}
        if invite is not None:
            f["invite"] = invite
        return await self.conn.request(f)


class PrivateRoom:
    """Client-side bookkeeping for a private room built with sc2ref and the
    fixed-size commit records (one change per commit)."""

    def __init__(self, room_hex=None):
        self.room = room_hex or os.urandom(16).hex()
        self.state = RoomState(self.room)
        self.epoch_keys = {}
        self.n = {}

    def genesis(self, admin):
        """{"commit", "sig"} for room.create: the creator is the only member."""
        return self.commit(admin, "create")

    def commit(self, admin, op="rotate", target=None, state=None):
        """{"commit", "sig"} for one change on top of the local state."""
        rec, sig = make_commit(state or self.state, admin.id, op, target, sign=admin.sign)
        return {"commit": b64e(rec), "sig": b64e(sig)}

    def accept(self, c):
        rec = b64d(c["commit"])
        parsed = layouts.commit_parse(rec)
        creator = hexe(parsed["by"]) if parsed["op"] == "create" else None
        self.state, _ = self.state.apply(rec, b64d(c["sig"]), lambda *a: True, creator=creator)
        self.epoch_keys[self.state.epoch] = os.urandom(32)

    async def create(self, admin, policy=None):
        g = self.genesis(admin)
        f = {"type": "room.create", "rid": admin.rid(), "room": self.room, "kind": "private"}
        if policy is not None:
            f["policy"] = policy
        f.update(g)
        ack = await admin.conn.request(f)
        if ack.get("type") == "ack":
            self.accept(g)
        return ack

    async def change(self, admin, op, target=None):
        """Send one commit; accept it locally when the relay acks it."""
        c = self.commit(admin, op, target)
        ack = await admin.conn.request(dict({"type": "room.commit", "rid": admin.rid(), "room": self.room}, **c))
        if ack.get("type") == "ack":
            self.accept(c)
        return ack

    def seal(self, dev, inner, epoch=None):
        e = epoch or self.state.epoch
        room_b = bytes.fromhex(self.room)
        ck = sc2ref.room_chain(self.epoch_keys.setdefault(e, os.urandom(32)), room_b, e, dev.ident.id)
        n = self.n.get((dev.id, e), 0)
        for _ in range(n):
            _, ck = sc2ref.chain_step(ck)
        mk, _ = sc2ref.chain_step(ck)
        self.n[(dev.id, e)] = n + 1
        hdr = sc2ref.room_header(room_b, e, dev.ident.id, n)
        nonce = os.urandom(24)
        ct, sig = sc2ref.room_seal(mk, nonce, hdr, sc2ref.dumps(inner).encode(), dev.ident.ik_seed)
        return {"s": 1, "e": e, "from": dev.id, "n": n, "nonce": b64e(nonce), "ct": b64e(ct), "sig": b64e(sig)}


async def http_get(port, path, headers=None, method="GET", body=None, host="127.0.0.1", ssl_ctx=None):
    r, w = await asyncio.open_connection(host, port, ssl=ssl_ctx)
    h = {"Host": "localhost", "Connection": "close"}
    h.update(headers or {})
    data = b""
    if body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
        h["Content-Length"] = str(len(data))
    req = "%s %s HTTP/1.1\r\n" % (method, path) + "".join("%s: %s\r\n" % kv for kv in h.items()) + "\r\n"
    w.write(req.encode() + data)
    await w.drain()
    raw = await asyncio.wait_for(r.read(), 10)
    w.close()
    head, _, payload = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split(" ")[1])
    hdrs = {}
    for ln in lines[1:]:
        k, _, v = ln.partition(":")
        hdrs[k.strip().lower()] = v.strip()
    return status, hdrs, payload


async def admin(srv, method, path, body=None, token=ADMIN_TOKEN):
    st, h, payload = await http_get(srv.ports["admin"], path, {"Authorization": "Bearer " + token} if token else {},
                                    method=method, body=body)
    return st, json.loads(payload or b"{}")


def ws_frame(payload, opcode=1, mask=True):
    n = len(payload)
    b0 = 0x80 | opcode
    if n < 126:
        head = struct.pack(">BB", b0, (0x80 if mask else 0) | n)
    elif n < 65536:
        head = struct.pack(">BBH", b0, (0x80 if mask else 0) | 126, n)
    else:
        head = struct.pack(">BBQ", b0, (0x80 if mask else 0) | 127, n)
    if not mask:
        return head + payload
    key = os.urandom(4)
    return head + key + bytes(b ^ key[i & 3] for i, b in enumerate(payload))


def insecure_client_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


__all__ = ["run", "Clock", "relay_server", "Conn", "Device", "PrivateRoom", "http_get", "admin", "ws_frame",
           "insecure_client_ctx", "free_port", "frames", "layouts", "hexe", "b64e", "b64d", "ADMIN_TOKEN",
           "make_config"]
