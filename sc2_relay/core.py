"""The SC2 relay state machine, independent of the transport.

A Session is one client connection (TCP, TLS or WebSocket). The transport
feeds raw bytes in with Session.feed() and provides write_line() / close()
callbacks. Every handler runs synchronously inside the event loop, so a
handler's database reads and writes and its fan-out are atomic with respect
to other clients.

The relay never sees plaintext of DMs or private rooms: it stores and
forwards opaque sealed envelopes, checks signatures that bind them to device
keys, and enforces quotas, ordering and membership routing.

SPDX-License-Identifier: MIT
"""

import collections
import hmac
import json
import logging
import time
import traceback

from sc2proto import (LineBuffer, ProtocolError, b64d, b64e, dumpb, dumps, frames, hexd, hexe, layouts, limits,
                     loads, rooms)
from sc2proto import relaykey
from sc2proto.errors import DEFAULT_TEXT, error_frame
from sc2proto.rooms import RoomState

from . import crypto
from .legacy import V1Client, V1Hub

log = logging.getLogger("sc2_relay")

PUBLIC_LABEL = "PUBLIC \u00b7 not encrypted"
PUBLIC_NOTICE = ("Messages here are NOT encrypted. The relay operator, everyone in the room and anyone viewing "
                 "the relay's public web page can read them. They are signed with your device key, so they prove "
                 "you wrote them and cannot be denied later.")

TUNABLE = ("admission", "admit_code", "post_per_min", "post_burst", "ip_post_per_min", "ip_post_burst",
           "room_post_per_min", "slow_key_minutes", "slow_until_posts", "slow_per_min", "slow_burst",
           "slow_body_max", "max_queue", "max_queue_bytes", "ttl_days", "send_per_min", "send_burst",
           "claim_per_min")


def with_seq(frame, seq):
    """Inbox frame with its seq right after type (the C vectors' layout)."""
    out = {"type": frame["type"], "seq": frames.fmt_seq(seq)}
    for k in frame:
        if k not in out:
            out[k] = frame[k]
    return out


class _Cfg:
    """Mutable copy of the Config, so the admin interface can tune values."""

    def __init__(self, config):
        for k, v in vars(config).items():
            setattr(self, k, v)
        self.official = config.official


class Relay:
    def __init__(self, config, store, key, clock=time.time):
        self.config = config
        self.cfg = _Cfg(config)
        self.store = store
        self.key = key
        self.clock = clock
        self.relay_id = config.relay_id
        self.sessions = set()
        self.by_device = collections.defaultdict(set)
        self.metrics = collections.Counter()
        self.tls_pin = None
        self.ports = {}       # listener ports, set by the server
        self.rotation = None  # {"from", "sig"}: the previous key's signature over this one
        for k in TUNABLE:
            v = store.setting("tune." + k)
            if v is not None:
                setattr(self.cfg, k, v)
        self.post_key = limits.RateTable(config.post_per_min, config.post_burst)
        self.post_ip = limits.RateTable(config.ip_post_per_min, config.ip_post_burst)
        self.post_room = limits.RateTable(config.room_post_per_min, max(10, config.room_post_per_min // 6))
        self.send_rate = limits.RateTable(config.send_per_min, config.send_burst)
        self.claim_rate = limits.RateTable(config.claim_per_min, max(1, config.claim_per_min // 2))
        self.register_rate = limits.RateTable(config.register_per_hour / 60.0, config.register_per_hour)
        self.report_rate = limits.RateTable(config.report_per_min, config.report_per_min)
        now = self.now()
        for room in config.public_rooms:
            if store.room(room) is None:
                store.create_room(room, "public", "#" + room[4:], {}, now)
                log.info("created public room %s from config", room)
        self.v1 = V1Hub(self)

    # ---------------- helpers ----------------

    def now(self):
        return int(self.clock())

    def logid(self, dev):
        return dev if self.cfg.log_device_ids else "<device>"

    def sign(self, msg):
        return self.key.sign(msg)

    def relay_key_b64(self):
        return b64e(self.key.public)

    def welcome_limits(self):
        lim = dict(limits.WELCOME_LIMITS)
        lim["members"] = self.cfg.room_members_max
        lim["rooms"] = self.cfg.rooms_per_device
        lim["queue"] = self.cfg.max_queue
        lim["queue_bytes"] = self.cfg.max_queue_bytes
        lim["ttl_days"] = self.cfg.ttl_days
        return lim

    def descriptor(self):
        """The signed descriptor (sc2proto.relaykey), or None without a
        client listener. Signed per request: the TLS pin can change."""
        c = self.config
        if "tls" in self.ports:
            port, tls = self.ports["tls"], True
        elif "plain" in self.ports:
            port, tls = self.ports["plain"], False
        else:
            return None
        text = relaykey.descriptor_text(
            self.relay_id, self.key.public, c.public_port or port, tls,
            host=c.public_host or c.acme_domain or None,
            pin=self.tls_pin if (tls and c.descriptor_pin) else None,
            fallbacks=[(u, b64d(k, 32)) for u, k in c.fallbacks], ts=self.now())
        return {"descriptor": b64e(text), "descriptor_sig": b64e(relaykey.sign_descriptor(self.sign, text))}

    def well_known(self):
        # the signed descriptor first: devices read only the start of the body
        out = self.descriptor() or {}
        out.update({
            "v": frames.VERSION, "suites": [layouts.SUITE], "relay_id": self.relay_id,
            "relay_key": self.relay_key_b64(), "limits": self.welcome_limits(), "admission": self.cfg.admission,
            "legacy_v1": bool(self.cfg.legacy_v1), "public_rooms": [r["id"] for r in self.store.public_rooms()],
            "public_room_create": self.cfg.public_room_create, "web_view": bool(self.cfg.web_view),
            "public_limits": {"msg": self.cfg.public_body_max, "per_min": self.cfg.post_per_min,
                              "burst": self.cfg.post_burst},
            "tls_pin": self.tls_pin,
        })
        if self.rotation is not None:
            out["rotation"] = dict(self.rotation)
        return out

    def verify_device(self, dev, msg, sig):
        d = self.store.device(dev)
        return d is not None and crypto.verify(bytes(d["ik"]), msg, sig)

    def push(self, dev, frame, exclude=None, live_only=True):
        if dev not in self.by_device:
            return
        line = dumpb(frame)
        for s in list(self.by_device[dev]):
            if s is exclude or (live_only and not s.live):
                continue
            s.write_line(line)

    def inbox_deliver(self, dev, kind, frame, size=None, dedup=None):
        """Queue one frame in a device's inbox and push it live. Every inbox
        item counts against SC2_MAX_QUEUE / SC2_MAX_QUEUE_BYTES; returns None
        (nothing stored) when it does not fit."""
        data = dumps(frame)
        size = len(data) if size is None else size
        n, b = self.store.inbox_stats(dev)
        if not limits.queue_admit(n, b, size, self.cfg.max_queue, self.cfg.max_queue_bytes):
            return None
        seq = self.store.inbox_add(dev, kind, data, size, self.now(), dedup)
        self.push(dev, with_seq(frame, seq))
        return seq

    def fanout_private(self, room, frame, audience="all", exclude=None):
        admins = None
        if audience == "admins":
            admins = {m["device"] for m in self.store.members(room) if m["admin"]}
        line = dumpb(frame)
        for dev in self.store.routing_members(room):
            if admins is not None and dev not in admins:
                continue
            for s in list(self.by_device.get(dev, ())):
                if s is not exclude and s.live:
                    s.write_line(line)

    def fanout_public(self, room, frame, exclude=None):
        line = dumpb(frame)
        for s in list(self.sessions):
            if s is not exclude and s.live and room in s.public_rooms:
                s.write_line(line)

    def room_log_event(self, room, event, dev, audience="all", exclude=None):
        seq = self.store.next_seq(room)
        f = {"type": "room.event", "room": room, "event": event, "device": dev, "seq": frames.fmt_seq(seq)}
        self.store.room_log_add(room, seq, "event", dumps(f), self.now(), audience)
        self.fanout_private(room, f, audience, exclude)
        return seq

    def room_state(self, room, rid=None):
        r = self.store.room(room)
        st = {"room": room, "kind": r["kind"]}
        if r["kind"] == "private":
            ms = self.store.members(room)
            st["members"] = [m["device"] for m in ms if m["routing"]]
            st["admins"] = [m["device"] for m in ms if m["admin"]]
            st["epoch"] = r["epoch"]
            st["head"] = r["head"]
        else:
            st["title"] = r["title"]
            st["members_count"] = self.store.public_member_count(room)
            st["label"] = PUBLIC_LABEL
            st["slow"] = bool(r["slow"])
        st["seq"] = frames.fmt_seq(r["seq"])
        return frames.frame("room.state", rid, **st)

    def post_policy(self, dev, room_row, now):
        """(per_min, burst, body_max, slow) for one device in one room."""
        d = self.store.device(dev)
        young = (d is None or now - d["first_seen"] < self.cfg.slow_key_minutes * 60 or
                 d["posts"] < self.cfg.slow_until_posts)
        if young or (room_row is not None and room_row["slow"]):
            return self.cfg.slow_per_min, self.cfg.slow_burst, min(self.cfg.slow_body_max,
                                                                    self.cfg.public_body_max), True
        return self.cfg.post_per_min, self.cfg.post_burst, self.cfg.public_body_max, False

    def ban_check(self, dev, ip, now):
        on, until = self.store.ban_active("key", dev, now)
        if not on and ip:
            on, until = self.store.ban_active("ip", ip, now)
        if on:
            raise ProtocolError(403, "banned", None, until=until)

    def mute_check(self, dev, ip, now):
        if not self.cfg.mutes:
            return
        on, until = self.store.mute_active("key", dev, now)
        if not on and ip:
            on, until = self.store.mute_active("ip", ip, now)
        if on:
            raise ProtocolError(403, "muted", None, until=until)

    def set_tunable(self, key, value):
        if key not in TUNABLE:
            raise KeyError(key)
        setattr(self.cfg, key, value)
        self.store.set_setting("tune." + key, value)

    # ---------------- moderation (admin interface) ----------------

    def resolve_post(self, room, ref, author=None):
        """The public post (room, author, ref). Message IDs are chosen by
        clients and unique per author only, so without the author the ID
        must match exactly one post in the room. Returns the row or None;
        raises 409 ambiguous_ref when several authors used the ID."""
        if author is not None:
            return self.store.post_by_id(room, author, ref)
        rows = self.store.posts_by_ref(room, ref)
        if len(rows) > 1:
            raise ProtocolError(409, "ambiguous_ref", None, ref=ref)
        return rows[0] if rows else None

    def mod_remove(self, room, ref, dev=None):
        """Remove a public post by message ID and author (dev); without dev,
        only if the ID is unambiguous in the room (409 ambiguous_ref).
        Emits a relay-signed room.mod remove. Returns 1, or 0 when there is
        no such post or it was already removed."""
        row = self.resolve_post(room, ref, dev)
        if row is None or row["removed"]:
            return 0
        self.store.mark_removed(room, row["seq"])
        self._emit_mod(room, "remove", row["from_dev"], ref=ref)
        return 1

    def mod_ban_key(self, dev, until, reason, remove_posts=False):
        now = self.now()
        self.store.set_ban("bans", "key", dev, until, reason, now)
        for r in self.store.public_rooms():
            room = r["id"]
            if remove_posts:
                for p in self.store.posts_of(room, dev):
                    self.store.mark_removed(room, p["seq"])
                    self._emit_mod(room, "remove", dev, ref=p["id"])
            self._emit_mod(room, "ban", dev, until=until)
            if self.store.public_member(room, dev) is not None:
                self.store.public_leave(room, dev)
        for s in list(self.by_device.get(dev, ())):
            s.public_rooms.clear()

    def mod_unban_key(self, dev):
        """Lift a key ban and announce it (room.mod unban) in every public
        room. Returns the number of bans lifted (0 or 1)."""
        n = self.store.lift_ban("bans", "key", dev)
        if n:
            for r in self.store.public_rooms():
                self._emit_mod(r["id"], "unban", dev)
        return n

    def mod_ban_ip(self, ip, until, reason):
        """Silent: IP bans are never announced."""
        self.store.set_ban("bans", "ip", ip, until, reason, self.now())
        for s in list(self.sessions):
            if s.ip == ip:
                s.public_rooms.clear()

    def _emit_mod(self, room, action, device, ref=None, until=None):
        now = self.now()
        seq = self.store.next_seq(room)
        f = frames.mod_frame(room, action, seq, now, self.sign, device, ref=ref, until=until)
        self.store.add_mod(room, seq, action, ref, device, until, now, f)
        self.metrics["mod_events_total"] += 1
        self.fanout_public(room, f)
        return f

    def purge_device(self, dev):
        self.store.purge_device(dev, self.now())
        for s in list(self.by_device.get(dev, ())):
            s.close()

    # ---------------- retention ----------------

    def retention(self):
        now = self.now()
        out = self.store.retention(limits.ttl_cutoff(now, self.cfg.ttl_days), self.cfg.private_log_max,
                                   self.cfg.public_log_max, self.cfg.v1_history,
                                   limits.ttl_cutoff(now, self.cfg.ttl_days) * 1000)
        out["bans"] = self.store.expire_bans(now)
        for t in (self.post_key, self.post_ip, self.post_room, self.send_rate, self.claim_rate, self.report_rate):
            t.prune(self.clock())
        return out

    # ---------------- sessions ----------------

    def new_session(self, ip, transport, write_line, close):
        s = Session(self, ip, transport, write_line, close)
        self.sessions.add(s)
        self.metrics["connections_total"] += 1
        return s

    # Connection slots. SC2_MAX_CONNECTIONS and SC2_MAX_CONN_PER_IP bound the
    # open sessions. When a cap is reached, a new connection may still take
    # the slot of the longest-idle established session (idle at least
    # SC2_EVICT_MIN_IDLE), but only once it has authenticated: eviction at
    # TCP accept would let anyone without a key churn every idle device off
    # the relay. Until then the newcomer occupies one of a few handshake
    # slots above the cap (HANDSHAKE_SLOTS, one per IP over its own cap);
    # these expire after SC2_AUTH_TIMEOUT like any unauthenticated session.

    HANDSHAKE_SLOTS = 16

    def connection_allowed(self, ip):
        """Admit a raw connection (before hello/auth)?"""
        pending = [s for s in self.sessions if not s.established]
        same_ip = [s for s in self.sessions if s.ip == ip]
        if len(self.sessions) >= self.cfg.max_connections:
            if len(pending) >= self.HANDSHAKE_SLOTS or self.evictable() is None:
                self.metrics["connections_refused_total"] += 1
                return False
        if len(same_ip) >= self.cfg.max_conn_per_ip:
            if any(not s.established for s in same_ip) or self.evictable(ip) is None:
                self.metrics["connections_refused_total"] += 1
                return False
        return True

    def evictable(self, ip=None, exclude=None):
        """The longest-idle established session (optionally from one IP) idle
        at least SC2_EVICT_MIN_IDLE, or None."""
        cut = self.clock() - self.cfg.evict_min_idle
        best = None
        for s in self.sessions:
            if s is exclude or s.closed or not s.established or s.active > cut:
                continue
            if ip is not None and s.ip != ip:
                continue
            if best is None or s.active < best.active:
                best = s
        return best

    def make_room(self, session):
        """Called when a session authenticates (or a legacy v1 client says
        hello). Evicts idle sessions so the caps hold; False if the relay is
        full of active sessions and the newcomer must be refused."""
        while True:
            over = len(self.sessions) > self.cfg.max_connections
            over_ip = sum(1 for s in self.sessions if s.ip == session.ip) > self.cfg.max_conn_per_ip
            if not over and not over_ip:
                return True
            # a victim from the same IP fixes both caps; any idle session fixes the global one
            victim = self.evictable(session.ip if over_ip else None, exclude=session)
            if victim is None:
                self.metrics["connections_refused_total"] += 1
                return False
            victim.kick(503, "evicted")
            self.metrics["sessions_evicted_total"] += 1

    def sweep(self):
        """Close sessions past one of their deadlines. Returns the number
        closed. Runs periodically from the server.

        - Unauthenticated sessions (no auth, no legacy v1 hello) get
          SC2_AUTH_TIMEOUT from the moment they connected, whatever they
          send meanwhile: pings, a slow trickle or half a frame do not
          extend it (408 auth_timeout).
        - Established sessions idle (no frame other than ping) for
          SC2_IDLE_TIMEOUT (408 idle).
        - Established sessions older than SC2_MAX_SESSION_SECONDS when set
          (503 reconnect)."""
        now = self.clock()
        n = 0
        for s in list(self.sessions):
            if s.closed:
                continue
            if not s.established:
                if now >= s.login_deadline:
                    s.auth_timed_out()
                    n += 1
            elif now - s.active >= self.cfg.idle_timeout:
                s.idled_out()
                n += 1
            elif self.cfg.max_session_seconds and now - s.established >= self.cfg.max_session_seconds:
                s.kick(503, "reconnect")
                self.metrics["sessions_expired_total"] += 1
                n += 1
        return n


class Session:
    def __init__(self, relay, ip, transport, write_line, close):
        self.relay = relay
        self.ip = ip
        self.transport = transport
        self._write = write_line
        self._close = close
        self.state = "new"
        self.lines = LineBuffer(frames.V1_LINE_MAX if transport != "ws" else frames.LINE_MAX)
        self.device = None
        self.ik = None
        self.challenge = None
        self.admit = None
        self.live = False
        self.public_rooms = set()
        self.presence = None
        self.v1 = None
        self.closed = False
        self.created = relay.clock()
        # absolute: nothing the client sends before auth moves it
        self.login_deadline = self.created + relay.cfg.auth_timeout
        self.established = None    # clock time of auth (or legacy v1 hello)
        self.active = self.created  # last frame other than ping/pong

    # transport side

    def write_line(self, line):
        if not self.closed:
            self.relay.metrics["bytes_out_total"] += len(line)
            self._write(line)

    def send(self, frame):
        self.write_line(dumpb(frame))

    def close(self):
        if not self.closed:
            self._close()

    def kick(self, code, err, text=None, presence=True):
        """Tell the client why with a final error frame, close, and release
        the slot right away (the transport's own cleanup is then a no-op)."""
        if self.closed:
            return
        if self.state == "v1":
            self.send({"type": "error", "text": text or DEFAULT_TEXT[err], "code": code})
        else:
            self.send(error_frame(code, err, text))
        self.close()
        self.on_closed(presence)

    def auth_timed_out(self):
        """The login deadline passed: 408 auth_timeout, then close."""
        if not self.closed:
            self.relay.metrics["sessions_auth_timeout_total"] += 1
            self.kick(408, "auth_timeout")

    def idled_out(self):
        """No frame other than ping for SC2_IDLE_TIMEOUT: 408 idle, then close."""
        if not self.closed:
            self.relay.metrics["sessions_idle_closed_total"] += 1
            self.kick(408, "idle")

    def read_timed_out(self):
        """The transport saw no data within the read timeout it was given."""
        if self.established:
            self.idled_out()
        else:
            self.auth_timed_out()

    def feed(self, data):
        self.relay.metrics["bytes_in_total"] += len(data)
        try:
            lines = self.lines.feed(data)
        except ProtocolError:
            lines = []
            overflow = True
        else:
            overflow = False
        for line in lines:
            if self.closed:
                return
            self.handle_line(line)
        if overflow and not self.closed:
            if self.state == "v1":
                self.send({"type": "error", "text": "line too long", "code": 413})
            else:
                self.send(ProtocolError(413, "too_large", "line too long").frame())
            self.close()

    def feed_frame(self, text):
        """WebSocket: one text message is one frame."""
        self.relay.metrics["bytes_in_total"] += len(text)
        if len(text) > frames.LINE_MAX:
            self.send(ProtocolError(413, "too_large", "line too long").frame())
            self.close()
            return
        self.handle_line(text)

    def on_closed(self, presence=True):
        if self.closed:
            return
        self.closed = True
        r = self.relay
        r.sessions.discard(self)
        if self.v1 is not None:
            self.v1.closed()
        if self.device is not None:
            group = r.by_device.get(self.device)
            if group is not None:
                group.discard(self)
                if not group:
                    del r.by_device[self.device]
                    if presence and self.presence in ("online", "away"):
                        self._broadcast_presence("offline")

    # protocol side

    def handle_line(self, line):
        r = self.relay
        if self.state == "v1":
            try:
                obj = loads(line)
            except ProtocolError:
                obj = None
            if not isinstance(obj, dict):
                self.v1.error("missing type", 400)
                return
            self.active = r.clock()
            self.v1.handle(obj)
            return
        rid = None
        try:
            t, obj, rid = frames.parse(line)
            if t not in ("ping", "pong"):
                self.active = r.clock()
            if self.state == "new":
                self._first(t, obj, rid)
                return
            if self.state != "authed" and t not in ("auth", "ping", "hello"):
                raise ProtocolError(401, "auth_required", "authenticate first")
            f = frames.validate(t, obj)
            getattr(self, "h_" + t.replace(".", "_"))(f, rid)
        except ProtocolError as e:
            r.metrics["errors_" + str(e.code)] += 1
            if e.code == 429:
                r.metrics["rate_limited_total"] += 1
            self.send(e.frame(rid))
            if e.close:
                self.close()
        except Exception:  # pragma: no cover - logged, client gets a generic error
            log.error("handler failed: %s", traceback.format_exc())
            self.send(ProtocolError(400, "bad_request", "request failed").frame(rid))

    def _first(self, t, obj, rid):
        r = self.relay
        if t == "hello" and frames.is_v2_hello(obj):
            f = frames.validate("hello", obj)
            if layouts.SUITE not in f["suites"]:
                raise ProtocolError(501, "not_supported", "no common suite", close=True)
            self.admit = f.get("admit")
            self.challenge = crypto.random_bytes(32)
            self.lines.max_line = frames.LINE_MAX
            self.state = "welcomed"
            proof = None
            if f.get("nonce") is not None:
                proof = b64e(r.sign(relaykey.welcome_bytes(r.relay_id, f["nonce"], self.challenge)))
            self.send(frames.welcome(r.relay_id, r.relay_key_b64(), b64e(self.challenge), r.cfg.legacy_v1,
                                     r.welcome_limits(), relay_sig_b64=proof, rotation=r.rotation))
            return
        if t == "hello":
            if not r.cfg.legacy_v1 or self.transport == "ws":
                r.metrics["v1_refused_total"] += 1
                raise ProtocolError(426, "upgrade_required", "this relay speaks SC2 v2 only", close=True)
            self.state = "v1"
            self.v1 = V1Client(r.v1, self)
            self.v1.handle(obj)
            if self.v1.authed and not self.closed:
                self.established = r.clock()
                if not r.make_room(self):
                    self.kick(503, "server_full")
            return
        f = {"type": "error", "code": 401, "err": "auth_required", "text": "hello required"}
        if rid is not None:
            f["rid"] = rid
        self.send(f)
        self.close()

    # ---------------- handshake ----------------

    def h_hello(self, f, rid):
        raise ProtocolError(400, "bad_request", "hello already received")

    def h_ping(self, f, rid):
        self.send(frames.frame("pong", rid))

    def h_auth(self, f, rid):
        r = self.relay
        if self.state != "welcomed":
            raise ProtocolError(400, "bad_request", "already authenticated")
        ik = b64d(f["ik"], 32)
        if not crypto.verify(ik, layouts.auth_bytes(r.relay_id, self.challenge, ik), b64d(f["sig"], 64)):
            raise ProtocolError(401, "bad_sig", "challenge signature invalid", close=True)
        dev = hexe(layouts.device_id(ik))
        store = r.store
        if store.is_purged(dev):
            raise ProtocolError(403, "forbidden", "device key was purged by the operator", close=True)
        if r.cfg.admission == "allowlist" and dev not in r.cfg.allowlist:
            raise ProtocolError(403, "admit_required", "device not on the allowlist", close=True)
        # one live session per device key: a new login replaces the old one
        # (a reconnect after a network change often leaves a half-open socket)
        for old in list(r.by_device.get(dev, ())):
            old.kick(409, "replaced", presence=False)
            r.metrics["sessions_replaced_total"] += 1
        self.established = r.clock()
        if not r.make_room(self):
            self.established = None
            raise ProtocolError(503, "server_full", close=True)
        now = r.now()
        row = store.device(dev)
        new = row is None
        if new:
            if r.cfg.admission == "code":
                if not self.admit or not hmac.compare_digest(self.admit.encode(), r.cfg.admit_code.encode()):
                    raise ProtocolError(403, "admit_required", None, close=True)
            wait = r.register_rate.take(self.ip or "-", r.clock())
            if wait:
                raise ProtocolError(429, "rate_limited", "too many new devices from this address", close=True,
                                    retry_ms=wait)
            store.register(dev, ik, now)
            r.metrics["devices_registered_total"] += 1
        else:
            store.touch(dev, now)
        self.device, self.ik, self.state = dev, ik, "authed"
        self.challenge = None
        r.by_device[dev].add(self)
        self.public_rooms = set(store.public_joined_rooms(dev))
        log.info("authed %s via %s (new=%s)", r.logid(dev), self.transport, new)
        self.send(frames.frame("authed", rid, device=dev, new=new, server_time=now))
        row = store.device(dev)
        if row["spk"] is not None:
            n = store.opk_count(dev)
            if n < r.cfg.keys_low:
                self.send({"type": "keys.low", "remaining": n})

    # ---------------- key directory ----------------

    def h_keys_publish(self, f, rid):
        r = self.relay
        dk, dk_sig = b64d(f["dk"], 32), b64d(f["dk_sig"], 64)
        if not crypto.verify(self.ik, layouts.dk_signed(dk), dk_sig):
            raise ProtocolError(401, "bad_sig", "dk_sig invalid")
        spk = f["spk"]
        spk_pub, spk_sig = b64d(spk["pub"], 32), b64d(spk["sig"], 64)
        if not crypto.verify(self.ik, layouts.spk_signed(spk["id"], spk_pub), spk_sig):
            raise ProtocolError(401, "bad_sig", "spk signature invalid")
        n = r.store.publish_keys(self.device, dk, dk_sig, spk["id"], spk_pub, spk_sig,
                                 [(o["id"], b64d(o["pub"], 32)) for o in f["opks"]], r.cfg.opk_max)
        self.send(frames.frame("ack", rid, opks=n))

    def h_keys_claim(self, f, rid):
        r = self.relay
        wait = r.claim_rate.take(self.device, r.clock())
        if wait:
            raise ProtocolError(429, "rate_limited", None, retry_ms=wait)
        dev = f["device"]
        d = r.store.device(dev)
        if d is None or d["spk"] is None or r.store.is_purged(dev):
            raise ProtocolError(404, "unknown_device")
        b = frames.frame("keys.bundle", rid, device=dev, ik=b64e(d["ik"]), dk=b64e(d["dk"]),
                         dk_sig=b64e(d["dk_sig"]),
                         spk={"id": d["spk_id"], "pub": b64e(d["spk"]), "sig": b64e(d["spk_sig"])})
        opk = r.store.claim_opk(dev)
        if opk is not None:
            b["opk"] = {"id": opk[0], "pub": b64e(opk[1])}
        self.send(b)
        r.metrics["keys_claimed_total"] += 1
        remaining = r.store.opk_count(dev)
        if remaining < r.cfg.keys_low:
            r.push(dev, {"type": "keys.low", "remaining": remaining}, live_only=False)
        if opk is None:
            raise ProtocolError(410, "prekey_exhausted", None, device=dev)

    # ---------------- DMs ----------------

    def h_dm_send(self, f, rid):
        r = self.relay
        env = f["env"]
        if env["from"] != self.device:
            raise ProtocolError(403, "forbidden", "env.from must be this device")
        to = f["to"]
        if r.store.device(to) is None or r.store.is_purged(to):
            raise ProtocolError(404, "unknown_device")
        wait = r.send_rate.take(self.device, r.clock(), r.cfg.send_per_min, r.cfg.send_burst)
        if wait:
            raise ProtocolError(429, "rate_limited", None, retry_ms=wait)
        dedup = env["from"] + ":" + env["rk"] + ":" + str(env["n"])
        seq = r.store.inbox_dedup(to, dedup)
        if seq is not None:
            self.send(frames.frame("ack", rid, seq=frames.fmt_seq(seq)))
            return
        msg = {"type": "dm.msg", "env": env}
        seq = r.inbox_deliver(to, "dm", msg, dedup=dedup)
        if seq is None:
            r.metrics["inbox_full_total"] += 1
            raise ProtocolError(507, "inbox_full", None, to=to)
        r.metrics["dm_total"] += 1
        self.send(frames.frame("ack", rid, seq=frames.fmt_seq(seq)))

    # ---------------- rooms ----------------

    def _private(self, room, member=True):
        r = self.relay
        row = r.store.room(room)
        if row is None or row["kind"] != "private":
            raise ProtocolError(404, "unknown_room")
        m = r.store.member(room, self.device)
        if member and m is None:
            raise ProtocolError(403, "not_member")
        return row, m

    def _public(self, room):
        row = self.relay.store.room(room)
        if row is None or row["kind"] != "public":
            raise ProtocolError(404, "unknown_room")
        return row

    def _load_state(self, room, row):
        ms = self.relay.store.members(room)
        pol = json.loads(row["policy"] or "{}")
        roster = {m["device"]: (rooms.ADMIN if m["admin"] else rooms.MEMBER) for m in ms}
        return RoomState(room, row["epoch"], roster, row["head"],
                         min(pol.get("max", self.relay.cfg.room_members_max), self.relay.cfg.room_members_max))

    def _check_added(self, devs):
        r = self.relay
        for d in devs:
            if r.store.device(d) is None or r.store.is_purged(d):
                raise ProtocolError(404, "unknown_device", "added device is not registered on this relay",
                                    device=d)
            if r.store.private_room_count(d) >= r.cfg.rooms_per_device:
                raise ProtocolError(403, "forbidden", "device is in too many rooms", device=d)

    def _commit_apply(self, room, new_state, f, old_members):
        r = self.relay
        st = r.store
        now = r.now()
        added = sorted(new_state.members - old_members)
        removed = sorted(old_members - new_state.members)
        with st.tx():
            seq = st.next_seq(room)
            cf = {"type": "room.commit", "room": room, "seq": frames.fmt_seq(seq), "commit": f["commit"],
                  "sig": f["sig"]}
            st.apply_commit(room, new_state, {"commit": f["commit"], "sig": f["sig"]}, seq, now, added, removed)
            st.room_log_add(room, seq, "commit", dumps(cf), now)
        r.fanout_private(room, cf)
        for d in removed:
            r.push(d, cf)
        for d in added:
            r.room_log_event(room, "joined", d)
            # a removal notice still waiting from an earlier removal is stale now
            st.inbox_drop(d, "removed:" + room)
        for d in removed:
            ev_seq = r.room_log_event(room, "removed", d)
            # At most one pending removal notice per (device, room), and it
            # counts against the inbox limit, so repeated add/remove cannot
            # grow an inbox. A skipped notice is not lost: sync replays the
            # removal event from the room log for rooms the device is no
            # longer a member of (h_sync).
            dedup = "removed:" + room
            if st.inbox_dedup(d, dedup) is not None:
                continue
            ev = {"type": "room.event", "room": room, "event": "removed", "device": d,
                  "room_seq": frames.fmt_seq(ev_seq)}
            if r.inbox_deliver(d, "event", ev, dedup=dedup) is None:
                r.metrics["removal_notices_skipped_total"] += 1
        return seq

    def h_room_create(self, f, rid):
        r = self.relay
        room = f["room"]
        if r.store.room(room) is not None:
            raise ProtocolError(403, "forbidden", "room already exists")
        if f["kind"] == "public":
            if r.cfg.public_room_create != "any":
                raise ProtocolError(403, "forbidden", "public rooms are created by the relay operator")
            r.store.create_room(room, "public", f["title"], {}, r.now())
            self.send(frames.frame("ack", rid, seq="0"))
            return
        if r.store.private_room_count(self.device) >= r.cfg.rooms_per_device:
            raise ProtocolError(403, "forbidden", "too many rooms")
        state = RoomState(room, 0, {}, "", min(f["policy"]["max"], r.cfg.room_members_max))
        new, _ = state.apply(b64d(f["commit"]), b64d(f["sig"]), r.verify_device, creator=self.device)
        with r.store.tx():
            r.store.create_room(room, "private", None, f["policy"], r.now())
            seq = self._commit_apply(room, new, f, set())
        r.metrics["rooms_created_total"] += 1
        self.send(frames.frame("ack", rid, seq=frames.fmt_seq(seq), epoch=new.epoch, head=new.head))

    def h_room_commit(self, f, rid):
        r = self.relay
        room = f["room"]
        row, m = self._private(room)
        state = self._load_state(room, row)
        new, _ = state.apply(b64d(f["commit"]), b64d(f["sig"]), r.verify_device)
        self._check_added(sorted(new.members - state.members))
        seq = self._commit_apply(room, new, f, state.members)
        self.send(frames.frame("ack", rid, seq=frames.fmt_seq(seq), epoch=new.epoch, head=new.head))

    def h_room_invite(self, f, rid):
        r = self.relay
        row, m = self._private(f["room"])
        if not m["admin"]:
            raise ProtocolError(403, "forbidden", "only room admins register invites")
        key = b64d(f["key"], 32)
        if f["revoke"]:
            r.store.revoke_invite(f["room"], key)
        else:
            r.store.add_invite(f["room"], key, r.now())
        self.send(frames.frame("ack", rid))

    def h_room_join(self, f, rid):
        r = self.relay
        room = f["room"]
        if frames.is_public_room(room):
            row = self._public(room)
            now = r.now()
            r.ban_check(self.device, self.ip, now)
            first = r.store.public_join(room, self.device)
            self.public_rooms.add(room)
            st = r.room_state(room, rid)
            per_min, burst, body_max, slow = r.post_policy(self.device, row, now)
            st["limits"] = {"msg": body_max, "per_min": per_min}
            st["first_join"] = first
            if first:
                st["notice"] = PUBLIC_NOTICE
            self.send(st)
            return
        row, m = self._private(room, member=False)
        if m is not None:
            if not m["routing"]:
                r.store.set_routing(room, self.device, True)
            self.send(r.room_state(room, rid))
            return
        if "invite" not in f:
            raise ProtocolError(403, "forbidden", "an invite is required for this room")
        wait = r.send_rate.take(self.device, r.clock(), r.cfg.send_per_min, r.cfg.send_burst)
        if wait:
            raise ProtocolError(429, "rate_limited", None, retry_ms=wait)
        proof = b64d(f["invite"], 32)
        ok = any(layouts.ct_equal(layouts.invite_proof(k, hexd(self.device, 16)), proof)
                 for k in r.store.invites(room))
        if not ok:
            raise ProtocolError(403, "forbidden", "invite not valid for this room")
        r.room_log_event(room, "join_request", self.device, audience="admins")
        self.send(frames.frame("ack", rid, status="requested"))

    def h_room_leave(self, f, rid):
        r = self.relay
        room = f["room"]
        if frames.is_public_room(room):
            self._public(room)
            r.store.public_leave(room, self.device)
            self.public_rooms.discard(room)
            self.send(frames.frame("ack", rid))
            return
        row, m = self._private(room)
        admins = [x["device"] for x in r.store.members(room) if x["admin"]]
        if m["admin"] and len(admins) == 1:
            raise ProtocolError(403, "forbidden", "the last admin cannot leave; promote another admin first")
        if m["routing"]:
            r.store.set_routing(room, self.device, False)
            r.room_log_event(room, "left", self.device)
        self.send(frames.frame("ack", rid))

    def h_room_members(self, f, rid):
        r = self.relay
        room = f["room"]
        if frames.is_public_room(room):
            row = self._public(room)
            st = r.room_state(room, rid)
            per_min, burst, body_max, slow = r.post_policy(self.device, row, r.now())
            st["limits"] = {"msg": body_max, "per_min": per_min}
            self.send(st)
            return
        self._private(room)
        self.send(r.room_state(room, rid))

    def h_room_list(self, f, rid):
        r = self.relay
        if f["kind"] == "public":
            rooms = [x["id"] for x in r.store.public_rooms()]
        else:
            rooms = r.store.private_rooms_of(self.device)
        for room in rooms:
            st = r.room_state(room, rid)
            if f["kind"] == "public":
                st["limits"] = {"msg": r.cfg.public_body_max, "per_min": r.cfg.post_per_min}
            self.send(st)
        self.send(frames.frame("ack", rid, count=len(rooms)))

    def h_room_send(self, f, rid):
        r = self.relay
        room = f["room"]
        row, m = self._private(room)
        if not m["routing"]:
            raise ProtocolError(403, "not_member", "you left this room")
        env = f["env"]
        if env["from"] != self.device:
            raise ProtocolError(403, "forbidden", "env.from must be this device")
        if env["e"] != row["epoch"]:
            raise ProtocolError(409, "stale_epoch", None, epoch=row["epoch"])
        if not crypto.verify(self.ik, frames.room_env_signed_bytes(room, env), b64d(env["sig"], 64)):
            raise ProtocolError(401, "bad_sig", "room message signature invalid")
        dedup = env["from"] + ":" + str(env["e"]) + ":" + str(env["n"])
        seq = r.store.room_log_dedup(room, dedup)
        if seq is not None:
            self.send(frames.frame("ack", rid, seq=frames.fmt_seq(seq)))
            return
        wait = r.send_rate.take(self.device, r.clock(), r.cfg.send_per_min, r.cfg.send_burst)
        if wait:
            raise ProtocolError(429, "rate_limited", None, retry_ms=wait)
        with r.store.tx():
            seq = r.store.next_seq(room)
            msg = {"type": "room.msg", "room": room, "seq": frames.fmt_seq(seq), "env": env}
            r.store.room_log_add(room, seq, "msg", dumps(msg), r.now(), dedup=dedup)
        r.metrics["room_msgs_total"] += 1
        self.send(frames.frame("ack", rid, seq=frames.fmt_seq(seq)))
        r.fanout_private(room, msg, exclude=self)

    def h_room_post(self, f, rid):
        r = self.relay
        room = f["room"]
        row = self._public(room)
        if room not in self.public_rooms:
            raise ProtocolError(403, "not_member", "join the room first")
        post = f["post"]
        now = r.now()
        # 1. verify the signature (bound to this relay and room)
        if not crypto.verify(b64d(post["ik"], 32), layouts.post_signed_bytes(r.relay_id, room, post),
                             b64d(post["sig"], 64)):
            raise ProtocolError(401, "bad_sig", "post signature invalid")
        # 2. from / ik: validate_post checked from == SHA-256(ik)[0:16]; the key must be the session's
        if post["from"] != self.device:
            raise ProtocolError(403, "forbidden", "post must be signed by this device")
        # 3. limits
        per_min, burst, body_max, slow = r.post_policy(self.device, row, now)
        if len(post["body"].encode()) > body_max:
            raise ProtocolError(413, "too_large", "body over the room limit", limit=body_max)
        # 4. dedup (from, id)
        old = r.store.post_by_id(room, post["from"], post["id"])
        if old is not None:
            self.send(frames.frame("ack", rid, seq=frames.fmt_seq(old["seq"])))
            return
        if post["t"] == "del":
            # a delete names the author's own post: (room, from, ref)
            if r.store.post_by_id(room, post["from"], post["ref"]) is None:
                raise ProtocolError(400, "bad_request", "unknown ref")
        # 5. rate limits and slow mode
        clock = r.clock()
        for wait in (r.post_key.take(self.device, clock, per_min, burst),
                     r.post_ip.take(self.ip or "-", clock, r.cfg.ip_post_per_min, r.cfg.ip_post_burst),
                     r.post_room.take(room, clock, r.cfg.room_post_per_min, max(10, r.cfg.room_post_per_min // 6))):
            if wait:
                raise ProtocolError(429, "rate_limited", None, retry_ms=wait)
        # 6. bans and mutes
        r.ban_check(self.device, self.ip, now)
        r.mute_check(self.device, self.ip, now)
        # 7. append and fan out
        with r.store.tx():
            seq = r.store.next_seq(room)
            r.store.public_add(room, seq, post, now)
            if post["t"] == "del":
                r.store.mark_deleted(room, post["from"], post["ref"])
            r.store.note_post(self.device)
        r.metrics["public_posts_total"] += 1
        self.send(frames.frame("ack", rid, seq=frames.fmt_seq(seq)))
        r.fanout_public(room, {"type": "room.pub", "room": room, "seq": frames.fmt_seq(seq), "post": post},
                        exclude=self)

    def h_room_report(self, f, rid):
        r = self.relay
        self._public(f["room"])
        wait = r.report_rate.take(self.device, r.clock())
        if wait:
            raise ProtocolError(429, "rate_limited", None, retry_ms=wait)
        post = r.resolve_post(f["room"], f["ref"], f.get("author"))
        if post is None:
            raise ProtocolError(400, "bad_request", "unknown ref")
        r.store.add_report(f["room"], f["ref"], self.device, f["reason"], r.now(), author=post["from_dev"])
        r.metrics["reports_total"] += 1
        self.send(frames.frame("ack", rid))

    # ---------------- sync ----------------

    def h_sync(self, f, rid):
        r = self.relay
        st = r.store
        budget = f["max"]
        more = False
        inbox_cursor = f["inbox"]
        for row in st.inbox_after(self.device, inbox_cursor, budget + 1):
            if budget == 0:
                more = True
                break
            self.send(with_seq(json.loads(row["data"]), row["seq"]))
            inbox_cursor = row["seq"]
            budget -= 1
        done_rooms = {}
        for room, cursor in f["rooms"].items():
            row = st.room(room)
            if row is None:
                self.send(ProtocolError(404, "unknown_room", None, room=room).frame(rid))
                continue
            if row["kind"] == "private":
                m = st.member(room, self.device)
                if m is None:
                    # removed: send the room's record of it first, so a device whose
                    # inbox notice was skipped (inbox full) still learns why
                    ev = st.removal_event(room, self.device)
                    if ev is not None:
                        self.write_line((ev + "\n").encode())
                    self.send(ProtocolError(403, "not_member", None, room=room).frame(rid))
                    continue
                lo, hi = st.room_log_range(room)
                after, gap = limits.sync_window(cursor, lo, hi, m["join_seq"])
                is_admin = bool(m["admin"])
            else:
                lo, hi = st.public_range(room)
                after, gap = limits.sync_window(cursor, lo, hi, 1)
                is_admin = False
            if gap is not None:
                self.send({"type": "sync.gap", "room": room, "from": frames.fmt_seq(gap[0]),
                           "oldest": frames.fmt_seq(gap[1])})
            last = after
            if budget == 0:
                more = more or (hi is not None and after < hi)
                done_rooms[room] = frames.fmt_seq(last)
                continue
            if row["kind"] == "private":
                items = st.room_log_after(room, after, budget + 1)
                for it in items:
                    if budget == 0:
                        more = True
                        break
                    last = it["seq"]
                    if it["audience"] == "admins" and not is_admin:
                        continue
                    self.write_line((it["data"] + "\n").encode())
                    budget -= 1
            else:
                for seq, kind, data in st.public_after(room, after, budget + 1):
                    if budget == 0:
                        more = True
                        break
                    last = seq
                    if kind == "post":
                        self.send({"type": "room.pub", "room": room, "seq": frames.fmt_seq(seq),
                                   "post": json.loads(data)})
                    else:
                        self.write_line((data + "\n").encode())
                    budget -= 1
                else:
                    if hi is not None and last < hi:
                        last = hi  # trailing removed posts
            done_rooms[room] = frames.fmt_seq(last)
        self.send(frames.frame("sync.done", rid, inbox=frames.fmt_seq(inbox_cursor), rooms=done_rooms, more=more))
        if not more:
            self.live = True

    def h_ack(self, f, rid):
        self.relay.store.inbox_ack(self.device, f["inbox"])

    # ---------------- presence ----------------

    def h_presence_set(self, f, rid):
        state = f["state"]
        prev = self.presence
        self.presence = state
        if state == "hidden":
            if prev in ("online", "away"):
                self._broadcast_presence("offline")
        else:
            self._broadcast_presence(state)
        if rid is not None:
            self.send(frames.frame("ack", rid))

    def _broadcast_presence(self, state):
        r = self.relay
        for dev, rooms in r.store.shared_rooms(self.device).items():
            r.push(dev, {"type": "presence", "device": self.device, "state": state, "rooms": sorted(rooms)})
