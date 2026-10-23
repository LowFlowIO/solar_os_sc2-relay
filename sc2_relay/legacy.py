"""Legacy v1 chat (INSECURE: unencrypted, unsigned), chatd-compatible.

Speaks the NDJSON protocol of src/jobs/solar_os_chatd_job.c so existing
SolarOS gateway clients keep working against the reference relay. v1
channels live in their own tables and are never bridged to SC2 v2 rooms in
either direction (draft §5.3). Enabled by SC2_LEGACY_V1 (default true; the
official profile forces false and answers v1 hello with 426).

SPDX-License-Identifier: MIT
"""

import hmac
import logging

from sc2proto import dumpb

log = logging.getLogger("sc2_relay.v1")

DEFAULT_CHANNEL = "general"
TOKEN_MAX = 96      # buffer sizes in chatd, NUL included
USER_MAX = 64
DEVICE_MAX = 64
CHANNEL_MAX = 64
TEXT_MAX = 4096


def _text_ok(text, size, allow_empty):
    if not isinstance(text, str):
        return allow_empty
    n = len(text.encode())
    if n >= size or (not allow_empty and n == 0):
        return False
    for ch in text:
        o = ord(ch)
        if o < 0x20 or o == 0x7F:
            return False
    return True


def channel_valid(name):
    if not _text_ok(name, CHANNEL_MAX, False):
        return False
    for ch in name:
        if ch.isspace() or ch in "/\\":
            return False
    return True


def _scan_str(obj, key, size):
    """Mirror solar_os_json_scan_object_string: a string field that fits."""
    v = obj.get(key)
    if not isinstance(v, str) or len(v.encode()) >= size:
        return None
    return v


def event(type_, channel=None, frm=None, text=None, ts=None, msg_id=None, code=None):
    f = {"type": type_}
    if channel is not None:
        f["channel"] = channel
    if frm is not None:
        f["from"] = frm
    if text is not None:
        f["text"] = text
    if ts is not None:
        f["ts"] = ts
    if msg_id:
        f["id"] = msg_id
    if code is not None:
        f["code"] = code
    return f


class V1Hub:
    """All v1 clients and channels of one relay."""

    def __init__(self, relay):
        self.relay = relay
        self.store = relay.store
        self.clients = set()
        if DEFAULT_CHANNEL not in self.store.v1_channels():
            self.store.v1_add_channel(DEFAULT_CHANNEL, 0)

    def now_ms(self):
        return int(self.relay.clock() * 1000)

    def channels(self):
        return self.store.v1_channels()

    def broadcast(self, frame, channel=None, exclude=None):
        line = dumpb(frame)
        for c in list(self.clients):
            if c is exclude or not c.authed:
                continue
            if channel is not None and channel not in c.joined:
                continue
            c.session.write_line(line)


class V1Client:
    def __init__(self, hub, session):
        self.hub = hub
        self.session = session
        self.authed = False
        self.user = ""
        self.device = ""
        self.frm = ""
        self.joined = set()
        hub.clients.add(self)

    def send(self, frame):
        self.session.write_line(dumpb(frame))

    def error(self, text, code, channel=None):
        self.send(event("error", channel=channel, text=text, code=code))

    def handle(self, obj):
        t = obj.get("type")
        if not isinstance(t, str) or len(t.encode()) >= 24:
            self.error("missing type", 400)
            return
        if t == "hello":
            self._hello(obj)
            return
        if not self.authed:
            self.error("hello required", 401)
            self.session.close()
            return
        if t == "join":
            ch = _scan_str(obj, "channel", CHANNEL_MAX)
            if ch is None:
                ch = DEFAULT_CHANNEL
            cursor = obj.get("cursor", 0)
            if isinstance(cursor, bool) or not isinstance(cursor, int) or cursor < 0:
                cursor = 0
            self._join(ch, cursor)
        elif t == "leave":
            ch = _scan_str(obj, "channel", CHANNEL_MAX)
            self._leave(DEFAULT_CHANNEL if ch is None else ch)
        elif t == "delete":
            ch = _scan_str(obj, "channel", CHANNEL_MAX)
            if ch is None:
                self.error("missing channel", 400)
                return
            self._delete(ch)
        elif t == "msg":
            ch = _scan_str(obj, "channel", CHANNEL_MAX)
            if ch is None:
                ch = DEFAULT_CHANNEL
            text = _scan_str(obj, "text", TEXT_MAX)
            if text is None:
                self.error("missing text", 400)
                return
            self._message(ch, text)
        else:
            self.error("unknown type", 400)

    def _hello(self, obj):
        token = _scan_str(obj, "token", TOKEN_MAX) or ""
        want = self.hub.relay.cfg.legacy_v1_token
        if want and not _const_eq(token, want):
            self.error("auth failed", 401)
            self.session.close()
            return
        user = _scan_str(obj, "user", USER_MAX)
        device = _scan_str(obj, "device", DEVICE_MAX)
        if user is None or not _text_ok(user, USER_MAX, True) or user == "":
            user = "user"
        if device is None or not _text_ok(device, DEVICE_MAX, True):
            device = "sol"
        self.user, self.device = user, device
        self.frm = user + "@" + device if device else user
        if not self.authed:
            self.hub.relay.metrics["v1_connections_total"] += 1
        self.authed = True
        self.send(event("connected", frm="chatd", text="connected", ts=self.hub.now_ms()))
        for ch in self.hub.channels():
            self.send({"type": "channel", "name": ch})

    def _join(self, ch, cursor):
        hub, store = self.hub, self.hub.store
        chans = hub.channels()
        created = False
        if ch not in chans:
            if not channel_valid(ch) or len(chans) >= hub.relay.cfg.v1_max_channels:
                self.error("invalid or full channel", 400)
                return
            store.v1_add_channel(ch, hub.now_ms())
            created = True
        if created:
            hub.broadcast({"type": "channel", "name": ch})
        else:
            self.send({"type": "channel", "name": ch})
        first = ch not in self.joined
        self.joined.add(ch)
        self.send(event("joined", ch, self.frm, "joined", hub.now_ms()))
        for r in store.v1_history(ch, cursor, hub.relay.cfg.v1_history):
            self.send(event("msg", ch, r["from_user"], r["text"], r["ts"], r["id"]))
        if first:
            hub.broadcast(event("presence", ch, self.frm, "joined", hub.now_ms()), ch, exclude=self)

    def _leave(self, ch):
        hub = self.hub
        if ch not in hub.channels():
            self.error("unknown channel", 404)
            return
        was = ch in self.joined
        self.joined.discard(ch)
        self.send(event("left", ch, self.frm, "left", hub.now_ms()))
        if was:
            hub.broadcast(event("presence", ch, self.frm, "left", hub.now_ms()), ch, exclude=self)

    def _delete(self, ch):
        hub = self.hub
        if ch not in hub.channels():
            self.error("unknown channel", 404)
            return
        if ch == DEFAULT_CHANNEL:
            self.error("default channel cannot be deleted", 403, channel=ch)
            return
        hub.broadcast(event("deleted", ch, self.frm, "deleted", hub.now_ms()))
        hub.store.v1_delete_channel(ch)
        for c in hub.clients:
            c.joined.discard(ch)

    def _message(self, ch, text):
        hub = self.hub
        if ch not in hub.channels():
            self.error("unknown channel", 404)
            return
        if ch not in self.joined:
            self.error("not joined", 403, channel=ch)
            return
        ts = hub.now_ms()
        msg_id = hub.store.v1_add_msg(ch, self.frm, text, ts)
        hub.relay.metrics["v1_messages_total"] += 1
        hub.broadcast(event("msg", ch, self.frm, text, ts, msg_id), ch)

    def closed(self):
        hub = self.hub
        hub.clients.discard(self)
        if self.authed:
            for ch in list(self.joined):
                hub.broadcast(event("presence", ch, self.frm, "left", hub.now_ms()), ch, exclude=self)
        self.joined.clear()


def _const_eq(a, b):
    return hmac.compare_digest(a.encode(), b.encode())
