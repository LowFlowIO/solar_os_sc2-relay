"""HTTP surface: well-known, health, metrics, read-only web view of public
rooms, the WebSocket endpoint and the operator admin API (draft §8.1, §8.1a).

A deliberately small HTTP/1.1 implementation on asyncio streams: one request
per connection (Connection: close), bounded headers and bodies, no cookies.

SPDX-License-Identifier: MIT
"""

import asyncio
import base64
import datetime
import hashlib
import hmac
import html
import json
import logging
import urllib.parse

from sc2proto import ProtocolError, dumps, frames, is_hex, limits, valid_text

log = logging.getLogger("sc2_relay.http")

MAX_HEADER = 8192
MAX_BODY = 65536
WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
REASONS = {200: "OK", 101: "Switching Protocols", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
           404: "Not Found", 405: "Method Not Allowed", 413: "Payload Too Large", 429: "Too Many Requests",
           501: "Not Implemented", 503: "Service Unavailable"}


class HttpError(Exception):
    def __init__(self, status, message):
        Exception.__init__(self, message)
        self.status = status
        self.message = message


class Request:
    def __init__(self, method, target, headers, body, ip):
        self.method = method
        u = urllib.parse.urlsplit(target)
        self.path = urllib.parse.unquote(u.path)
        self.query = {k: v[-1] for k, v in urllib.parse.parse_qs(u.query, keep_blank_values=True).items()}
        self.headers = headers
        self.body = body
        self.ip = ip

    def json(self):
        if not self.body:
            return {}
        try:
            obj = json.loads(self.body.decode())
        except (ValueError, UnicodeError):
            raise HttpError(400, "body must be JSON")
        if not isinstance(obj, dict) or not valid_text(obj):
            raise HttpError(400, "body must be a JSON object")
        return obj


class Response:
    def __init__(self, status=200, body=b"", ctype="application/json", headers=None):
        self.status = status
        self.body = body if isinstance(body, bytes) else body.encode()
        self.ctype = ctype
        self.headers = dict(headers or {})

    def encode(self):
        lines = ["HTTP/1.1 %d %s" % (self.status, REASONS.get(self.status, "Status"))]
        h = {"Content-Type": self.ctype, "Content-Length": str(len(self.body)), "Connection": "close",
             "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"}
        h.update(self.headers)
        for k, v in h.items():
            lines.append(k + ": " + v)
        return ("\r\n".join(lines) + "\r\n\r\n").encode() + self.body


def json_response(obj, status=200, headers=None):
    return Response(status, dumps(obj) + "\n", "application/json; charset=utf-8", headers)


async def read_request(reader, ip):
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = await reader.read(1024)
        if not chunk:
            raise HttpError(400, "incomplete request")
        head += chunk
        if len(head) > MAX_HEADER + MAX_BODY:
            raise HttpError(413, "headers too large")
    raw, _, rest = head.partition(b"\r\n\r\n")
    if len(raw) > MAX_HEADER:
        raise HttpError(413, "headers too large")
    try:
        lines = raw.decode("latin-1").split("\r\n")
        method, target, version = lines[0].split(" ")
    except ValueError:
        raise HttpError(400, "bad request line")
    if not version.startswith("HTTP/1."):
        raise HttpError(400, "HTTP/1.x only")
    headers = {}
    for ln in lines[1:]:
        k, sep, v = ln.partition(":")
        if not sep:
            raise HttpError(400, "bad header")
        headers[k.strip().lower()] = v.strip()
    n = 0
    if "content-length" in headers:
        try:
            n = int(headers["content-length"])
        except ValueError:
            raise HttpError(400, "bad content-length")
        if n < 0 or n > MAX_BODY:
            raise HttpError(413, "body too large")
    if "transfer-encoding" in headers:
        raise HttpError(501, "chunked bodies are not supported")
    body = rest
    while len(body) < n:
        chunk = await reader.read(n - len(body))
        if not chunk:
            raise HttpError(400, "incomplete body")
        body += chunk
    return Request(method.upper(), target, headers, body[:n], ip)


# ---------------- public HTTP ----------------

class PublicHttp:
    def __init__(self, relay, ws_handler=None):
        self.relay = relay
        self.ws_handler = ws_handler
        self.rate = limits.RateTable(relay.cfg.web_rate_per_min, max(10, relay.cfg.web_rate_per_min // 4))

    def web_headers(self):
        h = {"Cache-Control": "public, max-age=15",
             "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; "
                                        "base-uri 'none'; form-action 'none'",
             "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"}
        if self.relay.cfg.web_noindex:
            h["X-Robots-Tag"] = "noindex"
        return h

    async def handle(self, req, reader, writer):
        r = self.relay
        if req.method not in ("GET", "HEAD"):
            raise HttpError(405, "read-only")
        p = req.path
        if p == "/sc2" and r.cfg.websocket:
            if req.headers.get("upgrade", "").lower() == "websocket":
                await self.ws_handler(req, reader, writer)
                return None
            raise HttpError(400, "WebSocket upgrade required")
        if p == "/.well-known/solaros-relay":
            return json_response(r.well_known(), headers={"Cache-Control": "public, max-age=60",
                                                          "Access-Control-Allow-Origin": "*"})
        if p == "/healthz":
            r.store.scalar("SELECT 1")
            return Response(200, "ok\n", "text/plain; charset=utf-8", {"Cache-Control": "no-store"})
        if p == "/metrics" and r.cfg.metrics:
            return Response(200, self.metrics(), "text/plain; version=0.0.4; charset=utf-8",
                            {"Cache-Control": "no-store"})
        if r.cfg.web_view and (p.startswith("/public") or p.startswith("/api/public/")):
            wait = self.rate.take(req.ip or "-", r.clock())
            if wait:
                return Response(429, "slow down\n", "text/plain; charset=utf-8",
                                {"Retry-After": str(max(1, wait // 1000))})
            if p in ("/public", "/public/"):
                return Response(200, self.page_index(), "text/html; charset=utf-8", self.web_headers())
            if p.startswith("/public/"):
                room = self._room(p[len("/public/"):])
                return Response(200, self.page_room(room, req.query.get("before")), "text/html; charset=utf-8",
                                self.web_headers())
            room = self._room(p[len("/api/public/"):])
            return json_response(self.api_room(room, req.query.get("after"), req.query.get("limit")),
                                 headers=dict(self.web_headers(), **{"Access-Control-Allow-Origin": "*"}))
        raise HttpError(404, "not found")

    def _room(self, name):
        name = name.strip("/")
        try:
            room = frames.public_room_name(name)
        except ValueError:
            raise HttpError(404, "unknown room")
        row = self.relay.store.room(room)
        if row is None or row["kind"] != "public":
            raise HttpError(404, "unknown room")
        return room

    def metrics(self):
        r = self.relay
        st = r.store.stats()
        lines = []

        def g(name, help_, kind, value):
            lines.append("# HELP sc2_%s %s" % (name, help_))
            lines.append("# TYPE sc2_%s %s" % (name, kind))
            lines.append("sc2_%s %s" % (name, value))

        g("connections", "Open client connections.", "gauge", len(r.sessions))
        g("devices_online", "Authenticated devices with at least one connection.", "gauge", len(r.by_device))
        g("devices", "Registered device keys.", "gauge", st["devices"])
        g("rooms_private", "Private rooms.", "gauge", st["rooms_private"])
        g("rooms_public", "Public rooms.", "gauge", st["rooms_public"])
        g("inbox_items", "Undelivered inbox items (queue depth).", "gauge", st["inbox_items"])
        g("inbox_bytes", "Undelivered inbox bytes.", "gauge", st["inbox_bytes"])
        g("room_log_entries", "Retained private room log entries.", "gauge", st["room_log"])
        g("public_log_entries", "Retained public posts.", "gauge", st["public_log"])
        g("reports_open", "Unresolved room.report entries.", "gauge", st["reports_open"])
        for k in sorted(r.metrics):
            name = k if k.endswith("_total") else k + "_total"
            g(name, "Counter " + k.replace("_", " ") + ".", "counter", r.metrics[k])
        return "\n".join(lines) + "\n"

    # web view pages

    def _page(self, title, body):
        return ("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
                "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
                + ("<meta name=\"robots\" content=\"noindex\">" if self.relay.cfg.web_noindex else "") +
                "<title>" + html.escape(title) + "</title><style>"
                "body{font-family:system-ui,sans-serif;max-width:46rem;margin:1rem auto;padding:0 1rem;color:#222}"
                ".tag{display:inline-block;background:#fde68a;border-radius:.3rem;padding:0 .4rem;font-size:.8rem}"
                ".post{border-bottom:1px solid #ddd;padding:.4rem 0}.meta{color:#666;font-size:.8rem}"
                ".body{white-space:pre-wrap;word-wrap:break-word}code{font-size:.8rem}"
                "</style></head><body>" + body + "</body></html>\n")

    def page_index(self):
        r = self.relay
        items = []
        for row in r.store.public_rooms():
            name = row["id"][4:]
            items.append("<li><a href=\"/public/%s\">%s</a> <span class=\"meta\">%d members</span></li>" % (
                urllib.parse.quote(name), html.escape(row["title"] or row["id"]),
                r.store.public_member_count(row["id"])))
        body = ("<h1>Public rooms on %s</h1><p><span class=\"tag\">PUBLIC \u00b7 not encrypted</span> "
                "Read-only view. Posts are signed by their authors' device keys; the "
                "<a href=\"/.well-known/solaros-relay\">relay key</a> signs removals.</p><ul>%s</ul>"
                % (html.escape(r.relay_id), "".join(items) or "<li>none</li>"))
        return self._page("Public rooms", body)

    def page_room(self, room, before):
        r = self.relay
        row = r.store.room(room)
        try:
            b = frames.parse_seq(before, "before") if before else frames.U64
        except ProtocolError:
            raise HttpError(400, "before must be a sequence number")
        rows = r.store.web_posts_before(room, b, r.cfg.web_page_size)
        posts = []
        for p in rows:
            post = json.loads(p["post"])
            ts = datetime.datetime.fromtimestamp(min(post["ts"], 253402300799),
                                                 datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            posts.append("<div class=\"post\" id=\"s%d\"><div class=\"meta\"><b>%s</b> \u00b7%s \u00b7 %s \u00b7 "
                         "<a href=\"#s%d\">#%d</a></div><div class=\"body\">%s</div></div>" % (
                             p["seq"], html.escape(post["name"] or "?"), html.escape(post["from"][:8]),
                             html.escape(ts), p["seq"], p["seq"], html.escape(post["body"])))
        nav = ""
        if rows and len(rows) == r.cfg.web_page_size:
            nav = "<p><a href=\"/public/%s?before=%d\">older posts</a></p>" % (
                urllib.parse.quote(room[4:]), rows[-1]["seq"])
        body = ("<p><a href=\"/public/\">all rooms</a></p><h1>%s</h1><p><span class=\"tag\">PUBLIC \u00b7 not "
                "encrypted</span> Anyone can read this room. Signed posts as JSON: "
                "<a href=\"/api/public/%s\"><code>/api/public/%s</code></a></p>%s%s" % (
                    html.escape(row["title"] or room), urllib.parse.quote(room[4:]), html.escape(room[4:]),
                    "".join(posts) or "<p>No posts yet.</p>", nav))
        return self._page(row["title"] or room, body)

    def api_room(self, room, after, limit):
        try:
            a = frames.parse_seq(after, "after") if after else 0
            n = int(limit) if limit else 100
        except (ProtocolError, ValueError):
            raise HttpError(400, "bad after/limit")
        n = max(1, min(200, n))
        store = self.relay.store
        items = [(p["seq"], "post", p["post"]) for p in store.web_posts_after(room, a, n)]
        items += [(m["seq"], "mod", m["frame"]) for m in store.web_mods_after(room, a, n)]
        items = sorted(items)[:n]
        # relay-signed removals and bans ride along so readers can verify them too
        posts = [{"seq": frames.fmt_seq(s), "post": json.loads(v)} for s, k, v in items if k == "post"]
        mods = [json.loads(v) for s, k, v in items if k == "mod"]
        nxt = frames.fmt_seq(items[-1][0]) if items else frames.fmt_seq(a)
        return {"room": room, "posts": posts, "mods": mods, "next": nxt}


# ---------------- admin API ----------------

class AdminHttp:
    def __init__(self, relay):
        self.relay = relay

    def _auth(self, req):
        tok = self.relay.cfg.admin_token
        got = req.headers.get("authorization", "")
        if not tok or not got.startswith("Bearer ") or not hmac.compare_digest(got[7:].encode(), tok.encode()):
            raise HttpError(401, "admin token required")

    @staticmethod
    def _until(body, now):
        if body.get("duration") is not None:
            d = body["duration"]
            if isinstance(d, bool) or not isinstance(d, int) or d <= 0:
                raise HttpError(400, "duration must be positive seconds")
            return now + d
        u = body.get("until")
        if u is None:
            return None
        if isinstance(u, bool) or not isinstance(u, int) or u <= now:
            raise HttpError(400, "until must be a future unix time or null")
        return u

    @staticmethod
    def _device(v):
        if not is_hex(v, 32):
            raise HttpError(400, "device must be a 32 hex device ID")
        return v

    def _room(self, v):
        try:
            room = frames.public_room_name(str(v))
        except ValueError:
            raise HttpError(400, "room must be a public room name")
        row = self.relay.store.room(room)
        if row is None:
            raise HttpError(404, "unknown room")
        return room

    async def handle(self, req, reader, writer):
        self._auth(req)
        r = self.relay
        st = r.store
        now = r.now()
        key = (req.method, req.path.rstrip("/") or "/")
        b = req.json() if req.method == "POST" else {}
        if key == ("GET", "/admin/status"):
            return json_response({"relay_id": r.relay_id, "profile": r.cfg.profile, "stats": st.stats(),
                                  "connections": len(r.sessions), "devices_online": len(r.by_device),
                                  "admission": r.cfg.admission, "legacy_v1": r.cfg.legacy_v1,
                                  "tunables": {k: getattr(r.cfg, k) for k in _public_tunables()},
                                  "schema": st.version()})
        if key == ("GET", "/admin/rooms"):
            return json_response({"rooms": st.room_sizes()})
        if key == ("GET", "/admin/posts"):
            room = self._room(req.query.get("room", "general"))
            try:
                lim = max(1, min(500, int(req.query.get("limit", "50") or 50)))
            except ValueError:
                raise HttpError(400, "limit must be an integer")
            rows = st.search_posts(room, req.query.get("q", ""), lim)
            return json_response({"room": room, "posts": [
                {"seq": str(x["seq"]), "removed": bool(x["removed"]), "deleted": bool(x["deleted"]),
                 "received": x["ts"], "post": json.loads(x["post"])} for x in rows]})
        if key == ("POST", "/admin/remove"):
            room = self._room(b.get("room", ""))
            ref = b.get("ref")
            if not is_hex(ref, 16):
                raise HttpError(400, "ref must be a 16 hex message ID")
            dev = self._device(b["device"]) if b.get("device") else None
            n = r.mod_remove(room, ref, dev)
            if n == 0:
                raise HttpError(404, "no such post")
            return json_response({"removed": n})
        if key == ("POST", "/admin/ban"):
            until = self._until(b, now)
            reason = str(b.get("reason", ""))[:256]
            if not b.get("device") and not b.get("ip"):
                raise HttpError(400, "give device and/or ip")
            out = {"until": until}
            if b.get("device"):
                r.mod_ban_key(self._device(b["device"]), until, reason, bool(b.get("remove_posts")))
                out["device"] = b["device"]
            if b.get("ip"):
                r.mod_ban_ip(str(b["ip"]), until, reason)
                out["ip"] = b["ip"]
            return json_response(out)
        if key == ("POST", "/admin/unban"):
            n = 0
            if b.get("device"):
                n += st.lift_ban("bans", "key", self._device(b["device"]))
            if b.get("ip"):
                n += st.lift_ban("bans", "ip", str(b["ip"]))
            return json_response({"lifted": n})
        if key == ("GET", "/admin/bans"):
            return json_response({"bans": st.list_bans("bans", now)})
        if key in (("POST", "/admin/mute"), ("POST", "/admin/unmute"), ("GET", "/admin/mutes")):
            if not r.cfg.mutes:
                raise HttpError(501, "mutes are disabled (SC2_MUTES=false)")
            if key[1] == "/admin/mutes":
                return json_response({"mutes": st.list_bans("mutes", now)})
            if not b.get("device") and not b.get("ip"):
                raise HttpError(400, "give device and/or ip")
            if key[1] == "/admin/unmute":
                n = 0
                if b.get("device"):
                    n += st.lift_ban("mutes", "key", self._device(b["device"]))
                if b.get("ip"):
                    n += st.lift_ban("mutes", "ip", str(b["ip"]))
                return json_response({"lifted": n})
            until = self._until(b, now)
            if b.get("device"):
                st.set_ban("mutes", "key", self._device(b["device"]), until, str(b.get("reason", ""))[:256], now)
            if b.get("ip"):
                st.set_ban("mutes", "ip", str(b["ip"]), until, str(b.get("reason", ""))[:256], now)
            return json_response({"until": until})
        if key == ("GET", "/admin/reports"):
            return json_response({"reports": st.reports(req.query.get("all") in ("1", "true"))})
        if key == ("POST", "/admin/reports/resolve"):
            if not isinstance(b.get("id"), int) or not st.resolve_report(b["id"]):
                raise HttpError(404, "no such report")
            return json_response({"resolved": b["id"]})
        if key == ("POST", "/admin/slowmode"):
            room = self._room(b.get("room", ""))
            st.set_slow(room, bool(b.get("on", True)))
            return json_response({"room": room, "slow": bool(b.get("on", True))})
        if key == ("POST", "/admin/tune"):
            out = {}
            for k, v in b.items():
                if k not in _public_tunables():
                    raise HttpError(400, "unknown tunable " + k)
                if isinstance(v, bool) or not isinstance(v, int) or v <= 0:
                    raise HttpError(400, k + " must be a positive integer")
                r.set_tunable(k, v)
                out[k] = v
            return json_response({"tuned": out})
        if key == ("POST", "/admin/admission"):
            mode = b.get("mode")
            if mode not in ("open", "code", "allowlist"):
                raise HttpError(400, "mode must be open, code or allowlist")
            if mode == "code":
                code = b.get("code") or r.cfg.admit_code
                if not isinstance(code, str) or not code or len(code.encode()) > frames.ADMIT_MAX:
                    raise HttpError(400, "code admission needs a code (at most 96 bytes)")
                r.set_tunable("admit_code", code)
            if mode == "allowlist" and b.get("allowlist") is not None:
                lst = [self._device(d) for d in b["allowlist"]]
                r.cfg.allowlist = lst
            r.set_tunable("admission", mode)
            return json_response({"admission": mode})
        if key == ("POST", "/admin/purge"):
            dev = self._device(b.get("device", ""))
            if st.device(dev) is None:
                raise HttpError(404, "unknown device")
            r.purge_device(dev)
            return json_response({"purged": dev})
        if key == ("POST", "/admin/retention"):
            return json_response({"deleted": r.retention()})
        raise HttpError(404, "unknown admin endpoint")


def _public_tunables():
    from .core import TUNABLE
    return tuple(k for k in TUNABLE if k not in ("admission", "admit_code"))


async def serve_http(app, reader, writer):
    peer = writer.get_extra_info("peername")
    ip = peer[0] if isinstance(peer, tuple) else ""
    try:
        try:
            req = await asyncio.wait_for(read_request(reader, ip), 15)
            if app.relay.cfg.trust_proxy and req.headers.get("x-forwarded-for"):
                req.ip = req.headers["x-forwarded-for"].split(",")[0].strip()
            resp = await app.handle(req, reader, writer)
            if resp is None:
                return  # WebSocket took over the connection
            if req.method == "HEAD":
                resp_bytes = resp.encode()
                resp_bytes = resp_bytes[:resp_bytes.index(b"\r\n\r\n") + 4]
                writer.write(resp_bytes)
            else:
                writer.write(resp.encode())
        except HttpError as e:
            writer.write(json_response({"error": e.message}, e.status).encode())
        except asyncio.TimeoutError:
            return
        except (ConnectionError, asyncio.IncompleteReadError):
            return
        except Exception:
            log.exception("http handler failed")
            writer.write(json_response({"error": "internal error"}, 503).encode())
        try:
            await writer.drain()
        except ConnectionError:
            pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


def ws_accept_key(key):
    return base64.b64encode(hashlib.sha1(key.encode() + WS_GUID).digest()).decode()
