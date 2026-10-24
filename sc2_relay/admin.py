"""Operator CLI for the relay admin API.

    python -m sc2_relay.admin [--url URL] [--token TOKEN] COMMAND [ARGS]

The token defaults to $SC2_ADMIN_TOKEN and the URL to
http://127.0.0.1:7780 (SC2_ADMIN_LISTEN). Commands:

    status | rooms | bans | reports [--all] | mutes
    posts ROOM [--q TEXT] [--limit N]
    remove ROOM REF [--device ID]
    ban [--device ID] [--ip IP] [--duration SECONDS | --until UNIX] [--reason TEXT] [--remove-posts]
    unban [--device ID] [--ip IP]
    mute / unmute  (self-hosted relays with SC2_MUTES=true; same options as ban/unban)
    resolve REPORT_ID
    slowmode ROOM on|off
    tune KEY=VALUE [KEY=VALUE ...]
    admission open|code|allowlist [--code CODE] [--allow ID ...]
    purge DEVICE
    retention

SPDX-License-Identifier: MIT
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


def call(url, token, method, path, body=None, query=None):
    full = url.rstrip("/") + path
    if query:
        full += "?" + urllib.parse.urlencode({k: v for k, v in query.items() if v is not None})
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(full, data=data, method=method)
    req.add_header("Authorization", "Bearer " + token)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode() or "{}")
        except ValueError:
            return e.code, {"error": e.reason}


def _ban_args(p):
    p.add_argument("--device")
    p.add_argument("--ip")
    p.add_argument("--duration", type=int, help="seconds from now")
    p.add_argument("--until", type=int, help="unix time; omit both for indefinite")
    p.add_argument("--reason", default="")


def build_parser():
    ap = argparse.ArgumentParser(prog="sc2_relay.admin", description="SC2 relay operator tool")
    host = os.environ.get("SC2_ADMIN_LISTEN", "127.0.0.1:7780")
    ap.add_argument("--url", default="http://" + host)
    ap.add_argument("--token", default=os.environ.get("SC2_ADMIN_TOKEN", ""))
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("status", "rooms", "bans", "mutes", "retention"):
        sub.add_parser(name)
    p = sub.add_parser("reports")
    p.add_argument("--all", action="store_true")
    p = sub.add_parser("posts")
    p.add_argument("room")
    p.add_argument("--q", default="")
    p.add_argument("--limit", type=int, default=50)
    p = sub.add_parser("remove")
    p.add_argument("room")
    p.add_argument("ref")
    p.add_argument("--device", help="the post's author; required when several authors used this message ID")
    p = sub.add_parser("ban")
    _ban_args(p)
    p.add_argument("--remove-posts", action="store_true")
    p = sub.add_parser("unban")
    p.add_argument("--device")
    p.add_argument("--ip")
    p = sub.add_parser("mute")
    _ban_args(p)
    p = sub.add_parser("unmute")
    p.add_argument("--device")
    p.add_argument("--ip")
    p = sub.add_parser("resolve")
    p.add_argument("id", type=int)
    p = sub.add_parser("slowmode")
    p.add_argument("room")
    p.add_argument("state", choices=("on", "off"))
    p = sub.add_parser("tune")
    p.add_argument("pairs", nargs="+")
    p = sub.add_parser("admission")
    p.add_argument("mode", choices=("open", "code", "allowlist"))
    p.add_argument("--code")
    p.add_argument("--allow", nargs="*")
    p = sub.add_parser("purge")
    p.add_argument("device")
    return ap


def run(argv=None, out=sys.stdout):
    a = build_parser().parse_args(argv)
    if not a.token:
        print("no admin token: pass --token or set SC2_ADMIN_TOKEN", file=sys.stderr)
        return 2
    c = a.cmd
    get = {"status": "/admin/status", "rooms": "/admin/rooms", "bans": "/admin/bans", "mutes": "/admin/mutes"}
    if c in get:
        st, body = call(a.url, a.token, "GET", get[c])
    elif c == "reports":
        st, body = call(a.url, a.token, "GET", "/admin/reports", query={"all": "1" if a.all else None})
    elif c == "posts":
        st, body = call(a.url, a.token, "GET", "/admin/posts", query={"room": a.room, "q": a.q, "limit": a.limit})
    elif c == "remove":
        st, body = call(a.url, a.token, "POST", "/admin/remove", {"room": a.room, "ref": a.ref, "device": a.device})
    elif c in ("ban", "mute"):
        b = {"device": a.device, "ip": a.ip, "reason": a.reason}
        if a.duration is not None:
            b["duration"] = a.duration
        elif a.until is not None:
            b["until"] = a.until
        if c == "ban":
            b["remove_posts"] = a.remove_posts
        st, body = call(a.url, a.token, "POST", "/admin/" + c, b)
    elif c in ("unban", "unmute"):
        st, body = call(a.url, a.token, "POST", "/admin/" + c, {"device": a.device, "ip": a.ip})
    elif c == "resolve":
        st, body = call(a.url, a.token, "POST", "/admin/reports/resolve", {"id": a.id})
    elif c == "slowmode":
        st, body = call(a.url, a.token, "POST", "/admin/slowmode", {"room": a.room, "on": a.state == "on"})
    elif c == "tune":
        b = {}
        for pair in a.pairs:
            k, sep, v = pair.partition("=")
            if not sep:
                print("tune expects KEY=VALUE", file=sys.stderr)
                return 2
            try:
                b[k] = int(v)
            except ValueError:
                print("tune values are integers", file=sys.stderr)
                return 2
        st, body = call(a.url, a.token, "POST", "/admin/tune", b)
    elif c == "admission":
        st, body = call(a.url, a.token, "POST", "/admin/admission",
                        {"mode": a.mode, "code": a.code, "allowlist": a.allow})
    elif c == "purge":
        st, body = call(a.url, a.token, "POST", "/admin/purge", {"device": a.device})
    elif c == "retention":
        st, body = call(a.url, a.token, "POST", "/admin/retention", {})
    else:  # pragma: no cover - argparse rejects unknown commands
        return 2
    json.dump(body, out, indent=2, sort_keys=True, ensure_ascii=False)
    out.write("\n")
    return 0 if st == 200 else 1


if __name__ == "__main__":
    sys.exit(run())
