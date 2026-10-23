"""HTTP surface: well-known, healthz, metrics and the read-only web view.

SPDX-License-Identifier: MIT
"""

import json

import sc2ref
from sc2proto import frames
from helpers import Device, admin, free_port, http_get, relay_server, run

ROOM = "pub:general"


def test_web_view_off_by_default_but_well_known_on():
    async def body():
        async with relay_server(http_port=free_port()) as srv:
            port = srv.ports["http"]
            st, h, b = await http_get(port, "/public/")
            assert st == 404
            st, h, b = await http_get(port, "/api/public/general")
            assert st == 404
            st, h, b = await http_get(port, "/.well-known/solaros-relay")
            wk = json.loads(b)
            assert st == 200 and wk["v"] == 2 and wk["suites"] == [1] and wk["legacy_v1"] is True
            assert wk["web_view"] is False and wk["public_rooms"] == [ROOM] and wk["admission"] == "open"
            assert wk["public_room_create"] == "operator" and wk["relay_key"] == sc2ref.b64(srv.relay.key.public)
            assert wk["limits"]["queue"] == 500 and wk["tls_pin"] is None
            st, h, b = await http_get(port, "/healthz")
            assert st == 200 and b == b"ok\n"
            st, h, b = await http_get(port, "/nope")
            assert st == 404
            st, h, b = await http_get(port, "/public/", method="POST", body={})
            assert st == 405
    run(body())


def test_web_view_pages_and_api():
    async def body():
        async with relay_server(http_port=free_port(), web_view=True, post_burst=1000, ip_post_burst=1000,
                                web_page_size=3) as srv:
            port = srv.ports["http"]
            d = Device()
            await d.connect(srv.ports["plain"])
            await d.join(ROOM)
            posts = []
            for i in range(5):
                p = d.post(ROOM, "<script>alert(%d)</script> & more" % i, name="<b>Ana</b>")
                await d.conn.request({"type": "room.post", "rid": "p%d" % i, "room": ROOM, "post": p})
                posts.append(p)
            await d.conn.request({"type": "room.post", "rid": "del", "room": ROOM,
                                  "post": d.post(ROOM, "", t="del", ref=posts[0]["id"])})
            await admin(srv, "POST", "/admin/remove", {"room": "general", "ref": posts[1]["id"]})

            st, h, b = await http_get(port, "/public/")
            html = b.decode()
            assert st == 200 and h["x-robots-tag"] == "noindex" and "set-cookie" not in h
            assert 'href="/public/general"' in html and "PUBLIC \u00b7 not encrypted" in html
            st, h, b = await http_get(port, "/public/general")
            html = b.decode()
            assert st == 200 and h["content-type"].startswith("text/html") and h["x-robots-tag"] == "noindex"
            assert "<script>" not in html and "&lt;script&gt;alert(4)&lt;/script&gt; &amp; more" in html
            assert "&lt;b&gt;Ana&lt;/b&gt;" in html
            assert "alert(0)" not in html and "alert(1)" not in html  # deleted by author, removed by relay
            assert "alert(4)" in html and "alert(3)" in html and "alert(2)" in html
            assert "?before=3" in html  # page size 3 -> link to older posts
            st, h, b = await http_get(port, "/public/general?before=3")
            assert "alert(2)" not in b.decode() and "No posts yet" in b.decode()
            st, h, b = await http_get(port, "/public/general?before=abc")
            assert st == 400

            st, h, b = await http_get(port, "/api/public/general?after=0&limit=500")
            api = json.loads(b)
            assert st == 200 and h["x-robots-tag"] == "noindex" and api["room"] == ROOM
            seqs = [x["seq"] for x in api["posts"]]
            assert "2" not in seqs  # removed by relay
            assert len(api["mods"]) == 1 and api["next"] == api["mods"][0]["seq"] == "7"
            m = api["mods"][0]
            assert m["action"] == "remove" and m["ref"] == posts[1]["id"] and m["by"] == "relay"
            assert sc2ref.ed_verify(srv.relay.key.public, frames.mod_signed_bytes_from_frame(m),
                                    sc2ref.unb64(m["sig"]))
            assert "script-src" not in h["content-security-policy"]
            assert h["content-security-policy"].startswith("default-src 'none'")
            assert h["x-content-type-options"] == "nosniff"
            for x in api["posts"]:  # anyone can verify every post independently
                p = x["post"]
                assert sc2ref.ed_verify(sc2ref.unb64(p["ik"]), sc2ref.post_signed_bytes("relay.test", ROOM, p),
                                        sc2ref.unb64(p["sig"]))
            st, h, b = await http_get(port, "/api/public/general?after=4&limit=1")
            api = json.loads(b)
            assert [x["seq"] for x in api["posts"]] == ["5"] and api["mods"] == [] and api["next"] == "5"
            # only public rooms are exposed
            st, h, b = await http_get(port, "/public/" + "ab" * 16)
            assert st == 404
            st, h, b = await http_get(port, "/api/public/nope")
            assert st == 404
            st, h, b = await http_get(port, "/.well-known/solaros-relay")
            assert json.loads(b)["web_view"] is True
    run(body())


def test_web_rate_limit_and_noindex_switch():
    async def body():
        async with relay_server(http_port=free_port(), web_view=True, web_rate_per_min=4, web_noindex=False) as srv:
            port = srv.ports["http"]
            codes, first = [], None
            for _ in range(12):
                st, h, b = await http_get(port, "/public/")
                codes.append(st)
                first = first or h
            assert 429 in codes and codes[0] == 200
            assert "x-robots-tag" not in first and b"noindex" not in b
    run(body())


def test_metrics_have_no_device_ids():
    async def body():
        async with relay_server(http_port=free_port()) as srv:
            d = Device()
            await d.connect(srv.ports["plain"])
            await d.join(ROOM)
            await d.send_post(ROOM, "hello")
            st, h, b = await http_get(srv.ports["http"], "/metrics")
            text = b.decode()
            assert st == 200 and "sc2_connections 1" in text and "sc2_public_posts_total 1" in text
            assert "sc2_inbox_items 0" in text and d.id not in text
            for line in text.splitlines():
                if not line.startswith("#"):
                    name, value = line.split(" ")
                    float(value)
    run(body())
