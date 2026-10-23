"""chats:// over TLS (port 7778 in production), the SPKI pin published in
/.well-known, HTTPS for the HTTP listener, and the wss:///sc2 WebSocket
endpoint.

SPDX-License-Identifier: MIT
"""

import asyncio
import base64
import hashlib
import json
import os
import shutil
import ssl
import subprocess

import pytest

import sc2ref
from helpers import Device, free_port, http_get, insecure_client_ctx, relay_server, run, ws_frame
from sc2_relay import tlsutil
from sc2proto import b64d, b64e

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl CLI not installed")


@pytest.fixture(scope="module")
def cert(tmp_path_factory):
    d = tmp_path_factory.mktemp("tls")
    crt, key = str(d / "cert.pem"), str(d / "key.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                    "-nodes", "-keyout", key, "-out", crt, "-days", "2", "-subj", "/CN=relay.test"],
                   check=True, capture_output=True)
    return crt, key


def openssl_pin(crt):
    pub = subprocess.run(["openssl", "x509", "-in", crt, "-pubkey", "-noout"], check=True, capture_output=True).stdout
    der = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "DER"], input=pub, check=True,
                         capture_output=True).stdout
    return "sha256/" + base64.b64encode(hashlib.sha256(der).digest()).decode()


def test_tls_listener_and_pin(cert):
    crt, key = cert

    async def body():
        async with relay_server(tls_cert=crt, tls_key=key, tls_port=0, plain=False,
                                http_port=free_port(), http_tls=True) as srv:
            assert "plain" not in srv.ports
            d = Device()
            a = await d.connect(srv.ports["tls"], ssl_ctx=insecure_client_ctx())
            assert a["type"] == "authed"
            sslobj = d.conn.writer.get_extra_info("ssl_object")
            assert sslobj.version() in ("TLSv1.2", "TLSv1.3")
            st, h, b = await http_get(srv.ports["http"], "/.well-known/solaros-relay", ssl_ctx=insecure_client_ctx())
            wk = json.loads(b)
            assert wk["tls_pin"] == tlsutil.spki_pin(crt) == openssl_pin(crt)
            assert srv.ssl.minimum_version == ssl.TLSVersion.TLSv1_2
    run(body())


def test_refuses_to_start_without_client_listener(tmp_path):
    async def body():
        with pytest.raises(RuntimeError):
            async with relay_server(plain=False, http_port=0):
                pass
    run(body())


class WS:
    def __init__(self, r, w):
        self.r, self.w = r, w

    @classmethod
    async def open(cls, port, path="/sc2"):
        r, w = await asyncio.open_connection("127.0.0.1", port)
        key = base64.b64encode(os.urandom(16)).decode()
        w.write(("GET %s HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                 "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n" % (path, key)).encode())
        await w.drain()
        head = await r.readuntil(b"\r\n\r\n")
        assert head.startswith(b"HTTP/1.1 101"), head
        accept = base64.b64encode(hashlib.sha1(key.encode() + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
        assert b"Sec-WebSocket-Accept: " + accept in head
        return cls(r, w)

    async def send(self, obj, opcode=1):
        data = obj if isinstance(obj, bytes) else sc2ref.dumps(obj).encode()
        self.w.write(ws_frame(data, opcode))
        await self.w.drain()

    async def recv(self):
        h = await asyncio.wait_for(self.r.readexactly(2), 5)
        assert h[1] & 0x80 == 0  # server frames are unmasked
        n = h[1] & 0x7F
        if n == 126:
            n = int.from_bytes(await self.r.readexactly(2), "big")
        elif n == 127:
            n = int.from_bytes(await self.r.readexactly(8), "big")
        data = await self.r.readexactly(n)
        op = h[0] & 0x0F
        if op == 1:
            return json.loads(data)
        return {"opcode": op, "data": data}


def test_websocket_v2_session_and_fanout():
    async def body():
        async with relay_server(http_port=free_port()) as srv:
            ws = await WS.open(srv.ports["http"])
            d = Device()
            await ws.send({"type": "hello", "v": 2, "proto": "sc2", "suites": [1]})
            w = await ws.recv()
            assert w["type"] == "welcome"
            sig = d.sign(sc2ref.auth_bytes("relay.test", b64d(w["challenge"]), d.ident.ik_pub))
            await ws.send({"type": "auth", "rid": "a", "ik": b64e(d.ident.ik_pub), "sig": b64e(sig)})
            assert (await ws.recv())["type"] == "authed"
            await ws.send({"type": "sync", "rid": "s"})
            assert (await ws.recv())["type"] == "sync.done"
            await ws.send({"type": "room.join", "rid": "j", "room": "pub:general"})
            assert (await ws.recv())["type"] == "room.state"
            # a TCP client posts, the WebSocket client receives it
            tcp = Device()
            await tcp.connect(srv.ports["plain"])
            await tcp.join("pub:general")
            await tcp.send_post("pub:general", "over websocket")
            pub = await ws.recv()
            assert pub["type"] == "room.pub" and pub["post"]["body"] == "over websocket"
            # fragmented message + ping
            data = sc2ref.dumps({"type": "ping", "rid": "frag"}).encode()
            ws.w.write(ws_frame(data[:5], 1)[:1].replace(b"\x81", b"\x01") + ws_frame(data[:5], 1)[1:])
            ws.w.write(ws_frame(data[5:], 0))
            await ws.w.drain()
            assert await ws.recv() == {"type": "pong", "rid": "frag"}
            await ws.send(b"hi", opcode=9)
            assert await ws.recv() == {"opcode": 10, "data": b"hi"}
            # binary frames are refused
            await ws.send(b"\x00\x01", opcode=2)
            e = await ws.recv()
            assert e["code"] == 400
    run(body())


def test_websocket_refuses_v1_and_unmasked():
    async def body():
        async with relay_server(http_port=free_port()) as srv:
            ws = await WS.open(srv.ports["http"])
            await ws.send({"type": "hello", "user": "x"})
            e = await ws.recv()
            assert e["code"] == 426
            ws = await WS.open(srv.ports["http"])
            ws.w.write(ws_frame(b'{"type":"ping"}', 1, mask=False))
            await ws.w.drain()
            assert await asyncio.wait_for(ws.r.read(), 5) in (b"", b"\x88\x02\x03\xe8")
            st, h, b = await http_get(srv.ports["http"], "/sc2")
            assert st == 400
        async with relay_server(http_port=free_port(), websocket=False) as srv:
            st, h, b = await http_get(srv.ports["http"], "/sc2")
            assert st == 404
    run(body())
