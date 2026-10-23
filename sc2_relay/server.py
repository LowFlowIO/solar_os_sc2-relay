"""asyncio listeners for the SC2 relay.

- chats:// NDJSON over TLS (default port 7778) when SC2_TLS_CERT/KEY are set
- chat:// plain NDJSON (port 7777), off unless SC2_PLAIN=true
- HTTP (SC2_HTTP_PORT, default 8080): well-known, healthz, metrics, web view
  and wss://host/sc2 (WebSocket, one JSON frame per text message)
- admin API on loopback (SC2_ADMIN_LISTEN) when SC2_ADMIN_TOKEN is set

SPDX-License-Identifier: MIT
"""

import asyncio
import logging
import os
import struct

from sc2proto import ProtocolError, dumpb

from . import tlsutil
from .core import Relay
from .crypto import SigningKey
from .storage import Storage
from .web import AdminHttp, HttpError, PublicHttp, Response, serve_http, ws_accept_key

log = logging.getLogger("sc2_relay.server")


class RelayServer:
    def __init__(self, config, clock=None, store=None, key=None):
        self.config = config
        if store is None:
            store = Storage(config.database)
        if key is None:
            key, created = SigningKey.load_or_create(config.key_path)
            if created:
                log.info("generated a new relay key at %s", config.key_path)
        kw = {} if clock is None else {"clock": clock}
        self.relay = Relay(config, store, key, **kw)
        self.servers = []
        self.ports = {}
        self._tasks = []
        self._conns = set()
        self.ssl = None
        if config.tls_enabled:
            self.ssl = tlsutil.server_context(config.tls_cert, config.tls_key)
            try:
                self.relay.tls_pin = tlsutil.spki_pin(config.tls_cert)
            except (ValueError, OSError) as e:
                log.warning("could not compute the TLS pin: %s", e)
        self.http = PublicHttp(self.relay, self._websocket)
        self.admin = AdminHttp(self.relay)

    async def start(self):
        c = self.config
        if not c.tls_enabled and not c.plain and not (c.http_port and c.websocket):
            raise RuntimeError("no client listener: set SC2_TLS_CERT/SC2_TLS_KEY, SC2_PLAIN=true or SC2_HTTP_PORT")
        if c.acme_domain and not c.tls_enabled:
            log.warning("SC2_ACME_DOMAIN is not implemented in the reference relay; terminate TLS with "
                        "certbot/Caddy and set SC2_TLS_CERT/SC2_TLS_KEY (see README)")
        if c.tls_enabled:
            await self._listen("tls", lambda r, w: self._ndjson(r, w, "tls"), c.bind, c.tls_port, self.ssl)
        if c.plain:
            await self._listen("plain", lambda r, w: self._ndjson(r, w, "tcp"), c.bind, c.plain_port, None)
        if c.http_port:
            await self._listen("http", lambda r, w: self._tracked(serve_http(self.http, r, w)), c.bind, c.http_port,
                               self.ssl if c.http_tls else None)
        if c.admin_token:
            host, port = c.admin_address()
            await self._listen("admin", lambda r, w: self._tracked(serve_http(self.admin, r, w)), host, port, None)
        else:
            log.info("admin interface disabled (set SC2_ADMIN_TOKEN to enable)")
        self._tasks.append(asyncio.ensure_future(self._retention_loop()))
        log.info("relay %s up (profile %s, legacy_v1=%s, web_view=%s): %s", self.relay.relay_id, c.profile,
                 c.legacy_v1, c.web_view, ", ".join("%s:%d" % kv for kv in sorted(self.ports.items())))

    async def _listen(self, name, cb, host, port, ssl_ctx):
        srv = await asyncio.start_server(cb, host, port, ssl=ssl_ctx, limit=1 << 16)
        self.servers.append(srv)
        self.ports[name] = srv.sockets[0].getsockname()[1]

    async def _tracked(self, coro):
        t = asyncio.current_task()
        self._conns.add(t)
        try:
            await coro
        finally:
            self._conns.discard(t)

    async def close(self):
        for t in self._tasks:
            t.cancel()
        for s in self.servers:
            s.close()
        for s in list(self.relay.sessions):
            s.close()
        for t in list(self._conns):
            t.cancel()
        for s in self.servers:
            try:
                await asyncio.wait_for(s.wait_closed(), 2)
            except asyncio.TimeoutError:
                pass
        await asyncio.sleep(0)
        self.relay.store.close()

    async def _retention_loop(self):
        while True:
            await asyncio.sleep(self.config.retention_interval)
            try:
                out = self.relay.retention()
                if any(out.values()):
                    log.info("retention: %s", {k: v for k, v in out.items() if v})
            except Exception:
                log.exception("retention failed")

    # ---------------- NDJSON (chat:// and chats://) ----------------

    async def _ndjson(self, reader, writer, transport):
        t = asyncio.current_task()
        self._conns.add(t)
        try:
            await self._ndjson_inner(reader, writer, transport)
        finally:
            self._conns.discard(t)

    async def _ndjson_inner(self, reader, writer, transport):
        relay = self.relay
        peer = writer.get_extra_info("peername")
        ip = peer[0] if isinstance(peer, tuple) else ""
        if not relay.connection_allowed(ip):
            writer.write(dumpb({"type": "error", "code": 503, "err": "server_full", "text": "server full"}))
            try:
                await writer.drain()
            finally:
                writer.close()
            return
        state = {"closing": False}

        def write_line(line):
            if state["closing"]:
                return
            writer.write(line)
            if writer.transport.get_write_buffer_size() > self.config.send_buffer_max:
                log.info("closing a slow client (send buffer full)")
                close()

        def close():
            if not state["closing"]:
                state["closing"] = True
                try:
                    writer.close()
                except Exception:
                    pass

        session = relay.new_session(ip, transport, write_line, close)
        try:
            while not state["closing"]:
                timeout = self.config.idle_timeout if session.state in ("authed", "v1") else self.config.auth_timeout
                try:
                    data = await asyncio.wait_for(reader.read(8192), timeout)
                except asyncio.TimeoutError:
                    break
                if not data:
                    break
                session.feed(data)
                if not state["closing"]:
                    await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            session.on_closed()
            close()

    # ---------------- WebSocket (wss://host/sc2) ----------------

    async def _websocket(self, req, reader, writer):
        relay = self.relay
        key = req.headers.get("sec-websocket-key", "")
        if req.method != "GET" or req.headers.get("sec-websocket-version") != "13" or not key or \
                "upgrade" not in req.headers.get("connection", "").lower():
            raise HttpError(400, "bad WebSocket handshake")
        if not relay.connection_allowed(req.ip):
            writer.write(Response(503, "server full\n", "text/plain").encode())
            return
        writer.write(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                      "Sec-WebSocket-Accept: %s\r\n\r\n" % ws_accept_key(key)).encode())
        state = {"closing": False}

        def send_frame(opcode, payload):
            n = len(payload)
            if n < 126:
                head = struct.pack(">BB", 0x80 | opcode, n)
            elif n < 65536:
                head = struct.pack(">BBH", 0x80 | opcode, 126, n)
            else:
                head = struct.pack(">BBQ", 0x80 | opcode, 127, n)
            writer.write(head + payload)

        def write_line(line):
            if state["closing"]:
                return
            send_frame(0x1, line.rstrip(b"\n"))
            if writer.transport.get_write_buffer_size() > self.config.send_buffer_max:
                close()

        def close():
            if not state["closing"]:
                state["closing"] = True
                try:
                    send_frame(0x8, struct.pack(">H", 1000))
                    writer.close()
                except Exception:
                    pass

        session = relay.new_session(req.ip, "ws", write_line, close)
        frag = b""
        frag_op = None
        try:
            while not state["closing"]:
                timeout = self.config.idle_timeout if session.state == "authed" else self.config.auth_timeout
                try:
                    hdr = await asyncio.wait_for(reader.readexactly(2), timeout)
                except asyncio.TimeoutError:
                    break
                fin, op = hdr[0] & 0x80, hdr[0] & 0x0F
                if hdr[0] & 0x70:
                    break  # no extensions negotiated
                masked, n = hdr[1] & 0x80, hdr[1] & 0x7F
                if not masked:
                    break  # clients must mask (RFC 6455 5.1)
                if n == 126:
                    n = struct.unpack(">H", await reader.readexactly(2))[0]
                elif n == 127:
                    n = struct.unpack(">Q", await reader.readexactly(8))[0]
                if n > 16384 + 1024 or (op >= 8 and n > 125):
                    session.send(ProtocolError(413, "too_large", "frame too large").frame())
                    break
                mask = await reader.readexactly(4)
                data = bytearray(await reader.readexactly(n))
                for i in range(n):
                    data[i] ^= mask[i & 3]
                data = bytes(data)
                if op == 0x8:
                    break
                if op == 0x9:
                    send_frame(0xA, data)
                    continue
                if op == 0xA:
                    continue
                if op == 0x2:
                    session.send(ProtocolError(400, "bad_request", "text frames only").frame())
                    break
                if op == 0x1:
                    if frag_op is not None:
                        break
                    frag, frag_op = data, op
                elif op == 0x0:
                    if frag_op is None:
                        break
                    frag += data
                else:
                    break
                if len(frag) > 16384:
                    session.send(ProtocolError(413, "too_large", "line too long").frame())
                    break
                if fin:
                    msg, frag, frag_op = frag, b"", None
                    session.relay.metrics["ws_messages_total"] += 1
                    session.feed_frame(msg)
                    if not state["closing"]:
                        await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            session.on_closed()
            close()


async def run(config):
    srv = RelayServer(config)
    await srv.start()
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    import signal
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, RuntimeError):
            pass
    await stop.wait()
    log.info("shutting down")
    await srv.close()


def ensure_data_dir(config):
    os.makedirs(config.data_dir, exist_ok=True)
