"""asyncio listeners for the SC2 relay.

- chats:// NDJSON over TLS (default port 7778) when SC2_TLS_CERT/KEY are set
- chat:// plain NDJSON (port 7777), off unless SC2_PLAIN=true
- HTTP (SC2_HTTP_PORT, default 8080): well-known, healthz, metrics, web view
  and wss://host/sc2 (WebSocket, one JSON frame per text message)
- admin API on loopback (SC2_ADMIN_LISTEN) when SC2_ADMIN_TOKEN is set

SPDX-License-Identifier: MIT
"""

import asyncio
import json
import logging
import os
import ssl
import struct

from sc2proto import ProtocolError, b64d, b64e, dumpb, relaykey

from . import crypto, tlsutil
from .core import Relay
from .crypto import SigningKey
from .storage import Storage
from .web import AdminHttp, HttpError, PublicHttp, Response, serve_http, ws_accept_key

log = logging.getLogger("sc2_relay.server")


def load_rotation(config, key):
    """relay_key.rotation, written by --rotate-key: the previous key's
    signature over the current one, sent in welcome so devices that pinned
    the old key accept the new one. Ignored (logged) if it does not match."""
    path = config.key_path + ".rotation"
    try:
        with open(path) as f:
            rot = json.load(f)
        old = b64d(rot["from"], 32, "from")
        sig = b64d(rot["sig"], 64, "sig")
    except FileNotFoundError:
        return None
    except (ValueError, KeyError, TypeError, ProtocolError) as e:
        log.warning("ignoring %s: %s", path, e)
        return None
    if not crypto.verify(old, relaykey.rotation_bytes(config.relay_id, old, key.public), sig):
        log.warning("ignoring %s: not a rotation to the current key for relay id %s", path, config.relay_id)
        return None
    return {"from": rot["from"], "sig": rot["sig"]}


def rotate_key(config):
    """Replace the relay key; the old key signs the new one (one step).
    Returns (old_b64, new_b64)."""
    old, created = SigningKey.load_or_create(config.key_path)
    if created:
        raise RuntimeError("no relay key existed; created one instead of rotating")
    seed = os.urandom(32)
    new = SigningKey(seed)
    sig = old.sign(relaykey.rotation_bytes(config.relay_id, old.public, new.public))
    rot = {"from": b64e(old.public), "to": b64e(new.public), "sig": b64e(sig)}
    for path, data in ((config.key_path + ".rotation", (json.dumps(rot) + "\n").encode()), (config.key_path, seed)):
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)
    return rot["from"], rot["to"]


class RelayServer:
    def __init__(self, config, clock=None, store=None, key=None):
        self.config = config
        if store is None or key is None:
            ensure_data_dir(config)
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
        self.relay.ports = self.ports
        self.relay.rotation = load_rotation(config, key)
        self._tasks = []
        self._conns = set()
        self.ssl = None
        self._tls_seen = None
        if config.tls_enabled:
            self._tls_seen = tlsutil.file_stamp(config.tls_cert, config.tls_key)
            if config.acme_domain and None in self._tls_seen:
                # first start with the certbot sidecar: the TLS listener opens once the files exist
                log.info("waiting for the Let's Encrypt certificate for %s in %s", config.acme_domain,
                         os.path.dirname(config.tls_cert))
                self._tls_seen = None
            else:
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
        if c.http_tls and self.ssl is None:
            raise RuntimeError("SC2_HTTP_TLS needs the certificate at startup (%s is missing)" % c.tls_cert)
        if c.tls_enabled and self.ssl is not None:
            await self._listen("tls", lambda r, w: self._ndjson(r, w, "tls"), c.bind, c.tls_port, self.ssl)
        if c.tls_enabled:
            self._tasks.append(asyncio.ensure_future(self._tls_watch_loop()))
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

    # ---------------- TLS hot reload ----------------

    def reload_tls(self, force=False):
        """Reload SC2_TLS_CERT/SC2_TLS_KEY if they changed (or always with force,
        e.g. on SIGHUP). Existing connections are not touched. Returns True when a
        new certificate is live. A broken or half-written pair is logged and
        skipped; the old certificate stays in use."""
        c = self.config
        if not c.tls_enabled:
            return False
        stamp = tlsutil.file_stamp(c.tls_cert, c.tls_key)
        if None in stamp or (not force and stamp == self._tls_seen):
            return False
        self._tls_seen = stamp
        try:
            ctx, pin = tlsutil.reload_context(self.ssl, c.tls_cert, c.tls_key)
        except (ssl.SSLError, OSError, ValueError) as e:
            self.relay.metrics["tls_reload_failures_total"] += 1
            log.warning("TLS reload skipped, keeping the current certificate: %s", e)
            return False
        first = self.ssl is None
        self.ssl = ctx
        old = self.relay.tls_pin
        self.relay.tls_pin = pin
        self.relay.metrics["tls_reloads_total"] += 1
        if old and pin != old:
            log.warning("TLS key changed: SPKI pin %s -> %s. Devices pinned with #pin= must re-pin; "
                        "use certbot --reuse-key to keep the key across renewals (README: key rotation)", old, pin)
        else:
            log.info("TLS certificate %s (pin %s)", "loaded" if first else "reloaded", pin)
        return True

    async def _tls_watch_loop(self):
        c = self.config
        while True:
            if self.ssl is None:
                await asyncio.sleep(min(5, c.tls_reload_interval or 5))
            elif c.tls_reload_interval:
                await asyncio.sleep(c.tls_reload_interval)
            else:
                return  # polling off; SIGHUP still reloads
            self.reload_tls()
            if self.ssl is not None and "tls" not in self.ports:
                try:
                    await self._listen("tls", lambda r, w: self._ndjson(r, w, "tls"), c.bind, c.tls_port, self.ssl)
                    log.info("chats:// listener up on %s:%d", c.bind, self.ports["tls"])
                except OSError:
                    log.exception("could not open the TLS listener")

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
    try:
        loop.add_signal_handler(signal.SIGHUP, lambda: srv.reload_tls(force=True))
    except (AttributeError, NotImplementedError, RuntimeError):
        pass
    await stop.wait()
    log.info("shutting down")
    await srv.close()


def ensure_data_dir(config):
    from . import fsperm
    fsperm.private_dir(config.data_dir)
