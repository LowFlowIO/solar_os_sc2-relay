"""TLS hot reload (Let's Encrypt renewals through the certbot sidecar or
plain certbot): the relay watches SC2_TLS_CERT/SC2_TLS_KEY, swaps the live
SSL context without dropping established connections, keeps the SPKI pin
across --reuse-key renewals, publishes the new pin after a key rotation,
ignores broken pairs and, in ACME mode, opens chats:// once the first
certificate appears.

SPDX-License-Identifier: MIT
"""

import asyncio
import json
import logging
import os
import shutil
import ssl
import subprocess

import pytest

from helpers import Device, free_port, http_get, insecure_client_ctx, relay_server, run
from sc2_relay import tlsutil

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl CLI not installed")


def _key(path):
    subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", path], check=True,
                   capture_output=True)


def _cert(key, path, cn, serial):
    """Self-signed certificate for key, written the way certbot's deploy hook
    does it (temp file, then rename)."""
    tmp = path + ".new"
    subprocess.run(["openssl", "req", "-x509", "-new", "-key", key, "-out", tmp, "-days", "2", "-subj", "/CN=" + cn,
                    "-set_serial", str(serial)], check=True, capture_output=True)
    os.replace(tmp, path)


def _install(src_key, dst_key):
    shutil.copyfile(src_key, dst_key + ".new")
    os.replace(dst_key + ".new", dst_key)


def _der(path):
    with open(path) as f:
        return ssl.PEM_cert_to_DER_cert(f.read())


def _peer(dev):
    return dev.conn.writer.get_extra_info("ssl_object").getpeercert(binary_form=True)


async def _wait(cond, timeout=8.0):
    loop = asyncio.get_running_loop()
    end = loop.time() + timeout
    while not cond():
        if loop.time() > end:
            raise AssertionError("timed out")
        await asyncio.sleep(0.05)


async def _ping(dev, rid):
    await dev.conn.send({"type": "ping", "rid": rid})
    return await dev.conn.expect("pong", rid=rid)


def test_renewal_with_reused_key_keeps_connections_and_pin(tmp_path):
    k1 = str(tmp_path / "k1.pem")
    _key(k1)
    crt, key = str(tmp_path / "fullchain.pem"), str(tmp_path / "privkey.pem")
    _install(k1, key)
    _cert(key, crt, "relay.test", 1)

    async def body():
        async with relay_server(tls_cert=crt, tls_key=key, tls_port=0, plain=False, tls_reload_interval=1,
                                http_port=free_port()) as srv:
            port = srv.ports["tls"]
            pin = srv.relay.tls_pin
            old = Device()
            assert (await old.connect(port, ssl_ctx=insecure_client_ctx()))["type"] == "authed"
            der_a = _peer(old)
            assert der_a == _der(crt)
            # certbot renew --reuse-key: new certificate, same key
            _cert(key, crt, "relay.test", 2)
            der_b = _der(crt)
            assert der_b != der_a
            await _wait(lambda: srv.relay.metrics["tls_reloads_total"] == 1)  # picked up by the watcher
            new = Device()
            assert (await new.connect(port, ssl_ctx=insecure_client_ctx()))["type"] == "authed"
            assert _peer(new) == der_b
            # the established connection was not dropped and still talks
            assert (await _ping(old, "p1"))["type"] == "pong"
            assert _peer(old) == der_a
            # same key, same SPKI pin: a device pinned with #pin= keeps working
            assert srv.relay.tls_pin == pin == tlsutil.spki_pin(crt)
            st, h, b = await http_get(srv.ports["http"], "/.well-known/solaros-relay")
            assert json.loads(b)["tls_pin"] == pin
            # nothing changed: no further reload
            assert srv.reload_tls() is False
            assert srv.relay.metrics["tls_reloads_total"] == 1
    run(body())


def test_key_rotation_changes_the_published_pin_and_broken_pairs_are_ignored(tmp_path, caplog):
    k1, k2 = str(tmp_path / "k1.pem"), str(tmp_path / "k2.pem")
    _key(k1)
    _key(k2)
    crt, key = str(tmp_path / "fullchain.pem"), str(tmp_path / "privkey.pem")
    _install(k1, key)
    _cert(key, crt, "relay.test", 1)

    async def body():
        async with relay_server(tls_cert=crt, tls_key=key, tls_port=0, plain=False, tls_reload_interval=0) as srv:
            port = srv.ports["tls"]
            pin1 = srv.relay.tls_pin
            der1 = _der(crt)
            # a certificate that does not match the key (half-way through a rotation): skipped
            _cert(k2, crt, "relay.test", 3)
            assert srv.reload_tls(force=True) is False
            assert srv.relay.metrics["tls_reload_failures_total"] == 1
            d = Device()
            await d.connect(port, ssl_ctx=insecure_client_ctx())
            assert _peer(d) == der1 and srv.relay.tls_pin == pin1  # still the old pair
            # the key lands too: the rotation completes (SIGHUP does reload_tls(force=True))
            _install(k2, key)
            with caplog.at_level(logging.WARNING, logger="sc2_relay.server"):
                assert srv.reload_tls(force=True) is True
            assert any("TLS key changed" in r.getMessage() for r in caplog.records)
            pin2 = srv.relay.tls_pin
            assert pin2 != pin1 and pin2 == tlsutil.spki_pin(crt)
            e = Device()
            await e.connect(port, ssl_ctx=insecure_client_ctx())
            assert _peer(e) == _der(crt)
            assert (await _ping(d, "still"))["type"] == "pong"  # the old connection survives a key change too
            # an unreadable key file is skipped as well
            with open(key, "w") as f:
                f.write("-----BEGIN PRIVATE KEY-----\ngarbage\n-----END PRIVATE KEY-----\n")
            assert srv.reload_tls(force=True) is False
            assert srv.relay.tls_pin == pin2
            f2 = Device()
            await f2.connect(port, ssl_ctx=insecure_client_ctx())
            assert _peer(f2) == _der(crt)
    run(body())


def test_acme_mode_waits_for_the_first_certificate(tmp_path):
    certs = tmp_path / "certs"
    certs.mkdir()

    async def body():
        async with relay_server(acme_domain="relay.example.org", acme_cert_dir=str(certs), tls_port=0, plain=False,
                                tls_reload_interval=1, http_port=free_port()) as srv:
            assert srv.config.tls_cert == str(certs / "fullchain.pem")
            assert "tls" not in srv.ports and srv.relay.tls_pin is None
            st, h, b = await http_get(srv.ports["http"], "/healthz")
            assert st == 200  # HTTP is up while certbot gets the first certificate
            k = str(tmp_path / "k.pem")
            _key(k)
            _install(k, str(certs / "privkey.pem"))
            _cert(str(certs / "privkey.pem"), str(certs / "fullchain.pem"), "relay.example.org", 1)
            await _wait(lambda: "tls" in srv.ports)
            d = Device()
            assert (await d.connect(srv.ports["tls"], ssl_ctx=insecure_client_ctx()))["type"] == "authed"
            assert srv.relay.tls_pin == tlsutil.spki_pin(str(certs / "fullchain.pem"))
    run(body())


def test_acme_domain_is_checked():
    from sc2_relay.config import Config, ConfigError
    with pytest.raises(ConfigError):
        Config(acme_domain="not a domain")
    c = Config(acme_domain="relay.example.org", acme_cert_dir="/le")
    assert (c.tls_cert, c.tls_key) == ("/le/fullchain.pem", "/le/privkey.pem") and c.tls_enabled
    c = Config(acme_domain="relay.example.org", tls_cert="/x/c.pem", tls_key="/x/k.pem")
    assert c.tls_cert == "/x/c.pem"  # explicit paths win (plain certbot live/ links)


DEPLOY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "deploy", "certbot")


@pytest.mark.skipif(shutil.which("sh") is None, reason="no POSIX sh")
def test_certbot_deploy_hook_feeds_the_relay(tmp_path):
    """The sidecar's deploy hook (run by certbot after each renewal) installs a
    pair the relay picks up; files land 0600 and never half-written."""
    live, certs = tmp_path / "live", tmp_path / "certs"
    live.mkdir()
    certs.mkdir()
    k = str(live / "privkey.pem")
    _key(k)
    _cert(k, str(live / "fullchain.pem"), "relay.example.org", 1)
    env = dict(os.environ, RENEWED_LINEAGE=str(live), SC2_CERT_DIR=str(certs), SC2_RELAY_UID=str(os.getuid()),
               SC2_RELAY_GID=str(os.getgid()))
    hook = os.path.join(DEPLOY, "deploy-hook.sh")
    subprocess.run(["sh", hook], env=env, check=True, capture_output=True)
    for f in ("fullchain.pem", "privkey.pem"):
        assert os.stat(certs / f).st_mode & 0o777 == 0o600
    assert sorted(os.listdir(certs)) == ["fullchain.pem", "privkey.pem"]

    async def body():
        async with relay_server(acme_domain="relay.example.org", acme_cert_dir=str(certs), tls_port=0, plain=False,
                                tls_reload_interval=1) as srv:
            pin = srv.relay.tls_pin
            d = Device()
            await d.connect(srv.ports["tls"], ssl_ctx=insecure_client_ctx())
            _cert(k, str(live / "fullchain.pem"), "relay.example.org", 2)  # certbot renew --reuse-key
            subprocess.run(["sh", hook], env=env, check=True, capture_output=True)
            await _wait(lambda: srv.relay.metrics["tls_reloads_total"] == 1)
            e = Device()
            await e.connect(srv.ports["tls"], ssl_ctx=insecure_client_ctx())
            assert _peer(e) == _der(str(live / "fullchain.pem")) != _peer(d)
            assert srv.relay.tls_pin == pin
            assert (await _ping(d, "x"))["type"] == "pong"
    run(body())


def test_certbot_sidecar_keeps_the_key():
    with open(os.path.join(DEPLOY, "run.sh")) as f:
        s = f.read()
    assert "--reuse-key" in s and "--key-type ecdsa" in s and "certbot renew" in s
    import sc2_relay.config as config
    for name in ("official.env", "selfhost.env"):
        env = {}
        with open(os.path.join(DEPLOY, "..", "..", "config", name)) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    k, _, v = line.partition("=")
                    env[k] = v
        c = config.Config.from_env(env)
        assert c.tls_enabled
    assert c.tls_cert == "/certs/cert.pem"  # selfhost keeps its own certificate
