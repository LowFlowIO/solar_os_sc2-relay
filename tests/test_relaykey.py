"""Relay key outside moderation: the signed /.well-known descriptor, the
welcome proof over the hello nonce and signed key rotation (--rotate-key).

SPDX-License-Identifier: MIT
"""

import base64
import json
import os

import pytest

from sc2_relay import crypto
from sc2_relay.config import Config, ConfigError
from sc2_relay.server import load_rotation, rotate_key
from sc2proto import b64d, b64e, relaykey
from helpers import Conn, free_port, http_get, make_config, relay_server, run

FB_KEY = b64e(crypto.SigningKey(bytes(range(32))).public)


def descriptor_of(wk):
    text = base64.b64decode(wk["descriptor"])
    return text, relaykey.parse_descriptor(text), base64.b64decode(wk["descriptor_sig"])


def test_descriptor_signed_and_first():
    async def body():
        fallbacks = ["chats://b.example:7443 " + FB_KEY, "chat://c.example:7777#x" + " " + FB_KEY]
        with pytest.raises(ConfigError):
            make_config("/tmp", fallback_relays=fallbacks)
        async with relay_server(http_port=free_port(), public_host="relay.example", public_port=443,
                                fallback_relays=fallbacks[:1]) as srv:
            st, h, b = await http_get(srv.ports["http"], "/.well-known/solaros-relay")
            assert st == 200
            assert b.startswith(b'{"descriptor":"')  # devices read only the start of the body
            wk = json.loads(b)
            text, d, sig = descriptor_of(wk)
            key = srv.relay.key.public
            assert relaykey.verify_descriptor(crypto.verify, key, text, sig)
            assert not relaykey.verify_descriptor(crypto.verify, key, text + b"x", sig)
            assert d["id"] == "relay.test" and d["key"] == b64e(key) and d["host"] == "relay.example"
            assert d["port"] == "443" and d["tls"] == "0"  # plain listener only in the test relay
            assert d["fallback"] == [("chats://b.example:7443", FB_KEY)]
            assert "pin" not in d  # SC2_DESCRIPTOR_PIN is off by default
            assert wk["relay_key"] == b64e(key) and "rotation" not in wk
            assert len(text) <= relaykey.DESC_TEXT_MAX
    run(body())


def test_config_rejects_bad_fallbacks():
    for bad in (["chats://b.example:7443"], ["https://b.example:443 " + FB_KEY], ["chats://b:1 nokey"],
                ["chats://a:1 " + FB_KEY] * 4):
        with pytest.raises(ConfigError):
            make_config("/tmp", fallback_relays=bad)
    with pytest.raises(ConfigError):
        make_config("/tmp", public_host="bad host")


def test_welcome_proof_over_nonce():
    async def body():
        async with relay_server() as srv:
            c = await Conn.open(srv.ports["plain"])
            nonce = os.urandom(16)
            await c.send({"type": "hello", "v": 2, "proto": "sc2", "suites": [1], "nonce": b64e(nonce)})
            w = await c.recv()
            key = b64d(w["relay"]["key"], 32)
            msg = relaykey.welcome_bytes(w["relay"]["id"], nonce, b64d(w["challenge"], 32))
            assert crypto.verify(key, msg, b64d(w["relay_sig"], 64))
            assert not crypto.verify(key, relaykey.welcome_bytes(w["relay"]["id"], bytes(16),
                                                                 b64d(w["challenge"], 32)), b64d(w["relay_sig"], 64))
            # without a nonce: no proof (old clients see the old welcome)
            c2 = await Conn.open(srv.ports["plain"])
            await c2.send({"type": "hello", "v": 2, "proto": "sc2", "suites": [1]})
            w2 = await c2.recv()
            assert "relay_sig" not in w2 and "rotation" not in w2
            c3 = await Conn.open(srv.ports["plain"])
            await c3.send({"type": "hello", "v": 2, "proto": "sc2", "suites": [1], "nonce": "AAAA"})
            e = await c3.recv()
            assert e["type"] == "error"
    run(body())


def test_rotate_key_signed_by_old(tmp_path):
    cfg = make_config(str(tmp_path))
    old, _ = crypto.SigningKey.load_or_create(cfg.key_path)
    old_b64, new_b64 = rotate_key(cfg)
    assert old_b64 == b64e(old.public) and new_b64 != old_b64
    assert oct(os.stat(cfg.key_path).st_mode & 0o777) == "0o600"
    new, created = crypto.SigningKey.load_or_create(cfg.key_path)
    assert not created and b64e(new.public) == new_b64
    rot = load_rotation(cfg, new)
    assert rot["from"] == old_b64
    assert crypto.verify(old.public, relaykey.rotation_bytes("relay.test", old.public, new.public), b64d(rot["sig"], 64))
    # a rotation file for another key or relay id is ignored
    assert load_rotation(cfg, old) is None
    assert load_rotation(make_config(str(tmp_path), relay_id="other"), new) is None

    async def body():
        async with relay_server(tmp=str(tmp_path), http_port=free_port()) as srv:
            assert srv.relay.key.public == new.public
            c = await Conn.open(srv.ports["plain"])
            await c.send({"type": "hello", "v": 2, "proto": "sc2", "suites": [1], "nonce": b64e(bytes(16))})
            w = await c.recv()
            assert w["rotation"] == {"from": old_b64, "sig": rot["sig"]}
            st, h, b = await http_get(srv.ports["http"], "/.well-known/solaros-relay")
            assert json.loads(b)["rotation"]["from"] == old_b64
    run(body())


def test_cli_rotate_key(tmp_path, capsys):
    from sc2_relay.__main__ import main
    os.environ["SC2_DATA_DIR"] = str(tmp_path)
    try:
        assert main(["--rotate-key"]) == 1  # nothing to rotate yet (a key gets created instead)
        assert main(["--rotate-key"]) == 0
        assert "relay key rotated" in capsys.readouterr().out
    finally:
        del os.environ["SC2_DATA_DIR"]
