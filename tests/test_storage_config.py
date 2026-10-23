"""Schema migrations, persistence across restarts, configuration profiles.

SPDX-License-Identifier: MIT
"""

import sqlite3

import pytest

from helpers import Device, relay_server, run
from sc2_relay.__main__ import load_env_file, main
from sc2_relay.config import Config, ConfigError
from sc2_relay.storage import MIGRATIONS, SCHEMA_VERSION, Storage


def test_migrations_from_v1_schema_keep_data(tmp_path):
    path = str(tmp_path / "old.sqlite3")
    db = sqlite3.connect(path)
    for stmt in [s for s in MIGRATIONS[0].split(";") if s.strip()]:
        db.execute(stmt)
    db.execute("PRAGMA user_version=1")
    db.execute("INSERT INTO devices(id, ik, first_seen, last_seen) VALUES('ab', x'00', 1, 1)")
    db.commit()
    db.close()
    st = Storage(path)
    assert st.version() == SCHEMA_VERSION == 4
    assert st.device("ab") is not None
    st.v1_add_channel("general", 0)
    st.set_setting("x", {"a": 1})
    assert st.setting("x") == {"a": 1}
    st.close()
    st = Storage(path)  # idempotent
    assert st.version() == 4
    st.close()
    db = sqlite3.connect(path)
    db.execute("PRAGMA user_version=99")
    db.commit()
    db.close()
    with pytest.raises(RuntimeError):
        Storage(path)


def test_state_and_relay_key_survive_restart(tmp_path):
    async def body():
        d = Device()
        async with relay_server(tmp=str(tmp_path)) as srv:
            key1 = srv.relay.key.public
            a = await d.connect(srv.ports["plain"])
            assert a["new"]
            await d.join("pub:general")
            await d.send_post("pub:general", "persisted")
        assert (tmp_path / "relay_key").stat().st_mode & 0o777 == 0o600
        async with relay_server(tmp=str(tmp_path)) as srv:
            assert srv.relay.key.public == key1
            a = await d.connect(srv.ports["plain"])
            assert not a["new"]
            items, done = await d.sync(rooms={"pub:general": "0"})
            assert [f["post"]["body"] for f in items if f["type"] == "room.pub"] == ["persisted"]
            assert "pub:general" in srv.relay.by_device[d.id].copy().pop().public_rooms
    run(body())


def test_profiles_and_validation():
    c = Config.from_env({})
    assert c.profile == "selfhost" and c.legacy_v1 and not c.web_view and c.public_rooms == ["pub:general"]
    assert c.tls_port == 7778 and c.plain_port == 7777 and not c.plain and c.public_room_create == "operator"
    assert (c.ttl_days, c.max_queue, c.max_queue_bytes) == (7, 500, 5242880)
    o = Config.from_env({"SC2_PROFILE": "official"})
    assert not o.legacy_v1 and o.web_view and o.official
    with pytest.raises(ConfigError):
        Config.from_env({"SC2_PROFILE": "official", "SC2_LEGACY_V1": "true"})
    for bad in ({"SC2_ADMISSION": "maybe"}, {"SC2_ADMISSION": "code"}, {"SC2_TLS_CERT": "/x"},
                {"SC2_PUBLIC_ROOMS": "Bad Name"}, {"SC2_PUBLIC_ROOM_CREATE": "all"}, {"SC2_TTL_DAYS": "x"},
                {"SC2_LEGACY_V1": "perhaps"}, {"SC2_ALLOWLIST": "nothex"}, {"SC2_ADMIN_LISTEN": "nope"}):
        with pytest.raises(ConfigError):
            Config.from_env(bad)
    c = Config.from_env({"SC2_PUBLIC_ROOMS": "general, solar-dev", "SC2_ALLOWLIST": "ab" * 16})
    assert c.public_rooms == ["pub:general", "pub:solar-dev"] and c.allowlist == ["ab" * 16]
    assert "admin_token" not in Config.from_env({"SC2_ADMIN_TOKEN": "s3cret"}).summary()


def test_env_files_and_cli(tmp_path, capsys):
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    for name in ("official.env", "selfhost.env"):
        env = load_env_file(os.path.join(here, "..", "config", name))
        cfg = Config.from_env(env)
        assert cfg.profile == name.split(".")[0]
    p = tmp_path / "x.env"
    p.write_text("# comment\nexport SC2_RELAY_ID='r.example'\nSC2_PLAIN=true\n")
    assert load_env_file(str(p)) == {"SC2_RELAY_ID": "r.example", "SC2_PLAIN": "true"}
    assert main(["--env-file", str(p), "--check-config"]) == 0
    assert '"relay_id": "r.example"' in capsys.readouterr().out
    p.write_text("SC2_ADMISSION=bogus\n")
    assert main(["--env-file", str(p), "--check-config"]) == 2
