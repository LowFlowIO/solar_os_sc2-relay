"""Relay state is private regardless of the umask: data dir 0700, SQLite
database with -wal/-shm and the relay key 0600; loose modes on existing
files are tightened at startup.

SPDX-License-Identifier: MIT
"""

import os
import stat

from helpers import make_config, run
from sc2_relay.server import RelayServer


def _mode(p):
    return stat.S_IMODE(os.stat(p).st_mode)


def _start_stop(cfg):
    async def body():
        srv = RelayServer(cfg)
        await srv.start()
        srv.relay.store.db.execute("CREATE TABLE IF NOT EXISTS t_perm(x)")  # make sure the WAL is written
        srv.relay.store.db.execute("INSERT INTO t_perm VALUES (1)")
        files = {p: _mode(p) for p in (cfg.database + "-wal", cfg.database + "-shm") if os.path.exists(p)}
        await srv.close()
        return files
    return run(body())


def test_private_modes_under_a_permissive_umask(tmp_path):
    old = os.umask(0)
    try:
        data = str(tmp_path / "new" / "data")
        cfg = make_config(data)
        wal = _start_stop(cfg)
        assert _mode(data) == 0o700
        assert _mode(cfg.database) == 0o600
        assert _mode(cfg.key_path) == 0o600
        assert cfg.database + "-wal" in wal and cfg.database + "-shm" in wal
        assert set(wal.values()) == {0o600}
    finally:
        os.umask(old)


def test_loose_existing_modes_are_tightened(tmp_path):
    data = str(tmp_path / "data")
    cfg = make_config(data)
    _start_stop(cfg)
    os.chmod(data, 0o755)
    for p in (cfg.database, cfg.key_path):
        os.chmod(p, 0o644)
    old = os.umask(0o002)
    try:
        wal = _start_stop(cfg)
    finally:
        os.umask(old)
    assert _mode(data) == 0o700
    assert _mode(cfg.database) == 0o600 and _mode(cfg.key_path) == 0o600
    assert set(wal.values()) == {0o600}
