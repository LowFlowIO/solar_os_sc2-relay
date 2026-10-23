"""Private file modes for relay state, independent of the process umask.

The data directory is 0700; the SQLite database with its -wal/-shm files
and the relay key are 0600. Files are created with O_CREAT and an explicit
mode and then chmod'ed, so a permissive umask (e.g. 000 in some container
setups) never leaves them group/world readable, and a pre-existing file
with a loose mode is tightened at startup.

SPDX-License-Identifier: MIT
"""

import logging
import os
import stat

log = logging.getLogger("sc2_relay")

DIR_MODE = 0o700
FILE_MODE = 0o600


def _tighten(path, mode):
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return
    if stat.S_IMODE(st.st_mode) != mode:
        try:
            os.chmod(path, mode)
        except PermissionError:
            log.warning("cannot set mode %o on %s (owned by uid %d)", mode, path, st.st_uid)


def private_dir(path):
    """Create path (and parents) if needed; the leaf ends up 0700."""
    if not path:
        return
    os.makedirs(path, mode=DIR_MODE, exist_ok=True)
    _tighten(path, DIR_MODE)


def private_file(path):
    """Create path empty if missing (0600) and make sure it is 0600."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT, FILE_MODE)
    os.close(fd)
    _tighten(path, FILE_MODE)


def tighten_file(path):
    """0600 on path if it exists."""
    _tighten(path, FILE_MODE)


def sqlite_files(db_path):
    return [db_path, db_path + "-wal", db_path + "-shm", db_path + "-journal"]
