"""SQLite storage with versioned schema migrations.

The relay keeps only what routing needs: public keys, opaque sealed
envelopes, signed public posts, membership, moderation and ban records.
Everything runs in one thread (the asyncio loop); each public method is a
short transaction.

SPDX-License-Identifier: MIT
"""

import json
import os
import sqlite3

from sc2proto import dumps

from . import fsperm

MIGRATIONS = [
    # 1: the SC2 v2 relay
    """
    CREATE TABLE meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);
    CREATE TABLE devices(
        id TEXT PRIMARY KEY, ik BLOB NOT NULL,
        dk BLOB, dk_sig BLOB, spk_id INTEGER, spk BLOB, spk_sig BLOB,
        first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, posts INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE opks(device TEXT NOT NULL, id INTEGER NOT NULL, pub BLOB NOT NULL, PRIMARY KEY(device, id));
    CREATE TABLE purged(device TEXT PRIMARY KEY, ts INTEGER NOT NULL);
    CREATE TABLE rooms(
        id TEXT PRIMARY KEY, kind TEXT NOT NULL, title TEXT, epoch INTEGER NOT NULL DEFAULT 0,
        seq INTEGER NOT NULL DEFAULT 0, policy TEXT NOT NULL DEFAULT '{}', slow INTEGER NOT NULL DEFAULT 0,
        created INTEGER NOT NULL);
    CREATE TABLE members(
        room TEXT NOT NULL, device TEXT NOT NULL, admin INTEGER NOT NULL DEFAULT 0,
        join_seq INTEGER NOT NULL, routing INTEGER NOT NULL DEFAULT 1, PRIMARY KEY(room, device));
    CREATE INDEX members_device ON members(device);
    CREATE TABLE invites(room TEXT NOT NULL, key BLOB NOT NULL, created INTEGER NOT NULL, PRIMARY KEY(room, key));
    CREATE TABLE commits(room TEXT NOT NULL, epoch INTEGER NOT NULL, seq INTEGER NOT NULL, commit_json TEXT NOT NULL,
        ts INTEGER NOT NULL, PRIMARY KEY(room, epoch));
    CREATE TABLE room_log(
        room TEXT NOT NULL, seq INTEGER NOT NULL, kind TEXT NOT NULL, audience TEXT NOT NULL DEFAULT 'all',
        data TEXT NOT NULL, ts INTEGER NOT NULL, dedup TEXT, PRIMARY KEY(room, seq));
    CREATE UNIQUE INDEX room_log_dedup ON room_log(room, dedup) WHERE dedup IS NOT NULL;
    CREATE INDEX room_log_ts ON room_log(ts);
    CREATE TABLE public_members(
        room TEXT NOT NULL, device TEXT NOT NULL, joined INTEGER NOT NULL DEFAULT 1,
        notice_seen INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(room, device));
    CREATE TABLE public_log(
        room TEXT NOT NULL, seq INTEGER NOT NULL, from_dev TEXT NOT NULL, id TEXT NOT NULL, post TEXT NOT NULL,
        ts INTEGER NOT NULL, deleted INTEGER NOT NULL DEFAULT 0, removed INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY(room, seq), UNIQUE(room, from_dev, id));
    CREATE INDEX public_log_ts ON public_log(ts);
    CREATE TABLE mod(
        room TEXT NOT NULL, seq INTEGER NOT NULL, action TEXT NOT NULL, ref TEXT, device TEXT, until INTEGER,
        by TEXT NOT NULL DEFAULT 'relay', ts INTEGER NOT NULL, frame TEXT NOT NULL, PRIMARY KEY(room, seq));
    CREATE TABLE bans(kind TEXT NOT NULL, value TEXT NOT NULL, until INTEGER, reason TEXT NOT NULL DEFAULT '',
        created INTEGER NOT NULL, PRIMARY KEY(kind, value));
    CREATE TABLE mutes(kind TEXT NOT NULL, value TEXT NOT NULL, until INTEGER, reason TEXT NOT NULL DEFAULT '',
        created INTEGER NOT NULL, PRIMARY KEY(kind, value));
    CREATE TABLE reports(id INTEGER PRIMARY KEY AUTOINCREMENT, room TEXT NOT NULL, ref TEXT NOT NULL,
        reporter TEXT NOT NULL, reason TEXT NOT NULL, ts INTEGER NOT NULL, resolved INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE inbox(
        device TEXT NOT NULL, seq INTEGER NOT NULL, kind TEXT NOT NULL, data TEXT NOT NULL, size INTEGER NOT NULL,
        ts INTEGER NOT NULL, dedup TEXT, PRIMARY KEY(device, seq));
    CREATE UNIQUE INDEX inbox_dedup ON inbox(device, dedup) WHERE dedup IS NOT NULL;
    CREATE INDEX inbox_ts ON inbox(ts);
    CREATE TABLE inbox_seq(device TEXT PRIMARY KEY, seq INTEGER NOT NULL);
    """,
    # 2: legacy v1 namespace (chatd compatible); never shares rows with v2 rooms
    """
    CREATE TABLE v1_channels(name TEXT PRIMARY KEY, created INTEGER NOT NULL);
    CREATE TABLE v1_log(id INTEGER PRIMARY KEY AUTOINCREMENT, channel TEXT NOT NULL, from_user TEXT NOT NULL,
        text TEXT NOT NULL, ts INTEGER NOT NULL);
    CREATE INDEX v1_log_channel ON v1_log(channel, id);
    """,
    # 3: operator settings changed at runtime through the admin interface
    """
    CREATE TABLE settings(k TEXT PRIMARY KEY, v TEXT NOT NULL);
    """,
    # 4: fixed-size commit records: rooms remember the head commit
    # ID that the next commit's prev must name
    """
    ALTER TABLE rooms ADD COLUMN head TEXT NOT NULL DEFAULT ''
    """,
]

SCHEMA_VERSION = len(MIGRATIONS)
INT_MAX = (1 << 63) - 1


def _clamp(args):
    """Wire cursors are uint64; SQLite integers are signed 64-bit. A cursor
    above every stored seq means the same as INT_MAX."""
    return tuple(INT_MAX if isinstance(a, int) and a > INT_MAX else a for a in args)


class Storage:
    def __init__(self, path):
        self.path = path
        if path != ":memory:":
            d = os.path.dirname(os.path.abspath(path))
            if not os.path.isdir(d):
                fsperm.private_dir(d)
            # SQLite gives -wal/-shm the database file's mode, so create it 0600 first
            fsperm.private_file(path)
        self.db = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        if path != ":memory:":
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=NORMAL")
        self.migrate()
        if path != ":memory:":
            for f in fsperm.sqlite_files(path):
                fsperm.tighten_file(f)

    # ---------------- schema ----------------

    def version(self):
        return self.db.execute("PRAGMA user_version").fetchone()[0]

    def migrate(self, target=SCHEMA_VERSION):
        v = self.version()
        if v > SCHEMA_VERSION:
            raise RuntimeError("database schema %d is newer than this relay (%d)" % (v, SCHEMA_VERSION))
        while v < target:
            script = MIGRATIONS[v]
            self.db.execute("BEGIN")
            try:
                for stmt in [s.strip() for s in script.split(";") if s.strip()]:
                    self.db.execute(stmt)
                self.db.execute("PRAGMA user_version=%d" % (v + 1))
                self.db.execute("COMMIT")
            except Exception:
                self.db.execute("ROLLBACK")
                raise
            v += 1

    def close(self):
        self.db.close()

    def tx(self):
        return _Tx(self.db)

    def one(self, sql, args=()):
        return self.db.execute(sql, _clamp(args)).fetchone()

    def all(self, sql, args=()):
        return self.db.execute(sql, _clamp(args)).fetchall()

    def scalar(self, sql, args=(), default=None):
        r = self.db.execute(sql, _clamp(args)).fetchone()
        return default if r is None or r[0] is None else r[0]

    # ---------------- settings ----------------

    def setting(self, key, default=None):
        r = self.one("SELECT v FROM settings WHERE k=?", (key,))
        return default if r is None else json.loads(r["v"])

    def set_setting(self, key, value):
        self.db.execute("INSERT INTO settings(k, v) VALUES(?, ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                        (key, json.dumps(value)))

    # ---------------- devices and keys ----------------

    def device(self, dev):
        return self.one("SELECT * FROM devices WHERE id=?", (dev,))

    def is_purged(self, dev):
        return self.one("SELECT 1 FROM purged WHERE device=?", (dev,)) is not None

    def register(self, dev, ik, now):
        self.db.execute("INSERT INTO devices(id, ik, first_seen, last_seen) VALUES(?, ?, ?, ?)", (dev, ik, now, now))

    def touch(self, dev, now):
        self.db.execute("UPDATE devices SET last_seen=? WHERE id=?", (now, dev))

    def publish_keys(self, dev, dk, dk_sig, spk_id, spk, spk_sig, opks, opk_max):
        with self.tx():
            self.db.execute("UPDATE devices SET dk=?, dk_sig=?, spk_id=?, spk=?, spk_sig=? WHERE id=?",
                            (dk, dk_sig, spk_id, spk, spk_sig, dev))
            have = self.scalar("SELECT COUNT(*) FROM opks WHERE device=?", (dev,), 0)
            for oid, pub in opks:
                exists = self.one("SELECT 1 FROM opks WHERE device=? AND id=?", (dev, oid)) is not None
                if exists:
                    self.db.execute("UPDATE opks SET pub=? WHERE device=? AND id=?", (pub, dev, oid))
                elif have < opk_max:
                    self.db.execute("INSERT INTO opks(device, id, pub) VALUES(?, ?, ?)", (dev, oid, pub))
                    have += 1
        return self.opk_count(dev)

    def opk_count(self, dev):
        return self.scalar("SELECT COUNT(*) FROM opks WHERE device=?", (dev,), 0)

    def claim_opk(self, dev):
        with self.tx():
            r = self.one("SELECT id, pub FROM opks WHERE device=? ORDER BY id LIMIT 1", (dev,))
            if r is None:
                return None
            self.db.execute("DELETE FROM opks WHERE device=? AND id=?", (dev, r["id"]))
            return r["id"], r["pub"]

    def note_post(self, dev):
        self.db.execute("UPDATE devices SET posts=posts+1 WHERE id=?", (dev,))

    def purge_device(self, dev, now):
        with self.tx():
            self.db.execute("INSERT OR REPLACE INTO purged(device, ts) VALUES(?, ?)", (dev, now))
            self.db.execute("DELETE FROM opks WHERE device=?", (dev,))
            self.db.execute("UPDATE devices SET dk=NULL, dk_sig=NULL, spk_id=NULL, spk=NULL, spk_sig=NULL WHERE id=?",
                            (dev,))
            self.db.execute("DELETE FROM inbox WHERE device=?", (dev,))
            self.db.execute("UPDATE members SET routing=0 WHERE device=?", (dev,))
            self.db.execute("DELETE FROM public_members WHERE device=?", (dev,))

    # ---------------- rooms ----------------

    def room(self, room):
        return self.one("SELECT * FROM rooms WHERE id=?", (room,))

    def create_room(self, room, kind, title, policy, now):
        self.db.execute("INSERT INTO rooms(id, kind, title, policy, created) VALUES(?, ?, ?, ?, ?)",
                        (room, kind, title, dumps(policy), now))

    def public_rooms(self):
        return self.all("SELECT * FROM rooms WHERE kind='public' ORDER BY id")

    def next_seq(self, room):
        self.db.execute("UPDATE rooms SET seq=seq+1 WHERE id=?", (room,))
        return self.scalar("SELECT seq FROM rooms WHERE id=?", (room,))

    def set_slow(self, room, on):
        self.db.execute("UPDATE rooms SET slow=? WHERE id=?", (1 if on else 0, room))

    def members(self, room):
        return self.all("SELECT * FROM members WHERE room=? ORDER BY device", (room,))

    def member(self, room, dev):
        return self.one("SELECT * FROM members WHERE room=? AND device=?", (room, dev))

    def routing_members(self, room):
        return [r["device"] for r in self.all("SELECT device FROM members WHERE room=? AND routing=1", (room,))]

    def private_rooms_of(self, dev):
        return [r["room"] for r in self.all(
            "SELECT m.room FROM members m JOIN rooms r ON r.id=m.room WHERE m.device=? AND r.kind='private'"
            " ORDER BY m.room", (dev,))]

    def private_room_count(self, dev):
        return self.scalar("SELECT COUNT(*) FROM members WHERE device=?", (dev,), 0)

    def shared_rooms(self, dev):
        """Private rooms where dev is routed, with their routed co-members."""
        out = {}
        for r in self.all("SELECT m2.room, m2.device FROM members m1 JOIN members m2 ON m1.room=m2.room "
                          "WHERE m1.device=? AND m1.routing=1 AND m2.routing=1 AND m2.device<>?", (dev, dev)):
            out.setdefault(r["device"], []).append(r["room"])
        return out

    def apply_commit(self, room, state, commit, seq, now, added, removed):
        """Store one accepted commit ({"commit", "sig"} as on the wire) and the
        resulting roster (members and admin flags) of state."""
        self.db.execute("UPDATE rooms SET epoch=?, head=? WHERE id=?", (state.epoch, state.head, room))
        self.db.execute("INSERT INTO commits(room, epoch, seq, commit_json, ts) VALUES(?, ?, ?, ?, ?)",
                        (room, state.epoch, seq, dumps(commit), now))
        for d in removed:
            self.db.execute("DELETE FROM members WHERE room=? AND device=?", (room, d))
        for d in added:
            self.db.execute("INSERT INTO members(room, device, admin, join_seq, routing) VALUES(?, ?, 0, ?, 1)",
                            (room, d, seq))
        self.db.execute("UPDATE members SET admin=0 WHERE room=?", (room,))
        for a in state.admins:
            self.db.execute("UPDATE members SET admin=1 WHERE room=? AND device=?", (room, a))

    def set_routing(self, room, dev, on):
        self.db.execute("UPDATE members SET routing=? WHERE room=? AND device=?", (1 if on else 0, room, dev))

    def commits(self, room):
        return self.all("SELECT * FROM commits WHERE room=? ORDER BY epoch", (room,))

    def add_invite(self, room, key, now, cap=16):
        with self.tx():
            self.db.execute("INSERT OR IGNORE INTO invites(room, key, created) VALUES(?, ?, ?)", (room, key, now))
            n = self.scalar("SELECT COUNT(*) FROM invites WHERE room=?", (room,), 0)
            if n > cap:
                self.db.execute("DELETE FROM invites WHERE rowid IN (SELECT rowid FROM invites WHERE room=? "
                                "ORDER BY created, rowid LIMIT ?)", (room, n - cap))

    def revoke_invite(self, room, key):
        self.db.execute("DELETE FROM invites WHERE room=? AND key=?", (room, key))

    def invites(self, room):
        return [bytes(r["key"]) for r in self.all("SELECT key FROM invites WHERE room=?", (room,))]

    # ---------------- private room log ----------------

    def room_log_add(self, room, seq, kind, data, now, audience="all", dedup=None):
        self.db.execute("INSERT INTO room_log(room, seq, kind, audience, data, ts, dedup) VALUES(?, ?, ?, ?, ?, ?, ?)",
                        (room, seq, kind, audience, data, now, dedup))

    def room_log_dedup(self, room, dedup):
        return self.scalar("SELECT seq FROM room_log WHERE room=? AND dedup=?", (room, dedup))

    def room_log_range(self, room):
        r = self.one("SELECT MIN(seq) AS lo, MAX(seq) AS hi FROM room_log WHERE room=?", (room,))
        return r["lo"], r["hi"]

    def room_log_after(self, room, after, limit):
        return self.all("SELECT * FROM room_log WHERE room=? AND seq>? ORDER BY seq LIMIT ?", (room, after, limit))

    # ---------------- public rooms ----------------

    def public_member(self, room, dev):
        return self.one("SELECT * FROM public_members WHERE room=? AND device=?", (room, dev))

    def public_join(self, room, dev):
        """Returns True on the very first join of dev to room (notice due)."""
        r = self.public_member(room, dev)
        if r is None:
            self.db.execute("INSERT INTO public_members(room, device, joined, notice_seen) VALUES(?, ?, 1, 1)",
                            (room, dev))
            return True
        self.db.execute("UPDATE public_members SET joined=1, notice_seen=1 WHERE room=? AND device=?", (room, dev))
        return not r["notice_seen"]

    def public_leave(self, room, dev):
        self.db.execute("UPDATE public_members SET joined=0 WHERE room=? AND device=?", (room, dev))

    def public_joined_rooms(self, dev):
        return [r["room"] for r in self.all("SELECT room FROM public_members WHERE device=? AND joined=1", (dev,))]

    def public_member_count(self, room):
        return self.scalar("SELECT COUNT(*) FROM public_members WHERE room=? AND joined=1", (room,), 0)

    def post_by_id(self, room, dev, msg_id):
        return self.one("SELECT * FROM public_log WHERE room=? AND from_dev=? AND id=?", (room, dev, msg_id))

    def post_any(self, room, msg_id):
        return self.one("SELECT * FROM public_log WHERE room=? AND id=? ORDER BY seq LIMIT 1", (room, msg_id))

    def public_add(self, room, seq, post, now):
        self.db.execute("INSERT INTO public_log(room, seq, from_dev, id, post, ts) VALUES(?, ?, ?, ?, ?, ?)",
                        (room, seq, post["from"], post["id"], dumps(post), now))

    def mark_deleted(self, room, dev, msg_id):
        self.db.execute("UPDATE public_log SET deleted=1 WHERE room=? AND from_dev=? AND id=?", (room, dev, msg_id))

    def mark_removed(self, room, seq):
        self.db.execute("UPDATE public_log SET removed=1 WHERE room=? AND seq=?", (room, seq))

    def public_range(self, room):
        r = self.one("SELECT MIN(s) AS lo, MAX(s) AS hi FROM (SELECT seq AS s FROM public_log WHERE room=? "
                     "UNION ALL SELECT seq AS s FROM mod WHERE room=?)", (room, room))
        return r["lo"], r["hi"]

    def public_after(self, room, after, limit, include_removed=False):
        """Posts and moderation events after seq, merged in seq order."""
        cond = "" if include_removed else " AND removed=0"
        posts = self.all("SELECT seq, post FROM public_log WHERE room=? AND seq>?" + cond + " ORDER BY seq LIMIT ?",
                         (room, after, limit))
        mods = self.all("SELECT seq, frame FROM mod WHERE room=? AND seq>? ORDER BY seq LIMIT ?", (room, after, limit))
        items = [(r["seq"], "post", r["post"]) for r in posts] + [(r["seq"], "mod", r["frame"]) for r in mods]
        items.sort(key=lambda x: x[0])
        return items[:limit]

    def web_posts_after(self, room, after, limit):
        return self.all("SELECT seq, post FROM public_log WHERE room=? AND seq>? AND removed=0 ORDER BY seq LIMIT ?",
                        (room, after, limit))

    def web_mods_after(self, room, after, limit):
        return self.all("SELECT seq, frame FROM mod WHERE room=? AND seq>? ORDER BY seq LIMIT ?", (room, after, limit))

    def web_posts_before(self, room, before, limit):
        return self.all("SELECT seq, post, from_dev, ts FROM public_log WHERE room=? AND seq<? AND removed=0 "
                        "AND deleted=0 AND json_extract(post, '$.t')='text' ORDER BY seq DESC LIMIT ?",
                        (room, before, limit))

    def search_posts(self, room, query, limit):
        args = [room]
        sql = "SELECT seq, post, removed, deleted, ts FROM public_log WHERE room=?"
        if query:
            sql += " AND (json_extract(post, '$.body') LIKE ? ESCAPE '\\' OR json_extract(post, '$.name') LIKE ? " \
                   "ESCAPE '\\' OR from_dev=? OR id=?)"
            like = "%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            args += [like, like, query, query]
        sql += " ORDER BY seq DESC LIMIT ?"
        args.append(limit)
        return self.all(sql, args)

    def posts_of(self, room, dev):
        return self.all("SELECT seq, id FROM public_log WHERE room=? AND from_dev=? AND removed=0 ORDER BY seq",
                        (room, dev))

    def add_mod(self, room, seq, action, ref, device, until, now, frame):
        self.db.execute("INSERT INTO mod(room, seq, action, ref, device, until, ts, frame) "
                        "VALUES(?, ?, ?, ?, ?, ?, ?, ?)", (room, seq, action, ref, device, until, now, dumps(frame)))

    # ---------------- bans, mutes, reports ----------------

    def _active(self, table, kind, value, now):
        r = self.one("SELECT until FROM " + table + " WHERE kind=? AND value=?", (kind, value))
        if r is None:
            return False, None
        if r["until"] is not None and r["until"] <= now:
            return False, None
        return True, r["until"]

    def ban_active(self, kind, value, now):
        return self._active("bans", kind, value, now)

    def mute_active(self, kind, value, now):
        return self._active("mutes", kind, value, now)

    def set_ban(self, table, kind, value, until, reason, now):
        assert table in ("bans", "mutes")
        self.db.execute("INSERT INTO " + table + "(kind, value, until, reason, created) VALUES(?, ?, ?, ?, ?) "
                        "ON CONFLICT(kind, value) DO UPDATE SET until=excluded.until, reason=excluded.reason, "
                        "created=excluded.created", (kind, value, until, reason, now))

    def lift_ban(self, table, kind, value):
        assert table in ("bans", "mutes")
        cur = self.db.execute("DELETE FROM " + table + " WHERE kind=? AND value=?", (kind, value))
        return cur.rowcount > 0

    def list_bans(self, table, now):
        assert table in ("bans", "mutes")
        return [dict(r) for r in self.all("SELECT * FROM " + table + " WHERE until IS NULL OR until>? "
                                          "ORDER BY created", (now,))]

    def add_report(self, room, ref, reporter, reason, now):
        cur = self.db.execute("INSERT INTO reports(room, ref, reporter, reason, ts) VALUES(?, ?, ?, ?, ?)",
                              (room, ref, reporter, reason, now))
        return cur.lastrowid

    def reports(self, include_resolved=False):
        sql = "SELECT * FROM reports" + ("" if include_resolved else " WHERE resolved=0") + " ORDER BY id"
        return [dict(r) for r in self.all(sql)]

    def resolve_report(self, rid):
        return self.db.execute("UPDATE reports SET resolved=1 WHERE id=?", (rid,)).rowcount > 0

    # ---------------- inbox ----------------

    def inbox_stats(self, dev):
        r = self.one("SELECT COUNT(*) AS n, COALESCE(SUM(size), 0) AS b FROM inbox WHERE device=?", (dev,))
        return r["n"], r["b"]

    def inbox_dedup(self, dev, dedup):
        return self.scalar("SELECT seq FROM inbox WHERE device=? AND dedup=?", (dev, dedup))

    def inbox_add(self, dev, kind, data, size, now, dedup=None):
        with self.tx():
            self.db.execute("INSERT INTO inbox_seq(device, seq) VALUES(?, 1) "
                            "ON CONFLICT(device) DO UPDATE SET seq=seq+1", (dev,))
            seq = self.scalar("SELECT seq FROM inbox_seq WHERE device=?", (dev,))
            self.db.execute("INSERT INTO inbox(device, seq, kind, data, size, ts, dedup) VALUES(?, ?, ?, ?, ?, ?, ?)",
                            (dev, seq, kind, data, size, now, dedup))
        return seq

    def inbox_after(self, dev, after, limit):
        return self.all("SELECT * FROM inbox WHERE device=? AND seq>? ORDER BY seq LIMIT ?", (dev, after, limit))

    def inbox_range(self, dev):
        r = self.one("SELECT MIN(seq) AS lo, MAX(seq) AS hi FROM inbox WHERE device=?", (dev,))
        return r["lo"], r["hi"]

    def inbox_ack(self, dev, seq):
        return self.db.execute("DELETE FROM inbox WHERE device=? AND seq<=?", _clamp((dev, seq))).rowcount

    # ---------------- legacy v1 ----------------

    def v1_channels(self):
        return [r["name"] for r in self.all("SELECT name FROM v1_channels ORDER BY created, rowid")]

    def v1_add_channel(self, name, now):
        self.db.execute("INSERT OR IGNORE INTO v1_channels(name, created) VALUES(?, ?)", (name, now))

    def v1_delete_channel(self, name):
        with self.tx():
            self.db.execute("DELETE FROM v1_channels WHERE name=?", (name,))
            self.db.execute("DELETE FROM v1_log WHERE channel=?", (name,))

    def v1_add_msg(self, channel, frm, text, ts_ms):
        return self.db.execute("INSERT INTO v1_log(channel, from_user, text, ts) VALUES(?, ?, ?, ?)",
                               (channel, frm, text, ts_ms)).lastrowid

    def v1_history(self, channel, cursor, limit):
        rows = self.all("SELECT * FROM v1_log WHERE channel=? AND id>? ORDER BY id DESC LIMIT ?",
                        (channel, cursor, limit))
        return list(reversed(rows))

    # ---------------- retention ----------------

    def retention(self, cutoff, private_max, public_max, v1_keep, v1_cutoff_ms):
        """Apply TTL and per-room caps. Returns a dict of deleted row counts."""
        out = {}
        with self.tx():
            out["inbox"] = self.db.execute("DELETE FROM inbox WHERE ts<?", (cutoff,)).rowcount
            out["room_log"] = self.db.execute("DELETE FROM room_log WHERE ts<?", (cutoff,)).rowcount
            out["public_log"] = self.db.execute("DELETE FROM public_log WHERE ts<?", (cutoff,)).rowcount
            out["mod"] = self.db.execute("DELETE FROM mod WHERE ts<?", (cutoff,)).rowcount
            for r in self.all("SELECT room, COUNT(*) AS n, MAX(seq) AS hi FROM room_log GROUP BY room HAVING n>?",
                              (private_max,)):
                out["room_log"] += self.db.execute(
                    "DELETE FROM room_log WHERE room=? AND seq NOT IN (SELECT seq FROM room_log WHERE room=? "
                    "ORDER BY seq DESC LIMIT ?)", (r["room"], r["room"], private_max)).rowcount
            for r in self.all("SELECT room, COUNT(*) AS n FROM public_log GROUP BY room HAVING n>?", (public_max,)):
                lo = self.scalar("SELECT MIN(seq) FROM (SELECT seq FROM public_log WHERE room=? ORDER BY seq DESC "
                                 "LIMIT ?)", (r["room"], public_max))
                out["public_log"] += self.db.execute("DELETE FROM public_log WHERE room=? AND seq<?",
                                                     (r["room"], lo)).rowcount
                out["mod"] += self.db.execute("DELETE FROM mod WHERE room=? AND seq<?", (r["room"], lo)).rowcount
            out["v1_log"] = self.db.execute("DELETE FROM v1_log WHERE ts<?", (v1_cutoff_ms,)).rowcount
            for r in self.all("SELECT channel, COUNT(*) AS n FROM v1_log GROUP BY channel HAVING n>?", (v1_keep,)):
                out["v1_log"] += self.db.execute(
                    "DELETE FROM v1_log WHERE channel=? AND id NOT IN (SELECT id FROM v1_log WHERE channel=? "
                    "ORDER BY id DESC LIMIT ?)", (r["channel"], r["channel"], v1_keep)).rowcount
            out["reports"] = self.db.execute("DELETE FROM reports WHERE resolved=1 AND ts<?", (cutoff,)).rowcount
        return out

    def expire_bans(self, now):
        n = self.db.execute("DELETE FROM bans WHERE until IS NOT NULL AND until<=?", (now,)).rowcount
        n += self.db.execute("DELETE FROM mutes WHERE until IS NOT NULL AND until<=?", (now,)).rowcount
        return n

    # ---------------- stats ----------------

    def stats(self):
        q = self.scalar
        return {
            "devices": q("SELECT COUNT(*) FROM devices", (), 0),
            "rooms_private": q("SELECT COUNT(*) FROM rooms WHERE kind='private'", (), 0),
            "rooms_public": q("SELECT COUNT(*) FROM rooms WHERE kind='public'", (), 0),
            "inbox_items": q("SELECT COUNT(*) FROM inbox", (), 0),
            "inbox_bytes": q("SELECT COALESCE(SUM(size), 0) FROM inbox", (), 0),
            "room_log": q("SELECT COUNT(*) FROM room_log", (), 0),
            "public_log": q("SELECT COUNT(*) FROM public_log", (), 0),
            "bans": q("SELECT COUNT(*) FROM bans", (), 0),
            "reports_open": q("SELECT COUNT(*) FROM reports WHERE resolved=0", (), 0),
            "v1_log": q("SELECT COUNT(*) FROM v1_log", (), 0),
        }

    def room_sizes(self):
        out = []
        for r in self.all("SELECT * FROM rooms ORDER BY kind, id"):
            if r["kind"] == "private":
                members = self.scalar("SELECT COUNT(*) FROM members WHERE room=?", (r["id"],), 0)
                logn = self.scalar("SELECT COUNT(*) FROM room_log WHERE room=?", (r["id"],), 0)
            else:
                members = self.public_member_count(r["id"])
                logn = self.scalar("SELECT COUNT(*) FROM public_log WHERE room=?", (r["id"],), 0)
            out.append({"room": r["id"], "kind": r["kind"], "title": r["title"], "members": members,
                        "epoch": r["epoch"], "seq": str(r["seq"]), "log": logn, "slow": bool(r["slow"])})
        return out


class _Tx:
    """Nested-safe transaction context (savepoints)."""

    _n = 0

    def __init__(self, db):
        self.db = db
        _Tx._n += 1
        self.name = "sp%d" % _Tx._n

    def __enter__(self):
        self.db.execute("SAVEPOINT " + self.name)
        return self

    def __exit__(self, et, ev, tb):
        if et is None:
            self.db.execute("RELEASE " + self.name)
        else:
            self.db.execute("ROLLBACK TO " + self.name)
            self.db.execute("RELEASE " + self.name)
        return False
