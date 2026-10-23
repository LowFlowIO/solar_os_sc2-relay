"""Private-room commit sequencing (draft §6.7, §7.3, §7.4).

The relay is the sequencer: it accepts a commit only when it extends the
current head (epoch = current + 1, prev = head commit ID), the signer is an
admin of the current roster, the single change it describes is allowed and
the resulting roster matches count and roster_hash. It can refuse commits but
cannot forge them. Signature checks are delegated to a
verify(device_hex, signed_bytes, sig_bytes) callable so this module stays
free of crypto and I/O.

A commit carries exactly one change (create, add, remove, promote, demote,
rotate). Several changes are several consecutive commits; clients distribute
the new epoch key only after the last one.

SPDX-License-Identifier: MIT
"""

from .codec import hexd, hexe
from .errors import ProtocolError
from . import layouts

ADMIN = layouts.ROLE_ADMIN
MEMBER = layouts.ROLE_MEMBER


class RoomState:
    """Signed membership of one private room as the relay sees it.

    roster maps device hex IDs to ADMIN or MEMBER; head is the hex ID of the
    last accepted commit (empty before genesis)."""

    def __init__(self, room, epoch=0, roster=None, head="", max_members=layouts.ROOM_MEMBERS_MAX):
        self.room = room
        self.epoch = epoch
        self.roster = dict(roster or {})
        self.head = head
        self.max_members = min(max_members, layouts.ROOM_MEMBERS_MAX)

    @property
    def members(self):
        return set(self.roster)

    @property
    def admins(self):
        return {d for d, role in self.roster.items() if role == ADMIN}

    def copy(self):
        return RoomState(self.room, self.epoch, self.roster, self.head, self.max_members)

    def roster_hash(self):
        return layouts.roster_hash({hexd(d, 16): r for d, r in self.roster.items()})

    def _after(self, op, target):
        m = dict(self.roster)
        if op == "create" or op == "promote":
            m[target] = ADMIN
        elif op == "add" or op == "demote":
            m[target] = MEMBER
        elif op == "remove":
            m.pop(target, None)
        return m

    def check(self, by, op, target):
        """Roster rules for one change by `by` (hex IDs; target "" for rotate)."""
        if op == "create":
            if self.epoch != 0:
                raise ProtocolError(409, "epoch_conflict", "room already has a genesis commit", epoch=self.epoch)
            return
        if self.epoch == 0:
            raise ProtocolError(404, "unknown_room", "room has no genesis commit")
        if self.roster.get(by) != ADMIN:
            raise ProtocolError(403, "forbidden", "only room admins may commit")
        admins = len(self.admins)
        if op == "add":
            if target in self.roster:
                raise ProtocolError(400, "bad_request", "added device is already a member")
            if len(self.roster) >= self.max_members:
                raise ProtocolError(403, "forbidden", "room is full")
        elif op in ("remove", "promote", "demote"):
            if target not in self.roster:
                raise ProtocolError(400, "bad_request", "target is not a member")
            if op == "promote" and self.roster[target] == ADMIN:
                raise ProtocolError(400, "bad_request", "target is already an admin")
            if op == "demote" and self.roster[target] != ADMIN:
                raise ProtocolError(400, "bad_request", "target is not an admin")
            if op != "promote" and self.roster[target] == ADMIN and admins <= 1:
                raise ProtocolError(400, "bad_request", "the last admin cannot be removed or demoted")

    def apply(self, record, sig, verify, creator=None):
        """Validate one commit record (130 raw bytes) with its 64-byte
        signature. creator is the authenticated device for room.create (the
        genesis must be its own). Returns (new state, parsed commit); self is
        not modified."""
        c = layouts.commit_parse(record)
        if hexe(c["room"]) != self.room:
            raise ProtocolError(400, "bad_request", "commit is for another room")
        by = hexe(c["by"])
        target = "" if c["op"] == "rotate" else hexe(c["target"])
        if (c["op"] == "create") != (creator is not None):
            raise ProtocolError(400, "bad_request", "room.create carries the genesis commit; room.commit the rest")
        if creator is not None and by != creator:
            raise ProtocolError(403, "forbidden", "genesis must be signed by the creator")
        if c["op"] != "create":
            if self.epoch == 0:
                raise ProtocolError(404, "unknown_room", "room has no genesis commit")
            if c["epoch"] != self.epoch + 1 or hexe(c["prev"]) != self.head:
                raise ProtocolError(409, "epoch_conflict", "commit does not extend the current head",
                                    epoch=self.epoch, head=self.head)
        self.check(by, c["op"], target)
        roster = self._after(c["op"], target)
        rhash = layouts.roster_hash({hexd(d, 16): r for d, r in roster.items()})
        if len(roster) != c["count"] or not layouts.ct_equal(rhash, c["hash"]):
            raise ProtocolError(400, "bad_request", "count/roster_hash do not match the resulting roster")
        if not verify(by, bytes(record), bytes(sig)):
            raise ProtocolError(401, "bad_sig", "commit signature invalid")
        new = RoomState(self.room, c["epoch"], roster, hexe(layouts.commit_id(record)), self.max_members)
        return new, c


def make_commit(state, by, op, target=None, sign=None):
    """Client/test helper: the commit record for one change on top of state,
    and its signature (sign(bytes) -> 64 bytes; zeros when sign is None).
    by and target are hex IDs; target defaults to by for create and is
    ignored for rotate. Rules are not checked here (the relay checks them)."""
    if op == "create":
        target = by
    elif op == "rotate":
        target = None
    roster = state._after(op, target) if op != "rotate" else dict(state.roster)
    rhash = layouts.roster_hash({hexd(d, 16): r for d, r in roster.items()})
    prev = layouts.ZERO32 if state.epoch == 0 else hexd(state.head, 32)
    rec = layouts.commit_record(hexd(state.room, 16), state.epoch + 1, prev, hexd(by, 16), op,
                                layouts.ZERO16 if target is None else hexd(target, 16), len(roster), rhash)
    return rec, (sign(rec) if sign is not None else bytes(64))
