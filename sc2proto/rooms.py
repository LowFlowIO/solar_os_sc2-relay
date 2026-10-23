"""Private-room commit sequencing (draft §6.7, §7.3, §7.4).

The relay is the sequencer: it accepts a commit only when prev equals the
current epoch, the signer is an admin and the resulting member set matches
members_hash. It can refuse commits but cannot forge them. Signature checks
are delegated to a verify(device_hex, signed_bytes, sig_bytes) callable so
this module stays free of crypto and I/O.

SPDX-License-Identifier: MIT
"""

from .codec import b64d, hexd
from .errors import ProtocolError
from . import frames, layouts


class RoomState:
    """Signed membership of one private room as the relay sees it."""

    def __init__(self, room, epoch=0, members=(), admins=(), max_members=frames.ROOM_MEMBERS_MAX):
        self.room = room
        self.epoch = epoch
        self.members = set(members)
        self.admins = set(admins)
        self.max_members = max_members

    def copy(self):
        return RoomState(self.room, self.epoch, self.members, self.admins, self.max_members)

    def members_hash(self):
        return layouts.members_hash([hexd(m, 16) for m in self.members])

    def apply_genesis(self, creator, commit, verify):
        """Validate a genesis commit (prev 0, epoch 1, by = creator) and return
        the new state. The creator must be added and listed as an admin."""
        if self.epoch != 0:
            raise ProtocolError(409, "epoch_conflict", "room already has a genesis commit", epoch=self.epoch)
        if commit["prev"] != 0 or commit["epoch"] != 1:
            raise ProtocolError(400, "bad_request", "genesis must be prev 0 epoch 1")
        if commit["by"] != creator:
            raise ProtocolError(403, "forbidden", "genesis must be signed by the creator")
        if creator not in commit["add"] or commit["remove"]:
            raise ProtocolError(400, "bad_request", "genesis must add the creator and remove nobody")
        if "admins" not in commit or creator not in commit["admins"]:
            raise ProtocolError(400, "bad_request", "genesis must list the creator as admin")
        return self._apply(commit, verify, genesis=True)

    def apply(self, commit, verify):
        """Validate a follow-up commit against this state; returns the new
        state (self is not modified)."""
        if self.epoch == 0:
            raise ProtocolError(404, "unknown_room", "room has no genesis commit")
        if commit["prev"] != self.epoch:
            raise ProtocolError(409, "epoch_conflict", None, epoch=self.epoch)
        if commit["by"] not in self.admins:
            raise ProtocolError(403, "forbidden", "only room admins may commit")
        return self._apply(commit, verify, genesis=False)

    def _apply(self, c, verify, genesis):
        add, remove = set(c["add"]), set(c["remove"])
        if add & remove:
            raise ProtocolError(400, "bad_request", "a device cannot be added and removed together")
        if add & self.members:
            raise ProtocolError(400, "bad_request", "added device is already a member")
        if not remove <= self.members:
            raise ProtocolError(400, "bad_request", "removed device is not a member")
        members = (self.members - remove) | add
        if len(members) > self.max_members:
            raise ProtocolError(403, "forbidden", "room is full")
        if "admins" in c:
            admins = set(c["admins"])
        else:
            admins = self.admins - remove
        if not admins or not admins <= members:
            raise ProtocolError(400, "bad_request", "admins must be a non-empty subset of the members")
        mhash = layouts.members_hash([hexd(m, 16) for m in members])
        if not layouts.ct_equal(mhash, b64d(c["members_hash"], 32)):
            raise ProtocolError(400, "bad_request", "members_hash does not match the resulting member set")
        if not verify(c["by"], frames.commit_signed_bytes(self.room, c), b64d(c["sig"], 64)):
            raise ProtocolError(401, "bad_sig", "commit signature invalid")
        return RoomState(self.room, c["epoch"], members, admins, self.max_members)


def make_commit(room, state, by, add=(), remove=(), admins=None, sign=None):
    """Client/test helper: build a commit dict on top of state. sign(bytes)
    returns the 64-byte Ed25519 signature of the admin `by`."""
    add = sorted(add)
    remove = sorted(remove)
    members = (set(state.members) - set(remove)) | set(add)
    c = {"prev": state.epoch, "epoch": state.epoch + 1, "by": by, "add": add, "remove": remove}
    if admins is not None:
        c["admins"] = sorted(admins)
    from .codec import b64e
    c["members_hash"] = b64e(layouts.members_hash([hexd(m, 16) for m in members]))
    c["sig"] = b64e(bytes(64))
    if sign is not None:
        c["sig"] = b64e(sign(frames.commit_signed_bytes(room, c)))
    return c
