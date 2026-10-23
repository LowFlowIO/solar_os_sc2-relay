"""Signature checks and the relay key (libsodium through PyNaCl).

Verification uses crypto_sign_open, exactly like protocol/sc2/tools/sc2ref.py,
so the relay accepts and rejects the same signatures as the reference and
the C core (checked against the ed25519_verify vectors in the tests).

SPDX-License-Identifier: MIT
"""

import os

import nacl.bindings as nb
import nacl.exceptions


def verify(pk, msg, sig):
    if len(pk) != 32 or len(sig) != 64:
        return False
    try:
        nb.crypto_sign_open(bytes(sig) + bytes(msg), bytes(pk))
        return True
    except (nacl.exceptions.BadSignatureError, nacl.exceptions.ValueError, nacl.exceptions.CryptoError,
            nacl.exceptions.TypeError):
        return False


def random_bytes(n):
    return os.urandom(n)


class SigningKey:
    """An Ed25519 key from a 32-byte seed."""

    def __init__(self, seed):
        if len(seed) != 32:
            raise ValueError("Ed25519 seed must be 32 bytes")
        self._seed = bytes(seed)
        self.public, self._sk = nb.crypto_sign_seed_keypair(self._seed)

    def sign(self, msg):
        return nb.crypto_sign(bytes(msg), self._sk)[:64]

    @classmethod
    def load_or_create(cls, path):
        """Load the relay seed from path, creating it (mode 0600) on first run."""
        try:
            with open(path, "rb") as f:
                seed = f.read()
            if len(seed) != 32:
                raise ValueError("relay key file " + path + " is corrupt (expected 32 bytes)")
            return cls(seed), False
        except FileNotFoundError:
            pass
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        seed = os.urandom(32)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, seed)
            os.fsync(fd)
        finally:
            os.close(fd)
        return cls(seed), True
