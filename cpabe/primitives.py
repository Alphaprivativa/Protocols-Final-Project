"""
Low-level cryptographic primitives used across the proof of concept.

These map directly onto the symbols used in the report:

    * ``H`` -- a collision-resistant hash modelled as a random oracle
              (report, Section 3.1: "Let H be a collision-resistant hash
              function (modelled as a random oracle)").
    * ``F`` -- a pseudo-random generator (report, Section 3.1: "F a
              pseudo-random generator").  It is also the one-way function
              used for the nullifier ratchet ``S_{i+1} = F(S_i)`` of F2/S7.
    * ``kdf`` -- an HKDF key-derivation wrapper (used to derive the KEM key
              ``k = kdf(R')`` in the Fujisaki-Okamoto layer).
    * ``xor`` -- the bitwise XOR used in Algorithms 1 and 2
              (``c' <- H(k) (+) R`` and ``R <- c' (+) H(k)``).

Everything is built on SHA-256 / HKDF-SHA256 from the ``cryptography``
package.  The CP-ABE itself is provided by OpenABE (CP-WATERS-KEM); these
primitives implement only the surrounding FO transform, nullifier ratchet and
signatures glue.
"""

from __future__ import annotations

import os
import struct
from typing import Iterable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand, HKDF

# Length of every digest / secret block that we XOR together.  The KEM key,
# the challenge secret ``R`` and ``H(k)`` are all 32 bytes so the XOR in
# Algorithms 1-2 is well defined.
BLOCK = 32


# --------------------------------------------------------------------------- #
# Deterministic, unambiguous serialisation                                     #
# --------------------------------------------------------------------------- #
def _encode(parts: Iterable[bytes]) -> bytes:
    """Length-prefix every field so that H(a, b) != H(a || b) accidents
    cannot happen.  Each part is prefixed with its 4-byte big-endian length."""
    out = bytearray()
    for p in parts:
        if not isinstance(p, (bytes, bytearray)):
            raise TypeError(f"expected bytes, got {type(p)!r}")
        out += struct.pack(">I", len(p))
        out += p
    return bytes(out)


# --------------------------------------------------------------------------- #
# H : random oracle                                                            #
# --------------------------------------------------------------------------- #
def H(*parts: bytes) -> bytes:
    """Collision-resistant hash (random oracle).  Returns 32 bytes."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(_encode(parts))
    return digest.finalize()


# --------------------------------------------------------------------------- #
# F : pseudo-random generator / one-way function                              #
# --------------------------------------------------------------------------- #
def F(seed: bytes, *, length: int = BLOCK, info: bytes = b"F-PRG") -> bytes:
    """Pseudo-random generator.  Expands ``seed`` deterministically.

    Used both as the PRG that "fixes the encapsulation randomness"
    (``R' <- F(u)`` in Algorithm 1) and as the one-way ratchet function
    for nullifiers (``S_{i+1} = F(S_i)``, Section 3.3 / S7).
    """
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info).derive(seed)


def kdf(key_material: bytes, *, info: bytes, length: int = BLOCK,
        salt: bytes | None = None) -> bytes:
    """A general key-derivation wrapper (HKDF-extract-then-expand)."""
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt,
                info=info).derive(key_material)


# --------------------------------------------------------------------------- #
# XOR                                                                          #
# --------------------------------------------------------------------------- #
def xor(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor operands must have equal length")
    return bytes(x ^ y for x, y in zip(a, b))


def rand_bytes(n: int = BLOCK) -> bytes:
    return os.urandom(n)
