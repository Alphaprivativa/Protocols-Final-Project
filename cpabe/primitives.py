"""
Low-level cryptographic primitives used across the proof of concept.

These map directly onto the symbols used in the report:

    * ``H`` -- a collision-resistant hash modelled as a random oracle
              (report, Section 3.1: "Let H be a collision-resistant hash
              function (modelled as a random oracle)").
    * ``F`` -- a pseudo-random generator (report, Section 3.1: "F a
              pseudo-random generator").  It is also the one-way function
              used for the nullifier ratchet ``S_{i+1} = F(S_i)`` of F2/S7.
    * ``xor`` -- the bitwise XOR used in Algorithms 1 and 2
              (``c' <- H(k) (+) R`` and ``R <- c' (+) H(k)``).

Everything is built on SHA-256 / HKDF-SHA256 from the ``cryptography``
package so that the reference backend performs genuine cryptographic
operations rather than book-keeping.
"""

from __future__ import annotations

import os
import struct
from typing import Iterable, List, Tuple

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


# TODO: This are for internal backend
# --------------------------------------------------------------------------- #
# GF(2^8) Shamir secret sharing (for k-of-n / threshold policy nodes)          #
# --------------------------------------------------------------------------- #
#
# AND nodes use an n-of-n XOR split and OR nodes replicate the secret, so
# Shamir is only needed for genuine threshold ("k of n") policy gates.  We
# implement it over the AES field GF(2^8) with modulus 0x11B.
#
_EXP = [0] * 512
_LOG = [0] * 256


def _xtime(a: int) -> int:
    """Multiply by 2 in GF(2^8) with reduction modulo 0x11B."""
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _init_gf() -> None:
    # 0x03 is a primitive element (generator) of GF(2^8)/0x11B; 0x02 is not,
    # so the exp/log tables must be built by repeated multiplication by 3.
    x = 1
    for i in range(255):
        _EXP[i] = x
        _LOG[x] = i
        x = _xtime(x) ^ x            # x <- x * 3
    for i in range(255, 512):
        _EXP[i] = _EXP[i - 255]


_init_gf()


def _gmul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _gdiv(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError
    if a == 0:
        return 0
    return _EXP[(_LOG[a] - _LOG[b]) % 255]


def shamir_split(secret: bytes, k: int, n: int, coins: bytes) -> List[Tuple[int, bytes]]:
    """Split ``secret`` into ``n`` shares such that any ``k`` reconstruct it.

    The polynomial coefficients are derived deterministically from ``coins``
    so that encapsulation is a pure function of its randomness (required for
    the re-encryption check of Algorithm 2 in the reference backend).
    Share x-coordinates are 1..n.
    """
    if not (1 <= k <= n <= 255):
        raise ValueError("require 1 <= k <= n <= 255")
    # Deterministic coefficient stream for the (k-1) non-constant coefficients.
    coeff_stream = F(coins, length=len(secret) * (k - 1) if k > 1 else 0,
                     info=b"shamir-coeffs")
    shares: List[Tuple[int, bytes]] = []
    for x in range(1, n + 1):
        out = bytearray(len(secret))
        for pos in range(len(secret)):
            acc = secret[pos]  # constant term = secret byte
            for j in range(1, k):
                coeff = coeff_stream[(j - 1) * len(secret) + pos]
                # acc += coeff * x^j  (Horner-free, explicit power)
                xp = 1
                for _ in range(j):
                    xp = _gmul(xp, x)
                acc ^= _gmul(coeff, xp)
            out[pos] = acc
        shares.append((x, bytes(out)))
    return shares


def shamir_combine(shares: List[Tuple[int, bytes]]) -> bytes:
    """Lagrange-interpolate the shares at x = 0 to recover the secret."""
    if not shares:
        raise ValueError("no shares")
    length = len(shares[0][1])
    secret = bytearray(length)
    xs = [s[0] for s in shares]
    for pos in range(length):
        acc = 0
        for xi, yi in shares:
            num, den = 1, 1
            for xj in xs:
                if xj == xi:
                    continue
                num = _gmul(num, xj)          # (0 - xj) == xj in GF(2^8)
                den = _gmul(den, xi ^ xj)     # (xi - xj) == xi ^ xj
            lag = _gdiv(num, den)
            acc ^= _gmul(yi[pos], lag)
        secret[pos] = acc
    return bytes(secret)
