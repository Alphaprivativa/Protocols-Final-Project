"""
The CCA-secure encryption / decryption of a secret R under an access policy AP.

These are Algorithms 1 and 2 of the report -- the Fujisaki-Okamoto-style
transform of ETSI TS 103 964 clause A.3 that wraps the CP-WATERS-KEM -- built
on the :class:`~cpabe.kem.CpAbeKem` interface.

    Algorithm 1  EncABE_mpk(AP, R):
        1: u  <- H(R || AP)
        2: R' <- F(u)                      # R' fixes the encapsulation randomness
        3: (k, c) <- Encaps_mpk(AP, R')    # here c = Encaps(AP, R'), k = kdf(R')
        4: c' <- H(k) (+) R
        5: return (c, c')

    Algorithm 2  DecABE_sk(c, c', AP):
        1: k  <- Decaps_sk(c, AP)          # recover R', then k = kdf(R')
        2: R  <- c' (+) H(k)
        3: u  <- H(R || AP)
        4: R' <- F(u)
        5: if Encaps_mpk(AP, R') != c then return _|_     # re-encryption check
        6: return R

The re-encryption check on line 5 is, as the report stresses, "exactly what
gives anonymity for the prover: a Prover accepts a challenge only if it could
itself have produced the same ciphertext from the recovered randomness, so a
malicious Verifier cannot craft a dishonest ciphertext to extract information
about the key."

Our KEM encapsulates the randomness R' itself, so line 5 is realised as a
byte-for-byte ciphertext comparison when the backend is deterministic (the
reference backend) and, equivalently, as decapsulated-randomness equality when
it is randomized (the OpenABE / CP-WATERS backend).
"""

from __future__ import annotations

from typing import Optional, Tuple

from .kem import Ciphertext, CpAbeKem
from .policy import Policy
from .primitives import H, F, xor, kdf


def _ap_label(ap: Policy) -> bytes:
    """Bytes standing for AP inside the hash: the canonical policy string binds
    the whole access structure into ``u = H(R || AP)``."""
    return ap.canonical().encode()


def _kem_key(coins: bytes) -> bytes:
    """``k`` from ``(k, c) <- Encaps(AP, R')`` -- a deterministic function of
    the encapsulated randomness ``R' = coins``."""
    return kdf(coins, info=b"kem-key")


def enc_abe(kem: CpAbeKem, mpk: object, ap: Policy, R: bytes) -> Tuple[Ciphertext, bytes]:
    """Algorithm 1 -- EncABE_mpk(AP, R) -> (c, c')."""
    u = H(R, _ap_label(ap))                 # 1
    Rprime = F(u)                           # 2
    c = kem.encaps(mpk, ap, Rprime)         # 3a: c <- Encaps(AP, R')
    k = _kem_key(Rprime)                    # 3b: k <- kdf(R')
    cprime = xor(H(k), R)                   # 4
    return c, cprime                        # 5


def dec_abe(kem: CpAbeKem, mpk: object, sk: object, ap: Policy,
            c: Ciphertext, cprime: bytes) -> Optional[bytes]:
    """Algorithm 2 -- DecABE_sk(c, c', AP) -> R or None.

    Returns ``None`` (the report's ``_|_``) when either the key's attributes do
    not satisfy the policy *or* the re-encryption check fails (the verifier did
    not honestly derive its randomness from R).
    """
    coins = kem.decaps(sk, c, ap)           # 1a: recover R'
    if coins is None:
        return None                         #     attributes do not satisfy AP
    k = _kem_key(coins)                     # 1b: k <- kdf(R')
    R = xor(cprime, H(k))                   # 2
    u = H(R, _ap_label(ap))                 # 3
    Rprime = F(u)                           # 4

    # 5: re-encryption check -----------------------------------------------
    if kem.deterministic_ciphertext:
        if kem.encaps(mpk, ap, Rprime) != c:      # literal Encaps(AP, R') == c
            return None
    else:
        if coins != Rprime:                        # equivalent seed-level check
            return None
    return R                                # 6
