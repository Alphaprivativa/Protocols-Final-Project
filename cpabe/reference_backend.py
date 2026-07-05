"""
A self-contained, runnable CP-ABE key-encapsulation backend.

Purpose.  So that the proof of concept executes anywhere the ``cryptography``
package is installed -- without the native OpenABE toolchain -- this backend
implements the :class:`~cpabe.kem.CpAbeKem` interface with genuine public-key
cryptography (X25519 + ECIES + AES-GCM) and LSSS-style secret sharing over the
policy tree.  Decryption succeeds *iff* the key's attributes satisfy the
policy, which is exactly the CP-ABE semantics the protocol needs.

How it works.
    * *Setup* fixes a (small) attribute universe and, from a master secret,
      deterministically derives one X25519 key pair per attribute.  ``mpk`` is
      the map ``attribute -> public key``; ``msk`` lets the authority re-derive
      any private key.
    * *KeyGen* hands the user the X25519 private keys for exactly its attributes.
    * *Encaps* draws a fresh secret, secret-shares it across the policy tree
      (AND = XOR n-of-n, OR = replicate, threshold = Shamir over GF(2^8)) and
      seals each leaf share to that attribute's public key with deterministic
      ECIES.  Because every random value is derived from ``coins`` via the PRG
      ``F``, the whole ciphertext is a *pure function of coins* -- which is
      what makes the re-encryption check of Algorithm 2 a byte-for-byte
      equality here.
    * *Decaps* walks the tree, opening the leaves it has keys for and
      recombining the shares.

Honest limitations (documented on purpose).
    Per-attribute keys are global rather than randomised per user, so this
    backend is a *small-universe, non-collusion-resistant* rendering of
    CP-ABE: two users could in principle pool their attribute keys.  Real
    collusion resistance is provided by the pairing-based CP-WATERS-KEM that
    the report actually specifies and that the OpenABE backend supplies.  For
    the properties this PoC demonstrates (single-holder anonymity/unlinkability,
    replay protection, unforgeability against a non-holder, and rejection of a
    malicious verifier) the reference backend is faithful.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat,
)

from . import policy as pol
from .kem import CpAbeKem
from .primitives import (
    BLOCK, F, kdf, xor, rand_bytes, shamir_split, shamir_combine,
)


# --------------------------------------------------------------------------- #
# Key material types                                                           #
# --------------------------------------------------------------------------- #
@dataclass
class MasterSecret:
    seed: bytes                       # derives every per-attribute private key
    universe: Tuple[str, ...]


@dataclass
class MasterPublic:
    attr_pk: Dict[str, bytes]         # attribute -> raw X25519 public key (32 B)


@dataclass
class UserKey:
    attr_sk: Dict[str, bytes]         # attribute -> raw X25519 private key (32 B)
    attributes: FrozenSet[str]


# --------------------------------------------------------------------------- #
# Ciphertext                                                                   #
# --------------------------------------------------------------------------- #
@dataclass
class RefCiphertext:
    """Ciphertext = the serialised, share-carrying policy tree.

    Equality is byte equality of the canonical encoding.  Because Encaps is
    deterministic in ``coins``, this makes ``Encaps(AP, R') == c`` (the
    re-encryption check of Algorithm 2) exact for this backend.
    """
    tree: dict

    def to_bytes(self) -> bytes:
        return json.dumps(self.tree, sort_keys=True, separators=(",", ":")).encode()

    def __eq__(self, other: object) -> bool:
        return isinstance(other, RefCiphertext) and self.to_bytes() == other.to_bytes()

    def __hash__(self) -> int:
        return hash(self.to_bytes())


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _unb64(s: str) -> bytes:
    return base64.b64decode(s.encode())


# --------------------------------------------------------------------------- #
# Deterministic ECIES to an attribute public key                               #
# --------------------------------------------------------------------------- #
def _ecies_seal(pk_raw: bytes, share: bytes, coins: bytes, ctx: bytes) -> dict:
    eph_priv = X25519PrivateKey.from_private_bytes(F(coins, info=b"ecies-eph" + ctx))
    eph_pub = eph_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    shared = eph_priv.exchange(X25519PublicKey.from_public_bytes(pk_raw))
    key = kdf(shared, info=b"ecies-kdf" + ctx)
    nonce = kdf(coins, info=b"ecies-nonce" + ctx, length=12)
    body = AESGCM(key).encrypt(nonce, share, eph_pub)
    return {"e": _b64(eph_pub), "n": _b64(nonce), "c": _b64(body)}


def _ecies_open(sk_raw: bytes, blob: dict, ctx: bytes) -> Optional[bytes]:
    try:
        eph_pub = _unb64(blob["e"])
        nonce = _unb64(blob["n"])
        body = _unb64(blob["c"])
        sk = X25519PrivateKey.from_private_bytes(sk_raw)
        shared = sk.exchange(X25519PublicKey.from_public_bytes(eph_pub))
        key = kdf(shared, info=b"ecies-kdf" + ctx)
        return AESGCM(key).decrypt(nonce, body, eph_pub)
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# Recursive secret sharing over the policy tree                                #
# --------------------------------------------------------------------------- #
def _share(node: pol.Policy, secret: bytes, mpk: MasterPublic,
           coins: bytes, path: bytes) -> dict:
    if isinstance(node, pol.Leaf):
        pk = mpk.attr_pk.get(node.attr)
        if pk is None:
            raise KeyError(f"attribute {node.attr!r} not in KEM universe")
        return {"t": "leaf", "a": node.attr,
                "s": _ecies_seal(pk, secret, coins, path)}

    if isinstance(node, pol.And):
        # n-of-n XOR split: shares XOR back to `secret`.
        n = len(node.children)
        parts: List[bytes] = []
        acc = secret
        for i in range(n - 1):
            si = F(coins, info=b"and-share" + path + bytes([i]))
            parts.append(si)
            acc = xor(acc, si)
        parts.append(acc)
        return {"t": "and",
                "c": [_share(child, parts[i], mpk, coins, path + b"/" + bytes([i]))
                      for i, child in enumerate(node.children)]}

    if isinstance(node, pol.Or):
        # 1-of-n: every child can reconstruct the same secret.
        return {"t": "or",
                "c": [_share(child, secret, mpk, coins, path + b"/" + bytes([i]))
                      for i, child in enumerate(node.children)]}

    if isinstance(node, pol.Threshold):
        shares = shamir_split(secret, node.k, len(node.children),
                              F(coins, info=b"thr" + path))
        out = []
        for i, (child, (x, sh)) in enumerate(zip(node.children, shares)):
            out.append({"x": x,
                        "node": _share(child, sh, mpk, coins,
                                       path + b"/" + bytes([i]))})
        return {"t": "thr", "k": node.k, "c": out}

    raise TypeError(f"unknown policy node {type(node)!r}")


def _recover(node: dict, uk: UserKey, path: bytes) -> Optional[bytes]:
    t = node["t"]
    if t == "leaf":
        sk = uk.attr_sk.get(node["a"])
        if sk is None:
            return None
        return _ecies_open(sk, node["s"], path)

    if t == "and":
        acc = bytes(BLOCK)
        for i, child in enumerate(node["c"]):
            part = _recover(child, uk, path + b"/" + bytes([i]))
            if part is None:
                return None
            acc = xor(acc, part)
        return acc

    if t == "or":
        for i, child in enumerate(node["c"]):
            got = _recover(child, uk, path + b"/" + bytes([i]))
            if got is not None:
                return got
        return None

    if t == "thr":
        collected: List[Tuple[int, bytes]] = []
        for i, entry in enumerate(node["c"]):
            got = _recover(entry["node"], uk, path + b"/" + bytes([i]))
            if got is not None:
                collected.append((entry["x"], got))
        if len(collected) >= node["k"]:
            return shamir_combine(collected[: node["k"]])
        return None

    raise TypeError(f"unknown ciphertext node type {t!r}")


# --------------------------------------------------------------------------- #
# The backend                                                                  #
# --------------------------------------------------------------------------- #
def _default_universe() -> Tuple[str, ...]:
    """A small, bounded attribute universe: roles, formulary drugs and a
    horizon of monthly validity slots.  Only attributes that can appear in a
    dispensing policy need to be here (prescription ids never do)."""
    attrs = ["role:patient", "role:pharmacy"]
    attrs += [f"drug:{d}" for d in pol.formulary_drugs()]
    for year in range(2024, 2029):            # 2024-01 .. 2028-12
        for month in range(1, 13):
            attrs.append(f"valid:{year:04d}-{month:02d}")
    return tuple(sorted(set(attrs)))


class ReferenceKEM(CpAbeKem):
    name = "reference (X25519/ECIES small-universe KEM)"

    def __init__(self, universe: Optional[Tuple[str, ...]] = None):
        self._universe = universe or _default_universe()

    # -- Setup --------------------------------------------------------------- #
    def setup(self) -> Tuple[MasterPublic, MasterSecret]:
        seed = rand_bytes(BLOCK)
        attr_pk: Dict[str, bytes] = {}
        for attr in self._universe:
            sk_raw = F(seed, info=b"attr-sk:" + attr.encode())
            pub = X25519PrivateKey.from_private_bytes(sk_raw).public_key()
            attr_pk[attr] = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return MasterPublic(attr_pk=attr_pk), MasterSecret(seed=seed,
                                                           universe=self._universe)

    # -- KeyGen -------------------------------------------------------------- #
    def keygen(self, msk: MasterSecret, mpk: MasterPublic,
               attributes: FrozenSet[str]) -> UserKey:
        attr_sk: Dict[str, bytes] = {}
        for attr in attributes:
            if attr in msk.universe:          # ignore non-policy attrs (e.g. presc:*)
                attr_sk[attr] = F(msk.seed, info=b"attr-sk:" + attr.encode())
        return UserKey(attr_sk=attr_sk, attributes=frozenset(attributes))

    # -- Encaps -------------------------------------------------------------- #
    def encaps(self, mpk: MasterPublic, policy: pol.Policy,
               coins: bytes) -> RefCiphertext:
        if len(coins) != BLOCK:
            coins = F(coins, info=b"coins-normalise")   # be robust to length
        tree = _share(policy, coins, mpk, coins, b"root")
        return RefCiphertext(tree=tree)

    # -- Decaps -------------------------------------------------------------- #
    def decaps(self, sk: UserKey, ct: RefCiphertext,
               policy: pol.Policy) -> Optional[bytes]:
        # Returns the encapsulated randomness (the shared secret) or None.
        return _recover(ct.tree, sk, b"root")

    # -- (de)serialisation --------------------------------------------------- #
    def ciphertext_from_bytes(self, raw: bytes) -> RefCiphertext:
        return RefCiphertext(tree=json.loads(raw.decode()))
