"""
The CP-ABE key-encapsulation interface the protocol is built on.

The report (Section 3.1) relies on an encapsulation mechanism

    Pi = (Setup, KeyGen, Encaps, Decaps)

"like the CP-WATERS-KEM", and then wraps it in the Fujisaki-Okamoto-style
transform of Algorithms 1 and 2.  This module defines that interface once and
lets two interchangeable backends implement it:

    * ``reference_backend.ReferenceKEM`` -- a self-contained, deterministic
      small-universe attribute KEM built from X25519 / ECIES / AES-GCM, so
      the proof of concept runs anywhere ``cryptography`` is installed.

    * ``openabe_backend.OpenABEKEM``     -- a thin adapter over Zeutro's
      OpenABE command-line tools (the CP-WATERS scheme, ``-s CP``), i.e. the
      "Multiplatform OpenABE Wrapper" primitive the proposal points at, used
      here directly through OpenABE's own CLI.

Both must satisfy the KEM contract:

    Encaps(mpk, AP, coins) -> ct          -- a *pure function of coins*
    Decaps(sk, ct, AP)     -> coins or None  -- the encapsulated randomness,
                                               returned iff attrs(sk) |= AP

i.e. the KEM encapsulates the randomness itself; the KEM key used in
Algorithm 1 is then ``k = kdf(coins)`` (a deterministic function of the
encapsulated randomness, as in ``(k, c) <- Encaps(AP, R')``).

The re-encryption check of Algorithm 2 is realised in two equivalent ways
depending on the backend (see :data:`CpAbeKem.deterministic_ciphertext`):

    * deterministic ciphertext (reference)  ->  recompute ``Encaps(AP, R')``
      and check it equals ``c`` *byte for byte*  (the report's literal check);
    * randomized ciphertext (OpenABE / CP-WATERS)  ->  check that the
      *decapsulated* randomness equals the recomputed ``R'`` (equivalent by
      KEM correctness, and it never puts the secret randomness on the wire).
"""

from __future__ import annotations

import abc
import shutil
from typing import FrozenSet, Optional, Protocol, Tuple


class Ciphertext(Protocol):
    """A KEM ciphertext.  Must be comparable (for the re-encryption check)
    and serialisable (so it can travel over the wire in the handshake)."""

    def __eq__(self, other: object) -> bool: ...

    def to_bytes(self) -> bytes: ...


# Here ABC is due to abstract methods which we want to impose to be modified in children classes
class CpAbeKem(abc.ABC):
    """Abstract CP-ABE key-encapsulation mechanism."""

    name: str = "abstract"

    #: Whether ``encaps`` produces byte-identical ciphertexts for identical
    #: coins.  True lets Algorithm 2 use the literal ``Encaps(AP, R') == c``
    #: check; False makes it use decapsulated-randomness equality instead.
    deterministic_ciphertext: bool = True

    @abc.abstractmethod
    def setup(self) -> Tuple[object, object]:
        """Return ``(mpk, msk)``  (report: ``msk, mpk <- Setup(lambda)``)."""

    @abc.abstractmethod
    def keygen(self, msk: object, mpk: object, attributes: FrozenSet[str]) -> object:
        """Issue a user secret key for ``attributes``
        (report: ``sk <- KeyGen_{msk,mpk}(S)``)."""

    @abc.abstractmethod
    def encaps(self, mpk: object, policy, coins: bytes) -> Ciphertext:
        """Encapsulate ``coins`` under ``policy``.  MUST be a deterministic
        function of ``coins`` (report: ``c`` of ``(k, c) <- Encaps(AP, R')``)."""

    @abc.abstractmethod
    def decaps(self, sk: object, ct: Ciphertext, policy) -> Optional[bytes]:
        """Recover the encapsulated randomness iff the key's attributes satisfy
        ``policy``; else return ``None``  (report: ``Decaps(sk, c, AP)``)."""

    @abc.abstractmethod
    def ciphertext_from_bytes(self, raw: bytes) -> Ciphertext:
        """Rebuild a ciphertext object from its wire encoding."""


# --------------------------------------------------------------------------- #
# Backend selection                                                            #
# --------------------------------------------------------------------------- #
def openabe_available() -> bool:
    """True iff the OpenABE command-line tools are on the PATH."""
    return all(shutil.which(t) for t in ("oabe_setup", "oabe_keygen",
                                         "oabe_enc", "oabe_dec"))


def select_backend(prefer: Optional[str] = None) -> CpAbeKem:
    """Return a KEM instance.

    ``prefer`` may be ``"openabe"`` or ``"reference"``.  With no preference,
    the real OpenABE backend is used when its CLI is installed, otherwise the
    self-contained reference backend is used so the demo still runs.
    """
    # TODO: remove reference_backend
    from . import reference_backend  # local import to avoid cycles

    if prefer == "reference":
        return reference_backend.ReferenceKEM()

    if prefer == "openabe" or (prefer is None and openabe_available()):
        from . import openabe_backend
        return openabe_backend.OpenABEKEM()

    return reference_backend.ReferenceKEM()
