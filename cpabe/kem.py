"""
The CP-ABE key-encapsulation interface the protocol is built on.

The report (Section 3.1) relies on an encapsulation mechanism

    Pi = (Setup, KeyGen, Encaps, Decaps)

"like the CP-WATERS-KEM", wrapped in the Fujisaki-Okamoto-style transform of
Algorithms 1 and 2.  This module defines that interface plus a small **backend
registry**, so the protocol code stays backend-agnostic and new backends can be
plugged in for future development (see :func:`register_backend`).

The only backend registered today is the real thing: Zeutro's OpenABE, driven
through its command-line tools (the CP-WATERS scheme, ``-s CP``) -- the
"Multiplatform OpenABE Wrapper" primitive the proposal points at, used here
directly through OpenABE's own CLI.

KEM contract:

    Encaps(mpk, AP, coins) -> ct          -- encapsulates the randomness ``coins``
    Decaps(sk, ct, AP)     -> coins or None  -- returns it iff attrs(sk) |= AP

The KEM key used in Algorithm 1 is ``k = kdf(coins)``.  OpenABE encryption is
randomized, so ``deterministic_ciphertext`` is False and Algorithm 2's
re-encryption check compares the *decapsulated* randomness against the
recomputed ``R'`` (equivalent by KEM correctness, and it never puts the secret
randomness on the wire -- see ``fo.py``).
"""

from __future__ import annotations

import abc
import shutil
from collections import OrderedDict
from dataclasses import dataclass
from typing import Callable, Dict, FrozenSet, List, Optional, Protocol, Tuple


class Ciphertext(Protocol):
    """A KEM ciphertext: serialisable (to travel over the wire) and comparable."""

    def __eq__(self, other: object) -> bool: ...

    def to_bytes(self) -> bytes: ...


class CpAbeKem(abc.ABC):
    """Abstract CP-ABE key-encapsulation mechanism."""

    name: str = "abstract"

    #: Whether ``encaps`` is byte-identical for identical coins.  OpenABE's is
    #: randomized (False), so Algorithm 2 uses decapsulated-randomness equality.
    deterministic_ciphertext: bool = False

    @abc.abstractmethod
    def setup(self) -> Tuple[object, object]:
        """Return ``(mpk, msk)``  (report: ``msk, mpk <- Setup(lambda)``)."""

    @abc.abstractmethod
    def keygen(self, msk: object, mpk: object, attributes: FrozenSet[str]) -> object:
        """Issue a user secret key for ``attributes``
        (report: ``sk <- KeyGen_{msk,mpk}(S)``)."""

    @abc.abstractmethod
    def encaps(self, mpk: object, policy, coins: bytes) -> Ciphertext:
        """Encapsulate ``coins`` under ``policy``
        (report: ``c`` of ``(k, c) <- Encaps(AP, R')``)."""

    @abc.abstractmethod
    def decaps(self, sk: object, ct: Ciphertext, policy) -> Optional[bytes]:
        """Recover the encapsulated randomness iff the key's attributes satisfy
        ``policy``; else return ``None``  (report: ``Decaps(sk, c, AP)``)."""

    @abc.abstractmethod
    def ciphertext_from_bytes(self, raw: bytes) -> Ciphertext:
        """Rebuild a ciphertext object from its wire encoding."""


# --------------------------------------------------------------------------- #
# Backend registry (extensible: register future backends here)                 #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class BackendSpec:
    """Describes one CP-ABE backend.

    * ``factory``   builds a fresh :class:`CpAbeKem` instance (imported lazily so
                    an unused backend never pulls in its dependencies).
    * ``available`` returns True iff this backend can actually run right now
                    (e.g. its native tools are installed).
    * ``hint``      shown to the user when the backend is selected but not
                    available (how to make it available).
    """
    name: str
    factory: Callable[[], "CpAbeKem"]
    available: Callable[[], bool]
    description: str = ""
    hint: str = ""


# Insertion order == auto-selection preference.
_BACKENDS: "OrderedDict[str, BackendSpec]" = OrderedDict()


def register_backend(spec: BackendSpec) -> None:
    """Register a CP-ABE backend so it can be picked via :func:`select_backend`.

    Adding a future backend is just:  implement :class:`CpAbeKem`, then ::

        from cpabe.kem import BackendSpec, register_backend
        register_backend(BackendSpec(
            name="mybackend",
            factory=lambda: MyKem(),
            available=lambda: True,
            description="my experimental CP-ABE backend",
        ))

    Backends are tried in registration order during auto-selection.
    """
    _BACKENDS[spec.name] = spec


def registered_backends() -> List[str]:
    """Names of all registered backends, in preference order."""
    return list(_BACKENDS.keys())


def available_backends() -> List[str]:
    """Names of the registered backends that can run right now."""
    return [n for n, s in _BACKENDS.items() if s.available()]


# --------------------------------------------------------------------------- #
# OpenABE availability + backend registration                                  #
# --------------------------------------------------------------------------- #
def openabe_available() -> bool:
    """True iff the OpenABE command-line tools are on the PATH."""
    return all(shutil.which(t) for t in ("oabe_setup", "oabe_keygen",
                                         "oabe_enc", "oabe_dec"))


def _make_openabe() -> "CpAbeKem":
    from . import openabe_backend
    return openabe_backend.OpenABEKEM()


_OPENABE_HINT = (
    "Build OpenABE first:\n"
    "  ./openabe/build_openabe.sh   (native)   or\n"
    "  docker build -f openabe/Dockerfile -t eprescription-poc .  (container)\n"
    "then run inside that environment (e.g. `source run_env.sh`).\n"
    "Or, to run without OpenABE, put the bundled mocks on PATH:\n"
    "  PATH=\"$PWD/openabe/mock_tools:$PATH\" python3 run_demo.py"
)

register_backend(BackendSpec(
    name="openabe",
    factory=_make_openabe,
    available=openabe_available,
    description="Zeutro OpenABE CLI (CP-WATERS-KEM, scheme CP) -- the real primitive",
    hint=_OPENABE_HINT,
))


# --------------------------------------------------------------------------- #
# Selection                                                                    #
# --------------------------------------------------------------------------- #
def select_backend(prefer: Optional[str] = None) -> CpAbeKem:
    """Return a CP-ABE KEM instance.

    ``prefer``:
        * ``None`` -- auto-select the first *available* registered backend
          (in registration/preference order).
        * a name  -- use that specific backend; raises if it is unknown or not
          currently available.
    """
    if prefer is not None:
        spec = _BACKENDS.get(prefer)
        if spec is None:
            raise ValueError(
                f"unknown CP-ABE backend {prefer!r}; "
                f"registered backends: {registered_backends()}"
            )
        if not spec.available():
            raise RuntimeError(
                f"CP-ABE backend {prefer!r} is registered but not available.\n"
                + (spec.hint or "")
            )
        return spec.factory()

    # Auto: first available backend in preference order.
    for spec in _BACKENDS.values():
        if spec.available():
            return spec.factory()

    # Nothing available -- report how to enable the preferred (first) backend.
    hints = "\n".join(s.hint for s in _BACKENDS.values() if s.hint)
    raise RuntimeError(
        "No CP-ABE backend is available.\n"
        f"Registered backends: {registered_backends()}.\n" + hints
    )
