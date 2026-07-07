"""
A small extensible backend registry, implemented for generality of the backend 
system (when we didn't know if OpenABE would work on our machine).
Initialization of the OpenABE backend then added to the backend system.

We expose OpenABE directly as a public-key encryption primitive:
    Setup(lambda)            -> (mpk, msk)
    KeyGen_{msk,mpk}(S)      -> sk
    Encrypt(mpk, AP, m)      -> ct
    Decrypt(sk, ct)          -> m  or  None   (m iff attrs(sk) |= AP)

The protocol code stays backend-agnostic through :class:`AbePke`, and new
backends can be plugged in for future development via :func:`register_backend`.
The only backend registered so far is Zeutro's OpenABE (CP-WATERS, ``-s CP``).
"""

from __future__ import annotations

import abc
import shutil
from collections import OrderedDict
from dataclasses import dataclass
from typing import Callable, FrozenSet, List, Optional, Tuple


class AbePke(abc.ABC):
    """Attribute-based public-key encryption (CP-ABE), CCA-secure.

    A ciphertext is opaque ``bytes`` (whatever the backend produces); the policy
    travels inside it, so :meth:`decrypt` needs only the key and the ciphertext.
    """

    name: str = "abstract"

    @abc.abstractmethod
    def setup(self) -> Tuple[object, object]:
        """Return ``(mpk, msk)``  (report: ``msk, mpk <- Setup(lambda)``)."""

    @abc.abstractmethod
    def keygen(self, msk: object, mpk: object, attributes: FrozenSet[str]) -> object:
        """Issue a user secret key for ``attributes``
        (report: ``sk <- KeyGen_{msk,mpk}(S)``)."""

    @abc.abstractmethod
    def encrypt(self, mpk: object, policy, plaintext: bytes) -> bytes:
        """CCA-secure ABE-encrypt ``plaintext`` under ``policy`` -> ciphertext."""

    @abc.abstractmethod
    def decrypt(self, sk: object, ciphertext: bytes) -> Optional[bytes]:
        """Return the plaintext iff the key's attributes satisfy the policy
        embedded in ``ciphertext``; otherwise return ``None``."""


# --------------------------------------------------------------------------- #
# Backend registry (extensible: register future backends here)                 #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class BackendSpec:
    """Describes one CP-ABE backend.

    * ``factory``   builds a fresh :class:`AbePke` instance (imported lazily so
                    an unused backend never pulls in its dependencies).
    * ``available`` returns True iff this backend can actually run right now.
    * ``hint``      shown when the backend is selected but not available.
    """
    name: str
    factory: Callable[[], "AbePke"]
    available: Callable[[], bool]
    description: str = ""
    hint: str = ""


_BACKENDS: "OrderedDict[str, BackendSpec]" = OrderedDict()   # order == preference


def register_backend(spec: BackendSpec) -> None:
    """Register a CP-ABE backend so it can be picked via :func:`select_backend`.

    Adding a future backend is just: implement :class:`AbePke`, then ::

        from cpabe.pke import BackendSpec, register_backend
        register_backend(BackendSpec(
            name="mybackend",
            factory=lambda: MyAbePke(),
            available=lambda: True,
            description="my experimental CP-ABE backend",
        ))
    """
    _BACKENDS[spec.name] = spec


def registered_backends() -> List[str]:
    """Names of all registered backends, in preference order."""
    return list(_BACKENDS.keys())


def available_backends() -> List[str]:
    """Names of the registered backends that can run right now."""
    return [n for n, s in _BACKENDS.items() if s.available()]


# --------------------------------------------------------------------------- #
# OpenABE availability + registration                                          #
# --------------------------------------------------------------------------- #
def openabe_available() -> bool:
    """True iff the OpenABE command-line tools are on the PATH."""
    return all(shutil.which(t) for t in ("oabe_setup", "oabe_keygen",
                                         "oabe_enc", "oabe_dec"))


def _make_openabe() -> "AbePke":
    from . import openabe_backend
    return openabe_backend.OpenABEPke()


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
    description="Zeutro OpenABE CLI (CP-ABE / CP-WATERS, scheme CP) -- the real primitive",
    hint=_OPENABE_HINT,
))


# --------------------------------------------------------------------------- #
# Selection                                                                    #
# --------------------------------------------------------------------------- #
def select_backend(prefer: Optional[str] = None) -> AbePke:
    """Return a CP-ABE PKE instance.

    ``prefer``:
        * ``None`` -- auto-select the first *available* registered backend.
        * a name  -- use that specific backend; raises if unknown or unavailable.
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

    hints = "\n".join(s.hint for s in _BACKENDS.values() if s.hint)
    raise RuntimeError(
        "No CP-ABE backend is available.\n"
        f"Registered backends: {registered_backends()}.\n" + hints
    )