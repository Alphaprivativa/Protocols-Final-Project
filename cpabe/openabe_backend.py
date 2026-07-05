"""
A CP-ABE backend that drives Zeutro's OpenABE through its command-line tools.

This is the primitive the proposal actually points at -- the "Multiplatform
OpenABE Wrapper [2]" -- used here *directly* through OpenABE's own CLI, which
is the simplest way to obtain the real CP-WATERS-KEM without a JNI / Kotlin
Native build.  It is selected automatically by :func:`cpabe.kem.select_backend`
whenever the ``oabe_*`` tools are on the PATH (see ``openabe/build_openabe.sh``
and ``openabe/Dockerfile`` for how to obtain them).

Mapping to OpenABE's tools (scheme ``-s CP`` = CP-ABE / CP-WATERS), following
OpenABE's documented CLI, whose default key filenames are ``mpk.cpabe`` /
``msk.cpabe`` (written into the working directory):

    Setup   ->  oabe_setup  -s CP                          (writes mpk.cpabe, msk.cpabe)
    KeyGen  ->  oabe_keygen -s CP -i "a|b|c" -o <key>      (writes <key>.key)
    Encaps  ->  oabe_enc    -s CP -e "<policy>" -i R'.bin -o ct
    Decaps  ->  oabe_dec    -s CP -k <key>.key -i ct -o R'.out

IMPORTANT design note.  ``oabe_setup`` can drop *several* files in the working
directory (not only ``mpk`` / ``msk`` -- e.g. scheme parameter files), and the
other tools expect to find them there.  We therefore run **every** OpenABE
operation inside a single, persistent working directory owned by this KEM
instance, created once at ``setup``, rather than shuttling only ``mpk`` / ``msk``
between throwaway temp dirs.  Each call uses unique filenames so repeated
keygen / encaps / decaps operations never clobber one another.  In this
single-process PoC the same KEM object is shared by all principals, so one
working directory is exactly right.

Because OpenABE encryption is randomized, ciphertexts are *not* byte-stable, so
``deterministic_ciphertext`` is False and the FO re-encryption check of
Algorithm 2 uses decapsulated-randomness equality (see ``fo.py``), which is
equivalent by KEM correctness and never places the secret randomness on the
wire.  The randomness ``R'`` is exactly 32 bytes and is what OpenABE transports
as its payload; the KEM key is ``k = kdf(R')`` (computed in the FO layer).

NOTE.  Exact CLI flag spellings and output-file extensions vary slightly across
OpenABE releases.  The commands below follow the documented interface; if your
build differs, adjust the ``_run`` invocations here only -- nothing else in the
proof of concept needs to change.
"""

from __future__ import annotations

import atexit
import glob
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from dataclasses import dataclass
from typing import FrozenSet, List, Optional

from . import policy as pol
from .kem import CpAbeKem
from .primitives import BLOCK, F

_SCHEME = "CP"
_MPK = "mpk.cpabe"           # OpenABE default master-public filename
_MSK = "msk.cpabe"           # OpenABE default master-secret filename


# --------------------------------------------------------------------------- #
# Key material                                                                 #
# --------------------------------------------------------------------------- #
@dataclass
class OAMasterPublic:
    mpk: bytes


@dataclass
class OAMasterSecret:
    msk: bytes
    mpk: bytes


@dataclass
class OAUserKey:
    key: bytes
    mpk: bytes
    attributes: FrozenSet[str]


@dataclass
class OACiphertext:
    blob: bytes

    def to_bytes(self) -> bytes:
        return self.blob

    def __eq__(self, other: object) -> bool:
        return isinstance(other, OACiphertext) and self.blob == other.blob

    def __hash__(self) -> int:
        return hash(self.blob)


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #
def _san(attr: str) -> str:
    """Sanitise an attribute string to an OpenABE-safe token."""
    return re.sub(r"[^A-Za-z0-9_]", "_", attr)


def _policy_string(node: pol.Policy) -> str:
    """Render a policy AST as an OpenABE boolean expression."""
    if isinstance(node, pol.Leaf):
        return _san(node.attr)
    if isinstance(node, pol.And):
        return "(" + " and ".join(_policy_string(c) for c in node.children) + ")"
    if isinstance(node, pol.Or):
        return "(" + " or ".join(_policy_string(c) for c in node.children) + ")"
    raise NotImplementedError(
        "the OpenABE CLI backend renders and/or policies; threshold gates "
        "are only supported by the reference backend in this PoC"
    )


# --------------------------------------------------------------------------- #
# The backend                                                                  #
# --------------------------------------------------------------------------- #
class OpenABEKEM(CpAbeKem):
    name = "OpenABE CLI (CP-WATERS-KEM, scheme CP)"
    deterministic_ciphertext = False       # OpenABE encryption is randomized

    def __init__(self) -> None:
        self._dir: Optional[str] = None    # persistent working directory

    # -- working dir + process helpers -------------------------------------- #
    def _workdir(self) -> str:
        if self._dir is None:
            self._dir = tempfile.mkdtemp(prefix="openabe_poc_")
            atexit.register(shutil.rmtree, self._dir, ignore_errors=True)
        return self._dir

    def _run(self, cmd: List[str]) -> subprocess.CompletedProcess:
        return subprocess.run(cmd, cwd=self._workdir(),
                              capture_output=True, text=True)

    def _run_checked(self, cmd: List[str]) -> subprocess.CompletedProcess:
        r = self._run(cmd)
        if r.returncode != 0:
            raise RuntimeError(
                f"{cmd[0]} failed (exit {r.returncode})\n"
                f"  cmd   : {' '.join(cmd)}\n"
                f"  cwd   : {self._workdir()}\n"
                f"  stdout: {r.stdout.strip()}\n"
                f"  stderr: {r.stderr.strip()}"
            )
        return r

    def _write(self, name: str, data: bytes) -> None:
        with open(os.path.join(self._workdir(), name), "wb") as fh:
            fh.write(data)

    def _read(self, name: str) -> bytes:
        path = os.path.join(self._workdir(), name)
        if not os.path.exists(path):
            matches = sorted(glob.glob(path + "*"))
            if not matches:
                raise FileNotFoundError(f"expected OpenABE output {name!r}")
            path = matches[0]
        with open(path, "rb") as fh:
            return fh.read()

    def _ensure_master(self, mpk: bytes, msk: Optional[bytes] = None) -> None:
        """Write the master files that this operation will use into the working
        dir.  Any *extra* files ``oabe_setup`` produced (e.g. scheme parameter
        files, which are the same for every authority of a given scheme) are
        left untouched; only ``mpk`` / ``msk`` are (re)written, so several
        authorities can share one KEM instance across the demo scenarios."""
        self._write(_MPK, mpk)
        if msk is not None:
            self._write(_MSK, msk)

    # -- Setup --------------------------------------------------------------- #
    def setup(self):
        self._run_checked(["oabe_setup", "-s", _SCHEME])
        mpk = self._read(_MPK)
        msk = self._read(_MSK)
        return OAMasterPublic(mpk=mpk), OAMasterSecret(msk=msk, mpk=mpk)

    # -- KeyGen -------------------------------------------------------------- #
    def keygen(self, msk: OAMasterSecret, mpk: OAMasterPublic,
               attributes: FrozenSet[str]):
        self._ensure_master(msk.mpk, msk.msk)
        attrs = sorted(_san(a) for a in attributes if not a.startswith("presc:"))
        tag = "key_" + uuid.uuid4().hex[:8]
        self._run_checked(["oabe_keygen", "-s", _SCHEME,
                           "-i", "|".join(attrs), "-o", tag])
        key = self._read(tag + ".key")
        return OAUserKey(key=key, mpk=mpk.mpk, attributes=frozenset(attributes))

    # -- Encaps -------------------------------------------------------------- #
    def encaps(self, mpk: OAMasterPublic, policy: pol.Policy,
               coins: bytes) -> OACiphertext:
        if len(coins) != BLOCK:
            coins = F(coins, info=b"coins-normalise")
        self._ensure_master(mpk.mpk)
        tag = uuid.uuid4().hex[:8]
        pin, cout = f"pt_{tag}.bin", f"ct_{tag}.cpabe"
        self._write(pin, coins)
        self._run_checked(["oabe_enc", "-s", _SCHEME,
                           "-e", _policy_string(policy),
                           "-i", pin, "-o", cout])
        return OACiphertext(blob=self._read(cout))

    # -- Decaps -------------------------------------------------------------- #
    def decaps(self, sk: OAUserKey, ct: OACiphertext,
               policy: pol.Policy) -> Optional[bytes]:
        self._ensure_master(sk.mpk)
        tag = uuid.uuid4().hex[:8]
        kfile, cfile, ofile = f"uk_{tag}.key", f"ct_{tag}.cpabe", f"out_{tag}.bin"
        self._write(kfile, sk.key)
        self._write(cfile, ct.blob)
        r = self._run(["oabe_dec", "-s", _SCHEME,
                       "-k", kfile, "-i", cfile, "-o", ofile])
        if r.returncode != 0:
            return None                     # attributes do not satisfy the policy
        try:
            return self._read(ofile)
        except FileNotFoundError:
            return None

    # -- (de)serialisation --------------------------------------------------- #
    def ciphertext_from_bytes(self, raw: bytes) -> OACiphertext:
        return OACiphertext(blob=raw)
