"""
A CP-ABE backend that drives Zeutro's OpenABE through its command-line tools,
exposed as a public-key encryption primitive (:class:`~cpabe.pki.AbePki`).

This is the primitive the proposal points at -- the "Multiplatform OpenABE
Wrapper [2]" -- used here *directly* through OpenABE's own CLI (CP-WATERS,
``-s CP``).  ``oabe_enc`` / ``oabe_dec`` already provide CCA-secure ABE
encryption (PKI + FO/AES-GCM internally), so we use them as-is: no outer
PKI/FO transform is re-implemented.

Mapping to OpenABE's tools (default key filenames ``mpk.cpabe`` / ``msk.cpabe``):

    Setup    ->  oabe_setup  -s CP                          (writes mpk.cpabe, msk.cpabe)
    KeyGen   ->  oabe_keygen -s CP -i "a|b|c" -o <key>      (writes <key>.key)
    Encrypt  ->  oabe_enc    -s CP -e "<policy>" -i pt -o ct
    Decrypt  ->  oabe_dec    -s CP -k <key>.key -i ct -o pt

IMPORTANT.  ``oabe_setup`` can drop *several* files in the working directory
(scheme parameter files, not only ``mpk`` / ``msk``), and the other tools expect
to find them there.  We therefore run **every** OpenABE operation inside a
single, persistent working directory owned by this backend instance, created
once at ``setup``.  Each call uses unique filenames so repeated operations never
clobber one another.  In this single-process PoC the same backend object is
shared by all principals, so one working directory is exactly right.

NOTE.  Exact CLI flag spellings / output-file extensions vary slightly across
OpenABE releases; if your build differs, adjust the ``_run`` invocations here
only -- nothing else in the proof of concept needs to change.
"""

from __future__ import annotations

import atexit
import glob
import os
import shutil
import subprocess
import tempfile
import uuid
from dataclasses import dataclass
from typing import FrozenSet, List, Optional

from . import policy as pol
from .pki import AbePki

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


# --------------------------------------------------------------------------- #
# The backend                                                                  #
# --------------------------------------------------------------------------- #
class OpenABEPki(AbePki):
    name = "OpenABE CLI (CP-ABE / CP-WATERS, scheme CP)"
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
        """Write the master files this operation needs into the working dir.
        Extra files ``oabe_setup`` produced (scheme parameters, identical across
        authorities) are left untouched; only ``mpk`` / ``msk`` are (re)written,
        so several authorities can share one backend instance in the demo."""
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
        # Attributes are already OpenABE-native: categorical tokens (e.g.
        # "drug_antiretroviral") and numerical assignments (e.g.
        # "expires_at = 9663").  Pass them straight through.
        attrs = sorted(attributes)
        self._ensure_master(msk.mpk, msk.msk)
        tag = "key_" + uuid.uuid4().hex[:8]
        self._run_checked(["oabe_keygen", "-s", _SCHEME,
                           "-i", "|".join(attrs), "-o", tag])
        key = self._read(tag + ".key")
        return OAUserKey(key=key, mpk=mpk.mpk, attributes=frozenset(attributes))

    # -- Encrypt ------------------------------------------------------------- #
    def encrypt(self, mpk: OAMasterPublic, policy: pol.Policy,
                plaintext: bytes) -> bytes:
        self._ensure_master(mpk.mpk)
        tag = uuid.uuid4().hex[:8]
        pin, cout = f"pt_{tag}.bin", f"ct_{tag}.cpabe"
        self._write(pin, plaintext)
        self._run_checked(["oabe_enc", "-s", _SCHEME,
                           "-e", policy.render(),
                           "-i", pin, "-o", cout])
        return self._read(cout)

    # -- Decrypt ------------------------------------------------------------- #
    def decrypt(self, sk: OAUserKey, ciphertext: bytes) -> Optional[bytes]:
        self._ensure_master(sk.mpk)
        tag = uuid.uuid4().hex[:8]
        kfile, cfile, ofile = f"uk_{tag}.key", f"ct_{tag}.cpabe", f"out_{tag}.bin"
        self._write(kfile, sk.key)
        self._write(cfile, ciphertext)
        r = self._run(["oabe_dec", "-s", _SCHEME,
                       "-k", kfile, "-i", cfile, "-o", ofile])
        if r.returncode != 0:
            return None                     # attributes do not satisfy the policy
        try:
            return self._read(ofile)
        except FileNotFoundError:
            return None
