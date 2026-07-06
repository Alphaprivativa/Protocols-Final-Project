"""
Revocation, double-spending and forward security (report Section 3.3).

Three revocation needs are covered by the design:

    F1  passive expiry              -- handled in the ABE layer by the
                                       ``valid:<slot>`` time attributes (see
                                       ``policy.py``); nothing is needed here.
    F2  detecting double spending   -- only when assumption A5 (chronic-illness,
        without breaking S3            unlimited reuse) is *dropped*.
    F3  active on-demand revocation -- deliberately forfeits privacy for the
                                       offending credential.

F2 / S7 -- the ratcheting nullifier.
    At issuance the Authority embeds a secret opening value ``S0`` in the
    credential; both Authority and Patient device compute the nullifier

        N_i  = H(S_i || ID_patient)

    and the Authority publishes the *handle*  ``NN_i = F(N_i)``  in a registry
    of valid prescriptions.  A single fixed nullifier would link repeated uses,
    so the opening value is ratcheted at every spend

        S_{i+1} = F(S_i)                       (one-way, so S7 holds)

    yielding a fresh, unlinkable nullifier each time.  At redemption the Patient
    reveals ``N_i``; the Pharmacy checks ``F(N_i)`` is present, has the Authority
    remove it, and only then dispenses.  Revealing ``NN_i`` exposes nothing about
    earlier ``N_{<i}`` because ``F`` is one-way (forward security, S7).

The report's *final* design replaces the public registry with a pairing-based
cryptographic accumulator (ETSI clause 4.3.4) to keep it compact and shift
revocation control to the Issuer; that pairing accumulator is out of scope for
this proof of concept, so we model the registry as an explicit set and note the
difference.
"""

from __future__ import annotations

from typing import Set

from .primitives import H, F


# --------------------------------------------------------------------------- #
# Ratchet helpers                                                              #
# --------------------------------------------------------------------------- #
def nullifier(opening: bytes, id_patient: bytes) -> bytes:
    """``N_i = H(S_i || ID_patient)``."""
    return H(opening, id_patient)


def handle(nullifier_value: bytes) -> bytes:
    """``NN_i = F(N_i)`` -- the public, one-way handle stored in the registry."""
    return F(nullifier_value, info=b"nullifier-handle")


def ratchet(opening: bytes) -> bytes:
    """``S_{i+1} = F(S_i)``."""
    return F(opening, info=b"opening-ratchet")


# --------------------------------------------------------------------------- #
# Registry (stands in for the pairing accumulator of the final design)         #
# --------------------------------------------------------------------------- #

#TODO: Optimize nullifier implementation via cryptographic accumulator
class NullifierRegistry:
    """A public registry of valid prescription handles ``NN_i``.

    Present in the registry  ==  "this single use is still available".
    """

    def __init__(self) -> None:
        self._valid: Set[bytes] = set()

    def publish(self, nn: bytes) -> None:
        self._valid.add(nn)

    def contains(self, nn: bytes) -> bool:
        return nn in self._valid

    def remove(self, nn: bytes) -> bool:
        """Remove a handle (spend or revoke).  Returns True if it was present."""
        if nn in self._valid:
            self._valid.discard(nn)
            return True
        return False

    def __len__(self) -> int:
        return len(self._valid)
