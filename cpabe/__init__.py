"""
Proof-of-concept implementation of the anonymous e-prescription protocol
("Verifiable Credentials via CP-ABE Challenge-Response").

CP-ABE is provided exclusively by the real OpenABE backend (CP-WATERS, ``-s CP``).

Public API:
    get_kem / openabe_available  -- obtain the OpenABE-backed CP-ABE KEM
    MedicalAuthority, Physician, Patient, Pharmacy  -- the four principals
    Prescription                 -- the clinical content authored by a physician
"""

from .kem import select_backend, openabe_available, CpAbeKem
from .policy import Prescription, date_to_int
from .principals import (
    MedicalAuthority, Physician, Patient, Pharmacy,
    PublicParams, SignedRequest, Credential, Challenge,
)

__all__ = [
    "select_backend", "openabe_available", "CpAbeKem",
    "Prescription", "date_to_int",
    "MedicalAuthority", "Physician", "Patient", "Pharmacy",
    "PublicParams", "SignedRequest", "Credential", "Challenge",
]
