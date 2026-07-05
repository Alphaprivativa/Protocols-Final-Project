"""
Proof-of-concept implementation of the anonymous e-prescription protocol
("Verifiable Credentials via CP-ABE Challenge-Response").

Public API:
    select_backend        -- pick a CP-ABE KEM backend (OpenABE if available,
                             else the self-contained reference backend)
    MedicalAuthority, Physician, Patient, Pharmacy  -- the four principals
    Prescription          -- the clinical content authored by a physician
"""

from .kem import select_backend, openabe_available, CpAbeKem
from .policy import Prescription, month_slot
from .principals import (
    MedicalAuthority, Physician, Patient, Pharmacy,
    PublicParams, SignedRequest, Credential, Challenge,
)

__all__ = [
    "select_backend", "openabe_available", "CpAbeKem",
    "Prescription", "month_slot",
    "MedicalAuthority", "Physician", "Patient", "Pharmacy",
    "PublicParams", "SignedRequest", "Credential", "Challenge",
]
