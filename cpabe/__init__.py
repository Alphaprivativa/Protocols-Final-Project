"""
Proof-of-concept implementation of the anonymous e-prescription protocol
("Verifiable Credentials via CP-ABE Challenge-Response").

Public API:
    get_pki / select_backend  -- obtain a CP-ABE PKE backend
    register_backend, BackendSpec, available_backends, registered_backends
    MedicalAuthority, Physician, Patient, Pharmacy  -- the four principals
    Prescription              -- the clinical content authored by a physician
"""

from .pki import (
    select_backend, openabe_available, AbePki,
    BackendSpec, register_backend, available_backends, registered_backends,
)
from .policy import Prescription, date_to_int
from .principals import (
    MedicalAuthority, Physician, Patient, Pharmacy,
    PublicParams, SignedRequest, Credential, Challenge,
)

__all__ = [
    "select_backend", "openabe_available", "AbePki",
    "BackendSpec", "register_backend", "available_backends", "registered_backends",
    "Prescription", "date_to_int",
    "MedicalAuthority", "Physician", "Patient", "Pharmacy",
    "PublicParams", "SignedRequest", "Credential", "Challenge",
]
