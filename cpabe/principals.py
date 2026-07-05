"""
The four principals and the message flow of the main protocol (Section 3.2).

    Medical Authority  = Issuer / Trusted Authority (holds mpk, msk)
    Physician          = honest party authoring prescriptions (cannot mint keys)
    Patient            = Holder / Prover (holds the ABE secret key)
    Pharmacy           = Verifier (encrypts the challenge; honest-but-curious)

Phases:
    0  Initialization        -- Authority.setup() publishes mpk (authenticated, S6)
    1  Prescription request  -- Physician.authorize() signs a request (S6/A2)
    2  Credential issuance    -- Authority.issue() runs KeyGen and delivers sk
    3  Anonymous auth.        -- Pharmacy.make_challenge() / Patient.answer_challenge()
                                (the ETSI challenge-response of Figure 1)
    4  Redemption            -- Pharmacy.verify_and_dispense() [+ nullifier under !A5]

Channels for Reference Points P / K / R are assumed authenticated and
integrity-protected (S1); here we make the *authenticity* of the public
parameters and of the issued credential concrete with Ed25519 signatures (S6),
and leave channel confidentiality implicit, exactly as the report scopes it.
The challenge-response itself derives its security from the cryptography, not
from the channel (the pharmacy is the adversary there).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Dict, FrozenSet, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

from . import fo
from .policy import (
    Prescription, Request, Policy, RequestGen, PolicyGen, DataGen,
)
from .primitives import H, rand_bytes, BLOCK
from .revocation import (
    NullifierRegistry, nullifier, handle, ratchet,
)


# --------------------------------------------------------------------------- #
# Canonical encodings for the signed objects                                   #
# --------------------------------------------------------------------------- #
def _request_payload(patient_id: bytes, presc: Prescription) -> bytes:
    return H(b"presc_req", patient_id, presc.presc_id.encode(),
             presc.drug_code.encode(),
             presc.not_before.isoformat().encode(),
             presc.expires_at.isoformat().encode())


def _credential_fingerprint(attrs: FrozenSet[str], patient_id: bytes) -> bytes:
    blob = b"\x00".join(sorted(a.encode() for a in attrs))
    return H(b"credential", patient_id, blob)


def _mpk_fingerprint(mpk: object) -> bytes:
    # OpenABE master public carries its bytes in `.mpk`.
    if hasattr(mpk, "mpk"):
        return H(b"mpk", mpk.mpk)
    return H(b"mpk", repr(mpk).encode())


# --------------------------------------------------------------------------- #
# Wire objects                                                                 #
# --------------------------------------------------------------------------- #
@dataclass
class PublicParams:
    mpk: object                             # for OpenABE backend this will be bytes type
    authority_pub: Ed25519PublicKey
    signature: bytes                        # over _mpk_fingerprint(mpk)  (S6)


@dataclass
class SignedRequest:
    cert_id: str                            # the physician's certificate id
    patient_id: bytes
    presc: Prescription
    signature: bytes                        # physician signature over the request


@dataclass
class Credential:
    sk: object                              # ABE secret key (backend object)
    attributes: FrozenSet[str]              # S (kept secret by the patient)
    presc: Prescription
    opening0: bytes                         # S0, seeds the nullifier chain (F2)
    auth_sig: bytes                         # Authority signature over fingerprint (S6)


@dataclass
class Challenge:
    c: object                               # KEM ciphertext part
    cprime: bytes                           # H(k) XOR R
    ap: Policy                              # advertised policy (patient re-derives its own)


@dataclass
class PharmSession:
    R: bytes
    ap: Policy
    data: str


# --------------------------------------------------------------------------- #
# Medical Authority (Issuer / TA)                                              #
# --------------------------------------------------------------------------- #
class MedicalAuthority:
    def __init__(self, kem):
        self.kem = kem
        self._sign = Ed25519PrivateKey.generate()
        self.pub = self._sign.public_key()
        self.mpk = None
        self.msk = None
        self.physician_pubs: Dict[str, Ed25519PublicKey] = {}
        self.registry = NullifierRegistry()
        self._issued: Dict[str, dict] = {}      # presc_id -> {patient_id, opening0, uses}

    # Phase 0
    def setup(self) -> PublicParams:
        self.mpk, self.msk = self.kem.setup()
        sig = self._sign.sign(_mpk_fingerprint(self.mpk))
        return PublicParams(mpk=self.mpk, authority_pub=self.pub, signature=sig)

    def register_physician(self, cert_id: str, pub: Ed25519PublicKey) -> None:
        self.physician_pubs[cert_id] = pub

    # Phase 2  (issuance / update)
    def issue(self, req: SignedRequest, uses: Optional[int] = None) -> Credential:
        """Verify the physician's certificate and request (S6/A2), then run
        KeyGen on the prescription attributes and deliver the credential.

        ``uses``:  None  -> assumption A5 (chronic, unlimited reuse; no nullifier
                            bookkeeping).
                   n     -> A5 dropped: publish n one-time nullifier handles so
                            reuse beyond n is detectable (F2).
        """
        pub = self.physician_pubs.get(req.cert_id)
        if pub is None:
            raise PermissionError(f"unknown physician certificate {req.cert_id!r}")
        # Raises cryptography.exceptions.InvalidSignature on tampering.
        pub.verify(req.signature, _request_payload(req.patient_id, req.presc))

        S = req.presc.key_attributes()
        sk = self.kem.keygen(self.msk, self.mpk, S)
        opening0 = rand_bytes(BLOCK)

        #TODO: Optimize nullifier implementation
        if uses is not None:
            # Publish handles NN_0 .. NN_{uses-1} (ratcheted openings).
            s_i = opening0
            for _ in range(uses):
                self.registry.publish(handle(nullifier(s_i, req.patient_id)))
                s_i = ratchet(s_i)
        self._issued[req.presc.presc_id] = {
            "patient_id": req.patient_id, "opening0": opening0, "uses": uses,
        }

        auth_sig = self._sign.sign(_credential_fingerprint(S, req.patient_id))
        return Credential(sk=sk, attributes=S, presc=req.presc,
                          opening0=opening0, auth_sig=auth_sig)

    # Phase 4 helper (only under !A5): confirm a spend by removing the handle.
    def confirm_spend(self, nn_handle: bytes) -> bool:
        return self.registry.remove(nn_handle)

    # F3 -- active revocation with deliberate loss of privacy.
    def revoke(self, presc_id: str, max_uses: int = 128) -> int:
        """Revoke a credential on demand.  Because the Authority knows the
        binding ID_patient <-> S0 it recomputes the whole nullifier chain and
        removes every handle -- linking the offender's uses by design (F3)."""
        rec = self._issued.get(presc_id)
        if rec is None:
            return 0
        removed = 0
        s_i = rec["opening0"]
        for _ in range(max_uses):
            if self.registry.remove(handle(nullifier(s_i, rec["patient_id"]))):
                removed += 1
            s_i = ratchet(s_i)
        return removed


# --------------------------------------------------------------------------- #
# Physician                                                                    #
# --------------------------------------------------------------------------- #
class Physician:
    def __init__(self, cert_id: str):
        self.cert_id = cert_id
        self._sign = Ed25519PrivateKey.generate()
        self.pub = self._sign.public_key()

    # Phase 1
    def authorize(self, patient_id: bytes, presc: Prescription) -> SignedRequest:
        sig = self._sign.sign(_request_payload(patient_id, presc))
        return SignedRequest(cert_id=self.cert_id, patient_id=patient_id,
                             presc=presc, signature=sig)


# --------------------------------------------------------------------------- #
# Patient (Holder / Prover)                                                    #
# --------------------------------------------------------------------------- #
class Patient:
    def __init__(self, kem, patient_id: bytes):
        self.kem = kem
        self.patient_id = patient_id
        self.pp: Optional[PublicParams] = None
        self.cred: Optional[Credential] = None
        self._opening: Optional[bytes] = None
        self._session: dict = {}

    # Phase 0 receive: verify authenticity of the public parameters (S6).
    def receive_params(self, pp: PublicParams) -> None:
        pp.authority_pub.verify(pp.signature, _mpk_fingerprint(pp.mpk))
        self.pp = pp

    # Phase 2 receive: verify the credential's origin (S6), then store it (A4).
    def store_credential(self, cred: Credential, authority_pub: Ed25519PublicKey) -> None:
        authority_pub.verify(cred.auth_sig,
                             _credential_fingerprint(cred.attributes, self.patient_id))
        self.cred = cred
        self._opening = cred.opening0
        self._session = {}

    # Phase 3 -- prover side of the ETSI handshake.
    def start_handshake(self, now: date) -> Request:
        req = RequestGen(self.cred.attributes, now)
        self._session = {"req": req}
        return req

    def answer_challenge(self, ch: Challenge) -> Optional[bytes]:
        """Run DecABE (Algorithm 2) with the patient's *own* view of the policy.

        Returns the recovered ``R`` on success, or ``None`` to abort -- which
        happens both when the credential does not satisfy the policy and when
        the re-encryption check fails (a malicious verifier's crafted
        challenge).  This is the report's "FIX (B)": the honest patient only
        proceeds for AP = PolicyGen(RequestGen(S)) of its own credential.
        """
        ap = PolicyGen(self._session["req"])
        return fo.dec_abe(self.kem, self.pp.mpk, self.cred.sk, ap, ch.c, ch.cprime)

    # Redemption under !A5 -- reveal the current nullifier, then ratchet (F2/S7).
    def current_nullifier(self) -> bytes:
        if self._opening is None: return b"\0"
        return nullifier(self._opening, self.patient_id)

    def advance_use(self) -> None:
        if self._opening is None: return None
        self._opening = ratchet(self._opening)


# --------------------------------------------------------------------------- #
# Pharmacy (Verifier)                                                          #
# --------------------------------------------------------------------------- #
class Pharmacy:
    def __init__(self, kem, pharmacy_id: bytes):
        self.kem = kem
        self.pharmacy_id = pharmacy_id
        self.pp: Optional[PublicParams] = None

    def receive_params(self, pp: PublicParams) -> None:
        pp.authority_pub.verify(pp.signature, _mpk_fingerprint(pp.mpk))
        self.pp = pp

    # TODO: Consider adding a check for date being really NOW
    # Phase 3 -- verifier side: compile the dispensing policy and challenge.
    def make_challenge(self, req: Request):
        ap = PolicyGen(req)                    # the dispensing rule
        data = DataGen(req)                    # the medicine to hand over
        R = rand_bytes(BLOCK)                  # fresh K_chosen || r_chosen (S3, S5)
        c, cprime = fo.enc_abe(self.kem, self.pp.mpk, ap, R)   # Algorithm 1
        return Challenge(c=c, cprime=cprime, ap=ap), PharmSession(R=R, ap=ap, data=data)

    # Phase 4 -- verify the response and dispense (A5 path: no extra bookkeeping).
    def verify_and_dispense(self, session: PharmSession,
                            response: Optional[bytes]) -> Optional[str]:
        if response is None or response != session.R:
            return None                        # unforgeable: no key -> no medicine
        return session.data

    # Phase 4 under !A5 -- additionally check & consume the one-time nullifier.
    def verify_and_dispense_once(self, session: PharmSession,
                                 response: Optional[bytes],
                                 nullifier_value: bytes,
                                 authority: MedicalAuthority) -> Optional[str]:
        if response is None or response != session.R:
            return None
        nn = handle(nullifier_value)
        if not authority.registry.contains(nn):
            return None                        # already redeemed / revoked (F2)
        authority.confirm_spend(nn)            # Authority removes the handle
        return session.data
