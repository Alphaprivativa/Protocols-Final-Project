"""
The four principals and the message flow of the main protocol.

    Medical Authority  = Issuer / Trusted Authority (holds mpk, msk)
    Physician          = honest party authoring prescriptions (cannot mint keys)
    Patient            = Holder / Prover (holds the ABE secret key)
    Pharmacy           = Verifier (ABE-encrypts the challenge; honest-but-curious)

Phases:
    0  Initialization        -- Authority.setup() publishes mpk (authenticated, S6)
    1  Prescription request  -- Physician.authorize() signs a request (S6/A2)
    2  Credential issuance    -- Authority.issue() runs KeyGen and delivers sk
    3  Anonymous auth.        -- Pharmacy.make_challenge() / Patient.answer_challenge()
                                (the ETSI challenge-response of Figure 1)
    4  Redemption            -- Pharmacy.verify_and_dispense() [+ nullifier under !A5]

Channels for Reference Points P / K / R are assumed authenticated and
integrity-protected; here we make the *authenticity* of the public
parameters and of the issued credential concrete with Ed25519 signatures,
and leave channel confidentiality implicit, exactly as the report scopes it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Dict, FrozenSet, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

from .policy import (
    Prescription, Request, Policy, RequestGen, PolicyGen, DataGen,
)
from .primitives import H, rand_bytes, BLOCK
from .revocation import (
    NullifierRegistry, nullifier, handle, ratchet,
)
from .pke import AbePke

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


def _mpk_fingerprint(mpk) -> bytes:
    # OpenABE master public carries its bytes in `.mpk`.
    if hasattr(mpk, "mpk"):
        return H(b"mpk", mpk.mpk)
    return H(b"mpk", repr(mpk).encode())


# --------------------------------------------------------------------------- #
# Wire objects                                                                 #
# --------------------------------------------------------------------------- #
@dataclass
class PublicParams:
    mpk: object                             # Object since we don't know exactly
                                            # how it is handled by the specific backend
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
    opening0: Optional[bytes]               # S0, seeds the nullifier chain (F2)
    auth_sig: bytes                         # Authority signature over fingerprint (S6)
    use: Optional[int] = None               # use counter


    def fetch_update_use(self) -> Optional[int]:
        """Increment the use counter, if any."""
        cur_use = self.use
        if self.use is not None:
            self.use += 1
        return cur_use


@dataclass
class Challenge:
    ct: bytes                               # ABE ciphertext of the nonce R under AP
    ap: Policy                              # advertised dispensing policy


@dataclass
class PharmSession:
    R: bytes
    ap: Policy
    data: str
    nullifier: bytes

# --------------------------------------------------------------------------- #
# Medical Authority (Issuer / TA)                                              #
# --------------------------------------------------------------------------- #
class MedicalAuthority:
    def __init__(self, pke: AbePke):
        self.pke = pke
        self._sign = Ed25519PrivateKey.generate()
        self.pub = self._sign.public_key()
        self.mpk = None
        self.msk = None
        self.physician_pubs: Dict[str, Ed25519PublicKey] = {}
        self.registry = NullifierRegistry()
        self._issued: Dict[str, dict] = {}      # presc_id -> {patient_id, opening0, uses}
        
        # hash table used to handle used handles
        self._handle_to_opening: Dict[bytes, dict] = {}

    # Phase 0
    def setup(self) -> PublicParams:
        self.mpk, self.msk = self.pke.setup()
        sig = self._sign.sign(_mpk_fingerprint(self.mpk))
        return PublicParams(mpk=self.mpk, authority_pub=self.pub, signature=sig)

    def register_physician(self, cert_id: str, pub: Ed25519PublicKey) -> None:
        self.physician_pubs[cert_id] = pub

    # Phase 2  (issuance / update)
    def issue(self, req: SignedRequest) -> Credential:
        """Verify the physician's certificate and request, then run
        KeyGen on the prescription attributes and deliver the credential.

        ``uses``:  None  -> assumption A5 (chronic, unlimited reuse; no nullifier bookkeeping).
                   n     -> publish ONLY the FIRST one-time nullifier handle.
                            Subsequent handles are published lazily after each spend.
        """
        pub = self.physician_pubs.get(req.cert_id)
        uses = req.presc.uses
        if pub is None:
            raise PermissionError(f"unknown physician certificate {req.cert_id!r}")
        # Raises cryptography.exceptions.InvalidSignature on tampering.
        pub.verify(req.signature, _request_payload(req.patient_id, req.presc))

        opening0 = None if uses is None else rand_bytes(BLOCK) 

        S = set(req.presc.key_attributes())
        if uses is not None and uses > 0:
            s_i = opening0
            S.remove("nullifier = 1")
            for i in range(uses):
                if s_i is None: break
                n_i = nullifier(s_i, req.patient_id)
                S.add(f"nullifier_{i} = {int.from_bytes(n_i[:4], 'big')}")
                s_i = ratchet(s_i)
        S = frozenset(S)
        sk = self.pke.keygen(self.msk, self.mpk, S)

        if uses is not None and opening0 is not None:
            # Publish the first handle only
            s_i = opening0
            nn_0 = handle(nullifier(s_i, req.patient_id))
            self.registry.publish(nn_0)
            self._handle_to_opening[nn_0] = {"presc_id": req.presc.presc_id, "opening": s_i}
            
        self._issued[req.presc.presc_id] = {
            "patient_id": req.patient_id, 
            "opening0": opening0, 
            "current_opening": opening0,
            "uses": uses,
            "revoked": False,
            "current_use": 0
        }

        auth_sig = self._sign.sign(_credential_fingerprint(S, req.patient_id))
        return Credential(sk=sk, attributes=S, presc=req.presc,
                          opening0=opening0, auth_sig=auth_sig,
                          use=0)

    # Phase 4 helper (only under !A5): confirm a spend by removing the handle
    # and publishing the next one in the chain.
    def confirm_spend(self, nn_handle: bytes) -> bool:
        if self.registry.remove(nn_handle):
            info = self._handle_to_opening.pop(nn_handle, None)
            if info:
                presc_id = info["presc_id"]
                s_i = info["opening"]
                rec = self._issued.get(presc_id)
                
                # If not revoked
                if rec and not rec.get("revoked", False):
                    rec["current_use"] += 1
                    # Check if there are uses left
                    if rec["uses"] is None or rec["current_use"] < rec["uses"]:
                        s_next = ratchet(s_i)
                        rec["current_opening"] = s_next
                        
                        # Next handle is computed and published on the chain
                        nn_next = handle(nullifier(s_next, rec["patient_id"]))
                        self.registry.publish(nn_next)
                        self._handle_to_opening[nn_next] = {"presc_id": presc_id, "opening": s_next}
            return True
        return False

    # F3 -- active revocation with deliberate loss of privacy.
    def revoke(self, presc_id: str, max_uses: int = 128) -> int:
        """Revoke a credential on demand.  Because the Authority knows the
        binding ID_patient <-> S0 it removes the currently published handle.
        Future handles will not be published because the credential is marked as revoked."""
        rec = self._issued.get(presc_id)
        if rec is None:
            return 0
            
        # Mark as revoked: confirm_spend does not publish the future handles
        rec["revoked"] = True
        
        removed = 0
        # Uses the checked opening value in order to find and remove the handle from the registry
        s_i = rec.get("current_opening", rec["opening0"])
        nn = handle(nullifier(s_i, rec["patient_id"]))
        
        if self.registry.remove(nn):
            removed += 1
            self._handle_to_opening.pop(nn, None)
            
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
    def __init__(self, pke: AbePke, patient_id: bytes):
        self.pke = pke
        self.patient_id = patient_id
        self.pp: Optional[PublicParams] = None
        self.cred: Optional[Credential] = None
        self._opening: Optional[bytes] = None
        self._session: dict = {}

    # Phase 0 receive: verify authenticity of the public parameters
    def receive_params(self, pp: PublicParams) -> None:
        pp.authority_pub.verify(pp.signature, _mpk_fingerprint(pp.mpk))
        self.pp = pp

    # Phase 2 receive: verify the credential's origin, then store it
    def store_credential(self, cred: Credential, authority_pub: Ed25519PublicKey) -> None:
        authority_pub.verify(cred.auth_sig,
                             _credential_fingerprint(cred.attributes, self.patient_id))
        self.cred = cred
        self._opening = cred.opening0
        self._session = {}

    # Phase 3 -- prover side of the ETSI handshake
    def start_handshake(self, now: date = datetime.now().date()) -> Request | None:
        if self.cred is None: return None
        req = RequestGen(
            self.cred.attributes, 
            use=self.cred.fetch_update_use(), 
            nullifier=self.current_nullifier(), 
            now=now)
        self._session = {"req": req}
        return req

    def answer_challenge(self, ch: Challenge) -> Optional[bytes]:
        """Answer the verifier's challenge by decrypting it with the credential.

        Prover-side consistency: the honest patient engages
        only with a challenge whose advertised policy equals the canonical AP of
        the prescription it is presenting -- AP = PolicyGen(RequestGen(S)).  It
        then ABE-decrypts the nonce; success requires its attributes to satisfy
        AP (and, via the numerical date attributes, the credential to be in
        date).  Returns the recovered nonce, or ``None`` to abort.

        NOTE: With OpenABE's built-in CCA encryption used directly there is no FO
        re-encryption check, since it is non-deterministic.
        """
        expected = PolicyGen(self._session["req"]).canonical()
        if self.cred is None: return None
        if ch.ap.canonical() != expected: return None

        return self.pke.decrypt(self.cred.sk, ch.ct)

    # Redemption under not A5 -- reveal the current nullifier, then ratchet
    def current_nullifier(self) -> bytes:
        if self._opening is None: return b"\1"
        return nullifier(self._opening, self.patient_id)

    def advance_use(self) -> None:
        if self._opening is None: return None
        self._opening = ratchet(self._opening)


# --------------------------------------------------------------------------- #
# Pharmacy (Verifier)                                                          #
# --------------------------------------------------------------------------- #
class Pharmacy:
    def __init__(self, pke: AbePke, pharmacy_id: bytes):
        self.pke = pke
        self.pharmacy_id = pharmacy_id
        self.pp: Optional[PublicParams] = None

    def receive_params(self, pp: PublicParams) -> None:
        pp.authority_pub.verify(pp.signature, _mpk_fingerprint(pp.mpk))
        self.pp = pp

    # Phase 3 -- verifier side: compile the dispensing policy and challenge.
    def make_challenge(self, req: Request):
        if self.pp is None: return None, None
        ap = PolicyGen(req)                    # the dispensing rule
        data = DataGen(req)                    # the medicine to hand over
        R = rand_bytes(BLOCK)                  # fresh nonce per session (S3, S5)
        ct = self.pke.encrypt(self.pp.mpk, ap, R)   # CCA-secure ABE encryption
        return Challenge(ct=ct, ap=ap), PharmSession(R=R, ap=ap, data=data, nullifier=req.nullifier)

    # Phase 4 -- verify the response and dispense (A5 path: no extra bookkeeping).
    def verify_and_dispense(self, session: PharmSession,
                            response: Optional[bytes]) -> Optional[str]:
        if response is None or response != session.R:
            return None                        # unforgeable: no key -> no medicine
        return session.data

    # Phase 4 under not A5 -- additionally check & consume the one-time nullifier.
    def verify_and_dispense_once(self, session: PharmSession,
                                 response: Optional[bytes],
                                 authority: MedicalAuthority) -> Optional[str]:
        if response is None or response != session.R:
            return None
        nn = handle(session.nullifier)
        if not authority.registry.contains(nn):
            return None                        # already redeemed / revoked (F2)
        authority.confirm_spend(nn)            # Authority removes the handle
        return session.data