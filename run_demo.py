#!/usr/bin/env python3
"""
End-to-end demonstration of the anonymous e-prescription protocol.

Run it with:

    python3 run_demo.py                 # auto-select backend
    python3 run_demo.py --backend reference
    python3 run_demo.py --backend openabe   # requires the oabe_* tools on PATH

Each scenario prints what happens and asserts the expected outcome, tying the
behaviour back to the security (S*) and functional (F*) requirements of the
report.
"""

from __future__ import annotations

import argparse
import sys
from datetime import date

from cryptography.exceptions import InvalidSignature

from cpabe import (
    select_backend, openabe_available,
    MedicalAuthority, Physician, Patient, Pharmacy, Prescription,
)
from cpabe import fo
from cpabe.policy import RequestGen, PolicyGen
from cpabe.primitives import rand_bytes, BLOCK, H, xor


# --------------------------------------------------------------------------- #
# Tiny console helpers                                                          #
# --------------------------------------------------------------------------- #
def hr(title: str) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def step(msg: str) -> None:
    print("  - " + msg)


def ok(msg: str) -> None:
    print("  \u2713 " + msg)


def digest(obj) -> str:
    """Short fingerprint of a ciphertext / bytes, for illustrating unlinkability."""
    raw = obj.to_bytes() if hasattr(obj, "to_bytes") else bytes(obj)
    return H(raw).hex()[:16]


# --------------------------------------------------------------------------- #
# Shared world set-up (Phases 0-2)                                             #
# --------------------------------------------------------------------------- #
def bootstrap(kem):
    """Set up the authority, register a physician and a pharmacy, and issue a
    valid antiretroviral prescription credential to a patient."""
    authority = MedicalAuthority(kem)
    pp = authority.setup()                                   # Phase 0
    ok("Phase 0: authority ran Setup(); mpk published and signed (S6)")

    physician = Physician(cert_id="cert:dr-Pavoletti")
    authority.register_physician(physician.cert_id, physician.pub)

    pharmacy = Pharmacy(kem, pharmacy_id=b"pharmacy:Via-Brombeis-17")
    pharmacy.receive_params(pp)
    ok("pharmacy fetched mpk and verified its authenticity (S6)")

    patient = Patient(kem, patient_id=b"patient:LVZZQL85E03A064Q")
    patient.receive_params(pp)

    # Phase 1: physician authors and signs the prescription request.
    presc = Prescription(presc_id="RX-2026-000123",
                         drug_code="antiretroviral",
                         not_before=date(2026, 1, 1),
                         expires_at=date(2026, 12, 31))
    signed_req = physician.authorize(patient.patient_id, presc)
    ok("Phase 1: physician signed a prescription request (S6/A2)")

    # Phase 2: authority verifies the physician and issues the credential.
    cred = authority.issue(signed_req)                       # A5: chronic, no nullifier
    patient.store_credential(cred, authority.pub)
    ok("Phase 2: authority verified physician, ran KeyGen, delivered sk (A4)")
    step(f"credential attributes S stay secret in the key: "
         f"drug + {sum(1 for a in cred.attributes if a.startswith('valid:'))} "
         f"monthly validity slots (never sent to the pharmacy)")
    return authority, physician, pharmacy, patient

# TODO: Date handling is a bit strange: It shouldn't be the patient who handles the date of handshake
def run_handshake(pharmacy: Pharmacy, patient: Patient, now: date):
    """One full Phase-3 handshake.  Returns (medicine_or_None, challenge, response)."""
    req = patient.start_handshake(now)                       # patient -> pharmacy
    challenge, session = pharmacy.make_challenge(req)        # Algorithm 1
    response = patient.answer_challenge(challenge)           # Algorithm 2
    medicine = pharmacy.verify_and_dispense(session, response)
    return medicine, challenge, response, session


# --------------------------------------------------------------------------- #
# Scenarios                                                                     #
# --------------------------------------------------------------------------- #
def scenario_happy(kem):
    hr("Scenario 1 - Happy path: valid credential, in-date  (S2, S4)")
    _, _, pharmacy, patient = bootstrap(kem)
    now = date(2026, 6, 15)
    medicine, challenge, response, _ = run_handshake(pharmacy, patient, now)
    step(f"pharmacy encrypted a fresh challenge under AP = {challenge.ap.canonical()}")
    step(f"patient decrypted and returned the token (re-encryption check passed)")
    assert medicine is not None
    ok(f"medicine dispensed: {medicine}")
    ok("pharmacy learned only the single 'policy satisfied' bit - no identity (S2)")


def scenario_wrong_drug(kem):
    hr("Scenario 2 - Wrong medicine requested  (S4)")
    _, _, pharmacy, patient = bootstrap(kem)
    # The patient holds an antiretroviral credential but asks for insulin.
    now = date(2026, 6, 15)
    patient.start_handshake(now)
    bad_req = RequestGen(patient.cred.attributes, now)
    bad_req = bad_req.__class__(drug_code="insulin", period=bad_req.period)  # insulin != antiretrovi
    challenge, session = pharmacy.make_challenge(bad_req)
    # Patient answers with its own policy view (antiretroviral) -> mismatch.
    response = patient.answer_challenge(challenge)
    medicine = pharmacy.verify_and_dispense(session, response)
    assert medicine is None
    ok("no antiretroviral->insulin substitution: handshake fails, nothing dispensed (S4)")


def scenario_expired(kem):
    hr("Scenario 3 - Expired credential  (F1)")
    _, _, pharmacy, patient = bootstrap(kem)
    now = date(2027, 3, 1)                                   # past expires_at
    medicine, challenge, _, _ = run_handshake(pharmacy, patient, now)
    step(f"current period {challenge.ap.canonical()} is not in the credential's slots")
    assert medicine is None
    ok("expired credential no longer satisfies any dispensing policy (F1)")


def scenario_forgery(kem):
    hr("Scenario 4 - Unforgeability against a non-holder  (S4)")
    authority, physician, pharmacy, victim = bootstrap(kem)
    now = date(2026, 6, 15)

    # A different patient holds only an *insulin* credential and tries to redeem
    # the victim's antiretroviral challenge by interacting with the pharmacy.
    attacker = Patient(kem, patient_id=b"patient:CVNDSN87B14Z613C")
    attacker.receive_params(victim.pp)
    bad_presc = Prescription("RX-ATK", "insulin", date(2026, 1, 1), date(2026, 12, 31))
    attacker.store_credential(authority.issue(physician.authorize(
        attacker.patient_id, bad_presc)), authority.pub)

    # The pharmacy is asked to dispense an antiretroviral.
    from cpabe.policy import Request
    req = Request(drug_code="antiretroviral", period=RequestGen(
        victim.cred.attributes, now).period)
    challenge, session = pharmacy.make_challenge(req)
    step("attacker holds an insulin key, but the challenge is for antiretroviral")
    attacker._session = {"req": req}
    forged = attacker.answer_challenge(challenge)   # DecABE -> None (attrs unsatisfied)
    medicine = pharmacy.verify_and_dispense(session, forged)
    assert medicine is None
    ok("a party without a satisfying credential cannot make the pharmacy dispense, "
       "even interacting adaptively (S4)")


def scenario_malicious_verifier(kem):
    hr("Scenario 5 - Malicious (honest-but-curious) pharmacy  (S2, A3)")
    _, _, pharmacy, patient = bootstrap(kem)
    now = date(2026, 6, 15)
    req = patient.start_handshake(now)
    ap = PolicyGen(req)

    # The curious pharmacy tries to probe the key: it crafts (c, c') NOT derived
    # from any R via Algorithm 1 (it picks independent randomness and a chosen R).
    from cpabe import Challenge
    bad_coins = rand_bytes(BLOCK)
    c_bad = kem.encaps(pharmacy.pp.mpk, ap, bad_coins)
    k_bad = fo._kem_key(bad_coins)
    chosen_R = rand_bytes(BLOCK)
    cprime_bad = xor(H(k_bad), chosen_R)
    step("pharmacy sends a dishonestly-formed challenge to fish for key info...")
    response = patient.answer_challenge(Challenge(c=c_bad, cprime=cprime_bad, ap=ap))
    assert response is None
    ok("the prover's re-encryption check rejects the crafted challenge - "
       "no information leaks (S2)")


def scenario_replay(kem):
    hr("Scenario 6 - Replay of a recorded transcript  (S5)")
    _, _, pharmacy, patient = bootstrap(kem)
    now = date(2026, 6, 15)

    # Session A completes successfully; an eavesdropper records the response.
    med_a, ch_a, resp_a, sess_a = run_handshake(pharmacy, patient, now)
    assert med_a is not None
    step(f"recorded response token digest = {H(resp_a).hex()[:16]}")

    # Session B: the pharmacy issues a fresh challenge (new random R).
    req_b = patient.start_handshake(now)
    ch_b, sess_b = pharmacy.make_challenge(req_b)
    step(f"new session uses fresh randomness: challenge digest "
         f"{digest(ch_a.c)} -> {digest(ch_b.c)}")
    # The attacker replays the OLD response against the new session.
    medicine = pharmacy.verify_and_dispense(sess_b, resp_a)
    assert medicine is None
    ok("a recorded response does not match a fresh challenge - replay fails (S5)")


def scenario_unlinkability(kem):
    hr("Scenario 7 - Unlinkability of repeated visits  (S3)")
    _, _, pharmacy, patient = bootstrap(kem)
    now = date(2026, 6, 15)
    _, ch1, resp1, _ = run_handshake(pharmacy, patient, now)
    _, ch2, resp2, _ = run_handshake(pharmacy, patient, now)
    step(f"visit 1 challenge digest: {digest(ch1.c)}  response: {H(resp1).hex()[:16]}")
    step(f"visit 2 challenge digest: {digest(ch2.c)}  response: {H(resp2).hex()[:16]}")
    assert ch1.c.to_bytes() != ch2.c.to_bytes() and resp1 != resp2
    ok("two visits with the SAME credential produce independent, uncorrelated "
       "transcripts (S3)")
    step("full indistinguishability is proved in the Tamarin equivalence model")


def scenario_double_spend(kem):
    hr("Scenario 8 - One-time prescription without A5: double spending  (F2, S7)")
    authority = MedicalAuthority(kem)
    pp = authority.setup()
    physician = Physician(cert_id="cert:dr-bianchi")
    authority.register_physician(physician.cert_id, physician.pub)
    pharmacy = Pharmacy(kem, pharmacy_id=b"pharmacy:roma-02")
    pharmacy.receive_params(pp)
    patient = Patient(kem, patient_id=b"patient:IT-SSN-4410-ABC")
    patient.receive_params(pp)

    presc = Prescription("RX-ONE-777", "salbutamol",
                         date(2026, 1, 1), date(2026, 12, 31))
    signed = physician.authorize(patient.patient_id, presc)
    cred = authority.issue(signed, uses=1)                   # A5 dropped: single use
    patient.store_credential(cred, authority.pub)
    step("issued a SINGLE-USE credential; one nullifier handle published")

    now = date(2026, 6, 15)

    # First redemption: reveal nullifier, pharmacy checks & consumes it.
    req = patient.start_handshake(now)
    ch, sess = pharmacy.make_challenge(req)
    resp = patient.answer_challenge(ch)
    med1 = pharmacy.verify_and_dispense_once(sess, resp, patient.current_nullifier(),
                                             authority)
    assert med1 is not None
    ok(f"first redemption succeeds: {med1}")
    patient.advance_use()                                    # ratchet S_i -> S_{i+1}

    # Second redemption attempt with the (now ratcheted) credential.
    req2 = patient.start_handshake(now)
    ch2, sess2 = pharmacy.make_challenge(req2)
    resp2 = patient.answer_challenge(ch2)
    med2 = pharmacy.verify_and_dispense_once(sess2, resp2, patient.current_nullifier(),
                                             authority)
    assert med2 is None
    ok("second redemption rejected: the one-time nullifier was already consumed (F2)")
    step("each use reveals a fresh, unlinkable nullifier via S_{i+1}=F(S_i); the "
         "one-way ratchet keeps earlier visits private (S7)")


def scenario_active_revocation(kem):
    hr("Scenario 9 - Active revocation of an illegitimate credential  (F3)")
    authority = MedicalAuthority(kem)
    pp = authority.setup()
    physician = Physician(cert_id="cert:dr-verdi")
    authority.register_physician(physician.cert_id, physician.pub)
    pharmacy = Pharmacy(kem, pharmacy_id=b"pharmacy:napoli-03")
    pharmacy.receive_params(pp)
    patient = Patient(kem, patient_id=b"patient:colluding-01")
    patient.receive_params(pp)

    presc = Prescription("RX-BAD-001", "statin", date(2026, 1, 1), date(2026, 12, 31))
    signed = physician.authorize(patient.patient_id, presc)
    cred = authority.issue(signed, uses=3)                   # multi-use, !A5
    patient.store_credential(cred, authority.pub)

    now = date(2026, 6, 15)
    # Works before revocation.
    req = patient.start_handshake(now)
    ch, sess = pharmacy.make_challenge(req)
    resp = patient.answer_challenge(ch)
    assert pharmacy.verify_and_dispense_once(sess, resp, patient.current_nullifier(),
                                             authority) is not None
    ok("credential works before revocation")

    removed = authority.revoke("RX-BAD-001")                 # F3
    step(f"authority recomputed the nullifier chain and removed {removed} handles")
    patient.advance_use()

    req2 = patient.start_handshake(now)
    ch2, sess2 = pharmacy.make_challenge(req2)
    resp2 = patient.answer_challenge(ch2)
    med = pharmacy.verify_and_dispense_once(sess2, resp2, patient.current_nullifier(),
                                            authority)
    assert med is None
    ok("after revocation the credential is refused; privacy is intentionally "
       "forfeited for the offender (F3)")


def scenario_authenticity(kem):
    hr("Scenario 10 - Credential / request authenticity  (S6)")
    authority = MedicalAuthority(kem)
    authority.setup()
    physician = Physician(cert_id="cert:dr-neri")
    authority.register_physician(physician.cert_id, physician.pub)

    patient_id = b"patient:auth-check"
    presc = Prescription("RX-AUTH-1", "insulin", date(2026, 1, 1), date(2026, 12, 31))

    # (a) An unregistered physician cannot get a credential issued.
    rogue = Physician(cert_id="cert:not-registered")
    try:
        authority.issue(rogue.authorize(patient_id, presc))
        raise AssertionError("rogue physician should have been rejected")
    except PermissionError:
        ok("request from an unregistered physician certificate is rejected (S6)")

    # (b) A tampered request (forged signature) is rejected.
    good = physician.authorize(patient_id, presc)
    tampered = good.__class__(cert_id=good.cert_id, patient_id=patient_id,
                              presc=Prescription("RX-AUTH-1", "antiretroviral",
                                                 presc.not_before, presc.expires_at),
                              signature=good.signature)      # signature no longer matches
    try:
        authority.issue(tampered)
        raise AssertionError("tampered request should have been rejected")
    except InvalidSignature:
        ok("a request whose content was altered fails signature verification (S6)")


# --------------------------------------------------------------------------- #
# Main                                                                          #
# --------------------------------------------------------------------------- #
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--backend", choices=["auto", "reference", "openabe"],
                    default="auto")
    args = ap.parse_args()

    prefer = None if args.backend == "auto" else args.backend
    kem = select_backend(prefer=prefer)

    # If the OpenABE backend was chosen (auto or forced) but the oabe_* CLI
    # tools are not actually installed, fall back to the reference backend so
    # the demo still runs -- instead of crashing on the first oabe_setup call.
    if getattr(kem, "name", "").startswith("OpenABE") and not openabe_available():
        if args.backend == "openabe":
            print("  NOTE: --backend openabe was requested, but the OpenABE CLI "
                  "tools\n        (oabe_setup, oabe_keygen, oabe_enc, oabe_dec) "
                  "are not on your PATH.")
        print("  Falling back to the self-contained reference backend so the "
              "demo can run.\n  To use the real CP-WATERS-KEM, build OpenABE "
              "first:\n    ./openabe/build_openabe.sh        (local install)\n"
              "    docker build -f openabe/Dockerfile -t eprescription-poc .  "
              "(containerised)")
        kem = select_backend(prefer="reference")

    hr("Anonymous e-prescriptions via CP-ABE challenge-response - PoC")
    print(f"  CP-ABE backend : {kem.name}")
    print(f"  OpenABE on PATH: {openabe_available()}")

    scenarios = [
        scenario_happy,
        scenario_wrong_drug,
        scenario_expired,
        scenario_forgery,
        scenario_malicious_verifier,
        scenario_replay,
        scenario_unlinkability,
        scenario_double_spend,
        scenario_active_revocation,
        scenario_authenticity,
    ]
    for sc in scenarios:
        sc(kem)

    hr("All scenarios completed successfully")
    print("  Requirements exercised: S2, S3, S4, S5, S6, S7, F1, F2, F3")
    print("  (S1 authenticated/confidential channels are assumed, as in the report.)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
