#!/usr/bin/env python3
"""
End-to-end demonstration of the anonymous e-prescription protocol.

at the moment CP-ABE is provided exclusively by the real OpenABE backend (CP-WATERS, -s CP).
Build OpenABE first, then run inside that environment:

    ./openabe/build_openabe.sh && source run_env.sh   # native, or
    docker build -f openabe/Dockerfile -t eprescription-poc . && docker run --rm eprescription-poc

    python3 run_demo.py

Each scenario prints what happens and asserts the expected S*/F* outcome.
"""

from __future__ import annotations

import argparse
import sys
from datetime import date

from cryptography.exceptions import InvalidSignature

from cpabe import (
    select_backend, openabe_available,
    MedicalAuthority, Physician, Patient, Pharmacy, Prescription, Challenge,
)
from cpabe.policy import Request, RequestGen, PolicyGen, date_to_int
from cpabe.primitives import rand_bytes, BLOCK, H


# --------------------------------------------------------------------------- #
# Console helpers                                                              #
# --------------------------------------------------------------------------- #
def hr(title: str) -> None:
    print("\n" + "=" * 72 + f"\n{title}\n" + "=" * 72)


def step(msg: str) -> None:
    print("  - " + msg)


def ok(msg: str) -> None:
    print("  \u2713 " + msg)


def digest(obj) -> str:
    raw = obj if isinstance(obj, (bytes, bytearray)) else bytes(obj)
    return H(raw).hex()[:16]


# --------------------------------------------------------------------------- #
# Shared world set-up (Phases 0-2)                                             #
# --------------------------------------------------------------------------- #
def bootstrap(pke, drug="antiretroviral",
              not_before=date(2026, 1, 1), expires_at=date(2026, 12, 31)):
    authority = MedicalAuthority(pke)
    pp = authority.setup()
    ok("Phase 0: authority ran Setup(); mpk published and signed (S6)")

    physician = Physician(cert_id="cert:dr-esposito")
    authority.register_physician(physician.cert_id, physician.pub)

    pharmacy = Pharmacy(pke, pharmacy_id=b"pharmacy:via-Brombeis-17")
    pharmacy.receive_params(pp)
    ok("pharmacy fetched mpk and verified its authenticity (S6)")

    patient = Patient(pke, patient_id=b"patient:MRDDRM60R30Z600D")
    patient.receive_params(pp)

    presc = Prescription("RX-2026-000123", drug, not_before, expires_at)
    signed_req = physician.authorize(patient.patient_id, presc)
    ok("Phase 1: physician signed a prescription request (S6/A2)")

    cred = authority.issue(signed_req)
    patient.store_credential(cred, authority.pub)
    ok("Phase 2: authority verified physician, ran KeyGen, delivered sk (A4)")
    step(f"credential holds only 4 attributes: role, drug, and the validity "
         f"window as two date numbers not_before={date_to_int(not_before)}, "
         f"expires_at={date_to_int(expires_at)} (never sent to the pharmacy)")
    return authority, physician, pharmacy, patient


def run_handshake(pharmacy: Pharmacy, patient: Patient, now: date | None = None):
    req = patient.start_handshake() if now is None else patient.start_handshake(now)
    if req is None:
        step("Aborted Handshake!!")
        return None, None, None, None
    challenge, session = pharmacy.make_challenge(req)
    if challenge is None or session is None:
        step("Aborted Handshake!!")
        return None, None, None, None
    response = patient.answer_challenge(challenge)
    medicine = pharmacy.verify_and_dispense(session, response)
    return medicine, challenge, response, session


# --------------------------------------------------------------------------- #
# Scenarios                                                                     #
# --------------------------------------------------------------------------- #
def scenario_happy(pke):
    hr("Scenario 1 - Happy path: valid credential, in-date  (S2, S4, F1)")
    _, _, pharmacy, patient = bootstrap(pke)
    medicine, challenge, _, _ = run_handshake(pharmacy, patient, date(2026, 10, 6))
    assert medicine is not None and challenge is not None
    step(f"pharmacy encrypted under AP = {challenge.ap.render()}")
    step("the two comparisons check not_before <= today <= expires_at natively")
    assert medicine is not None
    ok(f"medicine dispensed: {medicine}")
    ok("pharmacy learned only the single 'policy satisfied' bit - no identity (S2)")


def scenario_wrong_drug(pke):
    hr("Scenario 2 - Wrong medicine requested  (S4)")
    _, _, pharmacy, patient = bootstrap(pke)
    now = date(2026, 6, 15)
    patient.start_handshake(now)                       # patient holds antiretroviral
    bad_req = Request(drug_code="insulin", today=date_to_int(now), now=now)
    challenge, session = pharmacy.make_challenge(bad_req)
    assert challenge is not None and session is not None
    response = patient.answer_challenge(challenge)
    assert pharmacy.verify_and_dispense(session, response) is None
    ok("no antiretroviral->insulin substitution: handshake fails (S4)")


def scenario_expired(pke):
    hr("Scenario 3 - Expired credential: today > expires_at  (F1)")
    _, _, pharmacy, patient = bootstrap(pke)
    now = date(2027, 3, 1)                             # past expires_at
    medicine, challenge, _, _ = run_handshake(pharmacy, patient, now)
    assert challenge is not None
    step(f"AP = {challenge.ap.render()}  (today={date_to_int(now)} exceeds expires_at)")
    assert medicine is None
    ok("the 'expires_at >= today' comparison fails -> nothing dispensed (F1)")


def scenario_not_yet_valid(pke):
    hr("Scenario 4 - Not-yet-valid credential: today < not_before  (F1)")
    _, _, pharmacy, patient = bootstrap(pke, not_before=date(2026, 6, 1),
                                        expires_at=date(2026, 12, 31))
    now = date(2026, 3, 1)                             # before not_before
    medicine, challenge, _, _ = run_handshake(pharmacy, patient, now)
    assert challenge is not None
    step(f"AP = {challenge.ap.render()}  (today={date_to_int(now)} precedes not_before)")
    assert medicine is None
    ok("the 'not_before <= today' comparison fails -> nothing dispensed (F1)")


def scenario_forgery(pke):
    hr("Scenario 5 - Unforgeability against a non-holder  (S4)")
    authority, physician, pharmacy, victim = bootstrap(pke)
    now = date(2026, 6, 15)
    attacker = Patient(pke, patient_id=b"patient:CVNDSN87B14Z613C")
    assert victim.pp is not None
    attacker.receive_params(victim.pp)
    bad = Prescription("RX-ATK", "insulin", date(2026, 1, 1), date(2026, 12, 31))
    attacker.store_credential(
        authority.issue(physician.authorize(attacker.patient_id, bad)), authority.pub)
    req = Request(drug_code="antiretroviral", today=date_to_int(now), now=now)
    challenge, session = pharmacy.make_challenge(req)
    assert challenge is not None and session is not None
    attacker._session = {"req": req}
    forged = attacker.answer_challenge(challenge)      # DecABE -> None (unsatisfied)
    assert pharmacy.verify_and_dispense(session, forged) is None
    ok("a party without a satisfying credential cannot make the pharmacy dispense (S4)")


def scenario_malicious_verifier(pke):
    hr("Scenario 6 - Curious pharmacy probing with a different policy  (S2, A3)")
    _, _, pharmacy, patient = bootstrap(pke)
    now = date(2026, 6, 15)
    patient.start_handshake(now)                       # patient presents antiretroviral
    # A curious pharmacy tries to learn extra attributes by advertising a
    # DIFFERENT policy (a probe) than the prescription the patient presented.
    probe_req = Request(drug_code="insulin", today=date_to_int(now), now=now)
    probe_ap = PolicyGen(probe_req)
    assert pharmacy.pp is not None
    ct = pharmacy.pke.encrypt(pharmacy.pp.mpk, probe_ap, rand_bytes(BLOCK))
    step("pharmacy advertises an insulin probe instead of the presented policy...")
    assert patient.answer_challenge(Challenge(ct=ct, ap=probe_ap)) is None
    ok("prover engages only with its own canonical policy; the probe is refused (S2)")
    step("(no FO re-encryption check now; anonymity rests on honest-but-curious A3)")


def scenario_replay(pke):
    hr("Scenario 7 - Replay of a recorded transcript  (S5)")
    _, _, pharmacy, patient = bootstrap(pke)
    now = date(2026, 6, 15)
    med_a, ch_a, resp_a, _ = run_handshake(pharmacy, patient, now)
    assert ch_a is not None and med_a is not None
    req_b = patient.start_handshake(now)
    assert req_b is not None
    ch_b, sess_b = pharmacy.make_challenge(req_b)
    assert ch_b is not None and sess_b is not None
    step(f"new session uses fresh randomness: {digest(ch_a.ct)} -> {digest(ch_b.ct)}")
    assert pharmacy.verify_and_dispense(sess_b, resp_a) is None
    ok("a recorded response does not match a fresh challenge - replay fails (S5)")


def scenario_unlinkability(pke):
    hr("Scenario 8 - Unlinkability of repeated visits  (S3)")
    _, _, pharmacy, patient = bootstrap(pke)
    now = date(2026, 6, 15)
    _, ch1, resp1, _ = run_handshake(pharmacy, patient, now)
    _, ch2, resp2, _ = run_handshake(pharmacy, patient, now)
    if ch1 is None or ch2 is None: return
    if resp1 is None or resp2 is None: return
    step(f"visit 1: challenge {digest(ch1.ct)}  response {H(resp1).hex()[:16]}")
    step(f"visit 2: challenge {digest(ch2.ct)}  response {H(resp2).hex()[:16]}")
    assert ch1.ct != ch2.ct and resp1 != resp2
    ok("two visits with the SAME credential produce uncorrelated transcripts (S3)")


def scenario_double_spend(pke):
    hr("Scenario 9 - One-time prescription without A5: double spending  (F2, S7)")
    authority = MedicalAuthority(pke); pp = authority.setup()
    physician = Physician(cert_id="cert:dr-bianchi")
    authority.register_physician(physician.cert_id, physician.pub)
    pharmacy = Pharmacy(pke, pharmacy_id=b"pharmacy:Via-Brombeis-17"); pharmacy.receive_params(pp)
    patient = Patient(pke, patient_id=b"patient:RVILGU44S07B354C"); patient.receive_params(pp)
    presc = Prescription("RX-ONE-777", "salbutamol", date(2026, 1, 1), date(2026, 12, 31))
    patient.store_credential(
        authority.issue(physician.authorize(patient.patient_id, presc), uses=1),
        authority.pub)
    step("issued a SINGLE-USE credential; one nullifier handle published")
    now = date(2026, 6, 15)
    req = patient.start_handshake(now)
    assert req is not None
    ch, sess = pharmacy.make_challenge(req)
    assert ch is not None and sess is not None
    med1 = pharmacy.verify_and_dispense_once(sess, patient.answer_challenge(ch),
                                             patient.current_nullifier(), authority)
    assert med1 is not None
    ok(f"first redemption succeeds: {med1}")
    patient.advance_use()
    req2 = patient.start_handshake(now)
    assert req2 is not None
    ch2, sess2 = pharmacy.make_challenge(req2)
    assert ch2 is not None and sess2 is not None
    med2 = pharmacy.verify_and_dispense_once(sess2, patient.answer_challenge(ch2),
                                             patient.current_nullifier(), authority)
    assert med2 is None
    ok("second redemption rejected: one-time nullifier already consumed (F2)")
    step("each use reveals a fresh nullifier via S_{i+1}=F(S_i); one-way ratchet (S7)")


def scenario_active_revocation(pke):
    hr("Scenario 10 - Active revocation of an illegitimate credential  (F3)")
    authority = MedicalAuthority(pke); pp = authority.setup()
    physician = Physician(cert_id="cert:dr-verdi")
    authority.register_physician(physician.cert_id, physician.pub)
    pharmacy = Pharmacy(pke, pharmacy_id=b"pharmacy:napoli-03"); pharmacy.receive_params(pp)
    patient = Patient(pke, patient_id=b"patient:BFFGLG78A28B832F"); patient.receive_params(pp)
    presc = Prescription("RX-BAD-001", "statin", date(2026, 1, 1), date(2026, 12, 31))
    patient.store_credential(
        authority.issue(physician.authorize(patient.patient_id, presc), uses=3),
        authority.pub)
    now = date(2026, 6, 15)
    req = patient.start_handshake(now)
    assert req is not None
    ch, sess = pharmacy.make_challenge(req)
    assert ch is not None and sess is not None
    assert pharmacy.verify_and_dispense_once(sess, patient.answer_challenge(ch),
                                             patient.current_nullifier(), authority) is not None
    ok("credential works before revocation")
    removed = authority.revoke("RX-BAD-001")
    step(f"authority recomputed the nullifier chain and removed {removed} handles")
    patient.advance_use()
    req2 = patient.start_handshake(now)
    assert req2 is not None
    ch2, sess2 = pharmacy.make_challenge(req2)
    assert ch2 is not None and sess2 is not None
    assert pharmacy.verify_and_dispense_once(sess2, patient.answer_challenge(ch2),
                                             patient.current_nullifier(), authority) is None
    ok("after revocation the credential is refused (F3)")


def scenario_authenticity(pke):
    hr("Scenario 11 - Credential / request authenticity  (S6)")
    authority = MedicalAuthority(pke); authority.setup()
    physician = Physician(cert_id="cert:dr-neri")
    authority.register_physician(physician.cert_id, physician.pub)
    pid = b"patient:PVLLRD88S26E625K"
    presc = Prescription("RX-AUTH-1", "insulin", date(2026, 1, 1), date(2026, 12, 31))
    rogue = Physician(cert_id="cert:not-registered")
    try:
        authority.issue(rogue.authorize(pid, presc)); raise AssertionError("should reject")
    except PermissionError:
        ok("request from an unregistered physician certificate is rejected (S6)")
    good = physician.authorize(pid, presc)
    tampered = good.__class__(cert_id=good.cert_id, patient_id=pid,
                              presc=Prescription("RX-AUTH-1", "antiretroviral",
                                                 presc.not_before, presc.expires_at),
                              signature=good.signature)
    try:
        authority.issue(tampered); raise AssertionError("should reject")
    except InvalidSignature:
        ok("a request whose content was altered fails signature verification (S6)")


# --------------------------------------------------------------------------- #
def main() -> int:
    hr("Anonymous e-prescriptions via CP-ABE challenge-response - PoC")

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--backend", choices=["auto", "reference", "openabe"],
                    default="auto")
    args = ap.parse_args()
    prefer = None if args.backend == "auto" else args.backend


    try:
        pke = select_backend(prefer=prefer)
    except RuntimeError as e:
        print(str(e)); return 1
    print(f"  CP-ABE backend : {pke.name}")
    print(f"  OpenABE on PATH: {openabe_available()}")

    for sc in (scenario_happy, scenario_wrong_drug, scenario_expired,
               scenario_not_yet_valid, scenario_forgery, scenario_malicious_verifier,
               scenario_replay, scenario_unlinkability, scenario_double_spend,
               scenario_active_revocation, scenario_authenticity):
        sc(pke)

    hr("All scenarios completed successfully")
    print("  Requirements exercised: S2, S3, S4, S5, S6, S7, F1, F2, F3")
    print("  Time validity (F1) uses OpenABE numerical date comparisons.")
    print("  (S1 authenticated/confidential channels are assumed, as in the report.)")
    return 0



if __name__ == "__main__":
    sys.exit(main())
