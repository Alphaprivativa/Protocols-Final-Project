# Anonymous Electronic Prescriptions — CP-ABE Challenge-Response (Proof of Concept)

A runnable proof of concept for the protocol described in the project report
*"Verifiable Credentials via CP-ABE Challenge-Response: Anonymous Electronic
Prescriptions"*.

It implements the four-principal, four-phase protocol of Section 3 end to end —
including the Fujisaki–Okamoto–transformed `EncABE`/`DecABE` of **Algorithms 1
and 2**, the anonymity-giving **re-encryption check**, time-based revocation
(**F1**), the ratcheting-nullifier machinery for double-spend detection
(**F2**/**S7**), and active revocation (**F3**) — and demonstrates the security
requirements **S2–S7** with executable scenarios.

---

## 1. Language and CP-ABE backend: what was chosen and why

#TODO: Correct this

## 1. Language and CP-ABE backend

**Language — Python**, driving **OpenABE** through its command-line tools. The
proposal allows Java/Kotlin/Python/Go and explicitly invites using OpenABE
directly instead of the Kotlin wrapper; driving the `oabe_*` CLI is the simplest
way to reach the real **CP-WATERS-KEM**, and the FO transform, handshake and
principals read almost line-for-line like the report's algorithms.

**CP-ABE — OpenABE only.** The protocol is written once against a small
`CpAbeKem` interface (`setup / keygen / encaps / decaps`, matching
`Pi = (Setup, KeyGen, Encaps, Decaps)`), and the sole backend is the real thing:

| Backend | What it is | When |
|---|---|---|
| **OpenABE** (`cpabe/openabe_backend.py`) | Thin adapter over `oabe_setup/keygen/enc/dec`, scheme `-s CP` — the real CP-WATERS-KEM. | Always (the only backend). |



---


## 2. Running against OpenABE (CP-WATERS-KEM)

The protocol code does not change — only the KEM backend does.

**Option A — Docker (self-contained):**

```bash
docker build -f openabe/Dockerfile -t eprescription-poc .
docker run --rm eprescription-poc          # runs the demo on the openabe backend
```

**Option B — Codespaces:**

Create a codespace on top of this repository, this will automatically build the docker container, then run

```bash
python3 run_demo.py --backend openabe      # runs the demo on the openabe backend
```

Both follow OpenABE's documented build (`. ./env && make deps && make && make
install`) with some adjustments to make it work for `ubuntu:20.04`.

---

## 3. What the PoC implements, mapped to the report

### Principals and phases (Section 3.2)

| Report | Code |
|---|---|
| Phase 0 — Initialization (`Setup`, publish `mpk`) | `MedicalAuthority.setup()` |
| Phase 1 — Prescription request (physician signs) | `Physician.authorize()` |
| Phase 2 — Credential issuance (`KeyGen`, deliver `sk`) | `MedicalAuthority.issue()` |
| Phase 3 — Anonymous authentication (challenge-response) | `Pharmacy.make_challenge()` / `Patient.answer_challenge()` |
| Phase 4 — Redemption (dispense, optional nullifier) | `Pharmacy.verify_and_dispense[_once]()` |

### Cryptographic core

* **Algorithms 1 & 2** (`cpabe/fo.py`) — `EncABE`/`DecABE` on the KEM, with the
  **re-encryption check**. OpenABE ciphertexts are randomized, so the check is
  realised as *decapsulated-randomness equality* (equivalent by KEM
  correctness, and it never puts the secret randomness on the wire).
* **`RequestGen` / `PolicyGen` / `DataGen`** (`cpabe/policy.py`) — the
  deterministic `S -> req -> (AP, data)` pipeline.

### Time validity (F1) via OpenABE numerical date comparisons

OpenABE policies are not limited to AND/OR trees: they support **numerical
attributes** and integer **comparisons**, compiled into a compact bit-encoded
LSSS. We use this directly. The credential carries the validity window as two
date numbers (days since 2000-01-01):

```
S = { role_patient, drug_<X>, not_before = <days>, expires_at = <days> }
```

and the pharmacy's dispensing policy is the report's
`drug:X AND (not_before <= now) AND (now <= expires_at)`, rendered natively as

```
drug_<X>  and  not_before <= <today>  and  expires_at >= <today>
```

An expired or not-yet-valid credential fails a comparison, so decryption fails
and nothing is dispensed — F1, enforced inside the ABE layer (so the pharmacy
still learns only the single "satisfied" bit, S2). This replaces the earlier
month-slot encoding: the key now holds **two** date attributes instead of dozens,
and the window check is two integer comparisons.

### Requirements exercised by `run_demo.py`

| Req | Scenario | Mechanism |
|---|---|---|
| **S2** patient anonymity | 1, 5 | attributes live in the key; re-encryption check blocks a curious verifier |
| **S3** unlinkability | 7 | fresh `R = K_chosen‖r_chosen` per session ⇒ uncorrelated transcripts |
| **S4** unforgeability | 2, 4 | no satisfying key ⇒ `DecABE = ⊥` ⇒ nothing dispensed |
| **S5** replay protection | 6 | a recorded response never matches a fresh challenge |
| **S6** authenticity | 10 | Ed25519 signatures on `mpk` and on the physician request |
| **S7** forward security | 8 | one-way nullifier ratchet `S_{i+1}=F(S_i)` |
| **F1** passive expiry | 3 | expired credential lacks the current time-slot attribute |
| **F2** double-spend detect | 8 | one-time nullifier consumed on first redemption |
| **F3** active revocation | 9 | authority recomputes the chain and removes the handles |

---

## 4. Architecture

```
run_demo.py                 driver: 11 scenarios, each asserting an S*/F* outcome
cpabe/
  kem.py                    CpAbeKem interface + OpenABE backend accessor
  openabe_backend.py        OpenABE CLI adapter (real CP-WATERS-KEM)
  fo.py                     Algorithms 1 & 2 (EncABE/DecABE + re-encryption check)
  policy.py                 attributes, RequestGen/PolicyGen/DataGen, generic
                            OpenABE policy AST (Attr / Num comparison / And / Or)
  principals.py             Authority / Physician / Patient / Pharmacy + Ed25519 (S6)
  revocation.py             nullifier ratchet + registry (F2/F3/S7)
  primitives.py             H (random oracle), F (PRG/one-way), XOR, HKDF
openabe/
  Dockerfile                build OpenABE + run the PoC
  build_openabe.sh          native OpenABE build (isolated OpenSSL 1.1.1, Relic fix)
  mock_tools/               fake oabe_* for offline smoke-testing (NOT real crypto)
```

## . References

* **[1]** ETSI. *Cyber Security (CYBER); A Verifiable Credentials extension using
  Attribute-Based Encryption.* TS 103 964 V1.1.1, Feb. 2025.
* **[2]** *A Kotlin multiplatform wrapper for OpenABE* —
  <https://github.com/StefanoBerlato/kotlin-multiplatform-openabe>
* **OpenABE** (Zeutro) — <https://github.com/zeutro/openabe>
