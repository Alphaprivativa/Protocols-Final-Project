# Anonymous Electronic Prescriptions — CP-ABE Challenge-Response (Proof of Concept)

A runnable proof of concept for the protocol described in the project report
*"Verifiable Credentials via CP-ABE Challenge-Response: Anonymous Electronic
Prescriptions"*.

---

## 1. Language and CP-ABE backend

**Language — Python**, driving Zeutro's **OpenABE** through its 
command-line tools. 

**CP-ABE — OpenABE, as a PKE.** The protocol is written once against a small
`AbePke` interface (`setup / keygen / encrypt / decrypt`), plus an extensible
**backend registry** (`register_backend`) so other backends can be added for
future development. The only backend registered so far is:


| Backend | What it is | When |
|---|---|---|
| **OpenABE** (`cpabe/openabe_backend.py`) | Thin adapter over `oabe_setup/keygen/enc/dec`, scheme `-s CP` — using the real CP-WATERS-KEM. | Always (the only backend). |



---


## 2. Running the code

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

* **Anonymous challenge-response** (`cpabe/principals.py`) — the pharmacy
  ABE-encrypts a fresh random nonce `R` under the dispensing policy `AP`
  (`AbePke.encrypt`); the patient decrypts it (`AbePke.decrypt`) and returns `R`.
  Success requires the credential's attributes to satisfy `AP` (drug + in-date),
  so the pharmacy learns only the single "satisfied" bit.
* **Prover-side anonymity guard** — the honest patient engages only with a
  challenge whose *advertised* policy equals the canonical `AP` of the
  prescription it is presenting (`PolicyGen(RequestGen(S))`) but there is no re-encryption check due to non-deterministic encryption given by Zeutro's **OpneABE**.
* **`RequestGen` / `PolicyGen` / `DataGen`** (`cpabe/policy.py`) — the
  deterministic `S -> req -> (AP, data)` pipeline.


### Time validity via OpenABE numerical date comparisons

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
and nothing is dispensed.

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
  pke.py                    AbePke interface (encrypt/decrypt) + backend 
  openabe_backend.py        OpenABE CLI adapter
  policy.py                 attributes, RequestGen/PolicyGen/DataGen, generic
                            OpenABE policy AST (Attr / Num comparison /
                            And / Or)
  principals.py             Authority / Physician / Patient / Pharmacy
  revocation.py             nullifier ratchet + registry
  primitives.py             H (random oracle), F (PRG/one-way)
openabe/
  Dockerfile                build OpenABE
  build_openabe.sh          native OpenABE build
```

## . References

* **[1]** ETSI. *Cyber Security (CYBER); A Verifiable Credentials extension using
  Attribute-Based Encryption.* TS 103 964 V1.1.1, Feb. 2025.
* **OpenABE** (Zeutro) — <https://github.com/zeutro/openabe>
