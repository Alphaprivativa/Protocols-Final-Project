# Anonymous Electronic Prescriptions — CP-ABE Challenge-Response (Proof of Concept)

A runnable proof of concept for the protocol described in the project report
*"Verifiable Credentials via CP-ABE Challenge-Response: Anonymous Electronic
Prescriptions"* and required by activity **4** of the proposal
(*"Proof-of-concept implementation in a Language among … Java, Kotlin, Python,
Go"*).

It implements the four-principal, four-phase protocol of Section 3 end to end —
including the Fujisaki–Okamoto–transformed `EncABE`/`DecABE` of **Algorithms 1
and 2**, the anonymity-giving **re-encryption check**, time-based revocation
(**F1**), the ratcheting-nullifier machinery for double-spend detection
(**F2**/**S7**), and active revocation (**F3**) — and demonstrates the security
requirements **S2–S7** with executable scenarios.

---

## 1. Language and CP-ABE backend: what was chosen and why

**Language — Python.** The proposal allows Java, Kotlin, Python or Go and asks
for the choice best suited to the task; it also explicitly invites bypassing the
Kotlin wrapper and *"using the OpenABE C++ API directly, whichever is simpler."*
The simplest, most direct way to obtain the real CP-WATERS-KEM is to drive
**OpenABE's own command-line tools** as a subprocess — this avoids the JNI /
Kotlin-Native native-linking burden of the wrapper entirely. Orchestrating a
CLI and expressing the FO transform, the handshake and the four principals is
cleanest in Python, and the code reads almost line-for-line like the report's
algorithms. (The proposal's reference to the *Multiplatform OpenABE Wrapper* is
honoured in spirit: that wrapper exists to expose OpenABE across platforms; here
we reach the same primitive through OpenABE directly.)

**CP-ABE — a pluggable KEM with two interchangeable backends.** The protocol is
written once against a small `CpAbeKem` interface (`setup / keygen / encaps /
decaps`, matching `Π = (Setup, KeyGen, Encaps, Decaps)` from Section 3.1). Two
backends implement it:

| Backend | What it is | When it is used |
|---|---|---|
| **OpenABE** (`openabe_backend.py`) | Thin adapter over `oabe_setup/keygen/enc/dec`, scheme `-s CP` — the **real CP-WATERS-KEM** the report specifies. | Automatically, whenever the `oabe_*` tools are on the PATH. |
| **Reference** (`reference_backend.py`) | A self-contained, deterministic small-universe attribute KEM built from real X25519 / ECIES / AES-GCM with LSSS-style secret sharing. | Fallback, so the PoC runs anywhere `cryptography` is installed. |

This keeps the PoC **runnable out of the box** (reference backend) while giving a
one-flag path to the **real primitive** (OpenABE) — see §3.

---

## 2. Quick start (reference backend, no native deps)

```bash
pip install -r requirements.txt        # just `cryptography`
python3 run_demo.py                     # runs all scenarios
```

Expected: ten scenarios, each ending in a `✓`, exercising S2, S3, S4, S5, S6,
S7, F1, F2, F3. Force a backend with `--backend reference` or
`--backend openabe`.

---

## 3. Running against the **real** OpenABE (CP-WATERS-KEM)

The protocol code does not change — only the KEM backend does.

**Option A — Docker (self-contained):**

```bash
docker build -f openabe/Dockerfile -t eprescription-poc .
docker run --rm eprescription-poc          # runs the demo on the openabe backend
```

**Option B — build OpenABE locally:**

```bash
./openabe/build_openabe.sh                 # clone + build + install oabe_* tools
python3 run_demo.py --backend openabe
```

Both follow OpenABE's documented build (`. ./env && make deps && make && make
install`). The dependency build takes a few minutes. Exact CLI flag spellings
vary slightly across OpenABE releases; if yours differs, the only file to adjust
is `cpabe/openabe_backend.py`.

---

## 4. What the PoC implements, mapped to the report

### Principals and phases (Section 3.2)

| Report | Code |
|---|---|
| Phase 0 — Initialization (`Setup`, publish `mpk`) | `MedicalAuthority.setup()` |
| Phase 1 — Prescription request (physician signs) | `Physician.authorize()` |
| Phase 2 — Credential issuance (`KeyGen`, deliver `sk`) | `MedicalAuthority.issue()` |
| Phase 3 — Anonymous authentication (challenge-response) | `Pharmacy.make_challenge()` / `Patient.answer_challenge()` |
| Phase 4 — Redemption (dispense, optional nullifier) | `Pharmacy.verify_and_dispense[_once]()` |

### Cryptographic core

* **Algorithms 1 & 2** (`fo.py`) — `EncABE`/`DecABE` written verbatim on top of
  the KEM, with `u = H(R‖AP)`, `R' = F(u)`, `c' = H(k) ⊕ R`, and the
  **re-encryption check** on decryption. As the report puts it, that check *"is
  exactly what gives anonymity for the prover: a Prover accepts a challenge only
  if it could itself have produced the same ciphertext … so a malicious Verifier
  cannot craft a dishonest ciphertext to extract information about the key."*
* **`RequestGen` / `PolicyGen` / `DataGen`** (`policy.py`) — the deterministic
  `S → req → (AP, data)` pipeline of the Tamarin abstraction. The dispensing
  policy is the report's `drug:X ∧ (not_before ≤ now) ∧ (now ≤ expires_at)`.
* **Attribute encoding** (`policy.py`) — the prescription becomes the attribute
  set `S` embedded in the key and **never transmitted**; the pharmacy only ever
  learns the single "policy satisfied" bit (S2).

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

## 5. Architecture

```
run_demo.py                 driver: 10 scenarios, each asserting an S*/F* outcome
cpabe/
  kem.py                    CpAbeKem interface + backend auto-selection
  reference_backend.py      runnable X25519/ECIES KEM  (default)
  openabe_backend.py        OpenABE CLI adapter  (real CP-WATERS-KEM)
  fo.py                     Algorithms 1 & 2 (EncABE/DecABE + re-encryption check)
  policy.py                 attributes, RequestGen/PolicyGen/DataGen, access-policy AST
  principals.py             MedicalAuthority / Physician / Patient / Pharmacy + S6 signatures
  revocation.py             nullifier ratchet + registry (F2/F3/S7)
  primitives.py             H (random oracle), F (PRG/one-way), XOR, GF(2^8) Shamir
openabe/
  Dockerfile                build OpenABE + run the PoC on the real backend
  build_openabe.sh          install the oabe_* CLI tools locally
```

### The two backends and the re-encryption check

The KEM here **encapsulates the randomness `R'` itself**; the KEM key is
`k = kdf(R')`. Algorithm 2's check `Encaps(AP, R') = c` is then realised in the
mathematically equivalent way that suits each backend:

* **Reference** ciphertexts are a *deterministic* function of `R'`, so the check
  is a literal byte-for-byte `Encaps(AP, R') == c` — the report's exact check.
* **OpenABE** encryption is *randomized*, so the check instead compares the
  *decapsulated* `R'` against the recomputed `F(H(R‖AP))`. This is equivalent by
  KEM correctness and never puts the secret randomness on the wire.

Both paths are exercised by the test suite (the reference path in the demo; the
seed-equality path is covered separately).

---

## 6. Faithfulness and honest limitations

This is a **proof of concept of the protocol**, so the CP-ABE primitive is a
building block sourced from OpenABE. Where the sandbox cannot build OpenABE, the
reference backend stands in — with limitations we state openly, several of which
mirror limitations the report itself records (Section 3.4):

* **Reference backend is a small-universe, non-collusion-resistant KEM.**
  Per-attribute keys are global rather than randomised per user, so two users
  could in principle pool attribute keys. Real collusion resistance comes from
  the pairing-based CP-WATERS-KEM — i.e. the **OpenABE backend**. For the
  properties demonstrated here (single-holder anonymity/unlinkability, replay,
  unforgeability against a non-holder, malicious-verifier rejection) the
  reference backend is faithful.
* **Time ranges are rendered as monthly `valid:<YYYY-MM>` slot attributes.**
  ETSI TS 103 964 compiles range predicates into the LSSS structure; we produce
  the same *effect* (expired ⇒ decryption fails, enforced inside the ABE layer)
  with coarse slots. Finer granularity is just more slot attributes.
* **The nullifier registry is an explicit set**, standing in for the report's
  *final* design (a pairing-based cryptographic accumulator, ETSI clause 4.3.4).
  The ratchet, one-wayness and the F2/F3/S7 logic are faithful; only the compact
  accumulator representation is simplified.
* **S1 channels are assumed** authenticated/confidential (as the report scopes
  them, and as the Tamarin model does); S6 authenticity of `mpk` and of the
  physician request is made concrete with Ed25519 signatures.
* **Not post-quantum**, consistent with the pairing-based construction and the
  report's own note.
* Trust concentration at the Authority (A1) is inherent to the design, as the
  report discusses; it is not "fixed" here.

---

## 7. References

* **[1]** ETSI. *Cyber Security (CYBER); A Verifiable Credentials extension using
  Attribute-Based Encryption.* TS 103 964 V1.1.1, Feb. 2025.
* **[2]** *A Kotlin multiplatform wrapper for OpenABE* —
  <https://github.com/StefanoBerlato/kotlin-multiplatform-openabe>
* **OpenABE** (Zeutro) — <https://github.com/zeutro/openabe>
