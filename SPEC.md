# vega-proof-of-need-sdk — Specification

Spec v1.0 — 2026-10-19 — describes the published reference implementation as tested; where this document and the source disagree, the source wins.

## 1. Purpose and scope

This specification covers the `vega_need` package (four modules: `constitution`, `analysis`, `book`, `income`) as implemented in `src/vega_need/` and tested in `tests/redteam_1_need.py`. It specifies the data structures, validation rules, state transitions, and guarantees that the reference implementation provides.

Out of scope: durable storage, real-money licensing/KYC/AML/COPPA, the freedom experiments, the saving-and-investing mechanic, mobile/embedded deployment, and any jurisdiction-specific legal minimums (those are defined by `vega-jurisdiction-sdk`).

## 2. Vocabulary

| Term | Definition |
|---|---|
| **constitution** | A versioned, co-signed document that defines parties, categories, want-signals, safety-net, and dispute method. |
| **party** | A signer with an id, role, and Ed25519 public key. |
| **category** | A named bucket with kind (NEED/WANT), keywords, monthly_cap_cents, payee rule (institution_only/any), evidence_required flag, and required approval roles. |
| **want_signals** | Lower-case words that indicate a request may be a want dressed as a need. |
| **safety_net** | Optional standing authority to release funds to institutions when approvers are unreachable for a configured time. |
| **dispute method** | `both_parties` (requester + decliner sign) or `arbiter` (named party signs). |
| **Record** | A constitution plus its signatures. `active` iff every party has a valid signature over this exact document. |
| **amendment** | A new constitution version (prev.version + 1, prev.digest = previous Record.digest) that starts unsigned. |
| **analysis** | An advisory classification (NEED/WANT/MIXED/UNCLEAR) with confidence 0.05–0.95, reasons, and flags. |
| **request** | A signed submission (category, amount_cents, payee, purpose, evidence hashes, nonce). Purpose text stays off-chain; only its SHA-256 is recorded. |
| **approval** | A signature by a required role (not the requester) over the request ID and the analysis flags hash. |
| **decline** | A signature by a required role (not the requester) over the request ID; blocks release. |
| **release** | State transition from `submitted`/`resolved_approved` to `released`; moves simulated balance; records chain entry. Requires all approvals, no declines, caps, balance, payee rule, evidence rule. Optional jacket Commit for `spend_funds`. |
| **safety_net_release** | Release via standing authority after timeout; institutions only; max cap; only for unanswered requests. |
| **proof_of_payment** | Institution signs receipt matching payee, amount, hash, time; mismatch records DISCREPANCY, returns `False`. |
| **income proof** | Pedersen commitment + issuer attestation + ZK range proof (at-least threshold, bound to context). Delegates to `vega_superproof.seal.zk`. |

## 3. Components

### 3.1 `constitution.py`

**Role**: Defines, validates, signs, and amends the co-signed rule set.

**Public interface**:
- `ConstitutionRefused` — exception for validation failures.
- `canonical(doc) -> bytes` — deterministic JSON serialization.
- `digest(doc) -> str` — SHA-256 of `VEGA-NEED-CONST-DOC-1|` + canonical(doc).
- `Party` — generates Ed25519 keypair; `sign(tag, text) -> hex`.
- `verify(public_hex, tag, text, sig_hex) -> bool` — validates Ed25519 signature; fail-closed.
- `_check(doc)` — validates structure, limits, cross-references; raises `ConstitutionRefused`.
- `Record(doc, sigs)` — holds doc, sigs, digest; `missing` property (list of unsigned parties); `active` property (bool); `sign_as(party_id, sig)` — adds valid signature.
- `amend(prev: Record, new_doc) -> Record` — only from active; version = prev+1; prev = prev.digest; returns unsigned Record.

**Behavior (guarantees on success)**:
- `Record.active` is true **iff** every party in `doc.parties` has a valid Ed25519 signature over the exact document digest with tag `CONST`.
- `amend` refuses if `prev` is not active, if version is not `prev.version + 1`, or if `prev` digest does not match.
- `_check` enforces: 2–12 parties, unique keys, valid roles; 1–40 categories, valid kinds/payee/evidence/cap/keywords/approvals; NEED categories require ≥1 approver; want_signals ≤100 lower-case words; safety_net if enabled requires institution-only categories, 1h–30d timeout, max 10^8 cents; dispute method valid, arbiter is a party; version ≥1, version 1 has no prev, later versions have valid prev digest.

**Behavior (on failure)**:
- Every validation failure raises `ConstitutionRefused` with a descriptive message. No partial state is committed.

**Invariants**:
- Single-use signatures: a signature is bound to one exact document digest.
- Non-transitive authority: a party's signature cannot be reused for another document.
- Append-only version chain: each amendment names the digest it replaces.

### 3.2 `analysis.py`

**Role**: Produces advisory need-vs-want classification from the constitution's own words.

**Public interface**:
- `AnalysisRefused` — exception for validation failures.
- `CLASSES = ("NEED", "WANT", "MIXED", "UNCLEAR")`
- `analyse(request: dict, doc: dict, institutions: set) -> dict` — rule-based analysis.
- `checked(result, name: str) -> dict` — validates and clamps a plugged-in analyser's output.

**Behavior (guarantees on success)**:
- `analyse` returns `{"analyzer": "rules-1", "classification": CLASSES, "confidence": 0.05–0.95, "flags": [...], "reasons": [...]}`.
- Confidence starts at 0.5; +0.2 for keyword match, +0.15 for evidence, -0.2 for missing required evidence, -0.25 per want_signal (if NEED category, adds `want_signal_in_need` flag), -0.3 for wrong payee type. Clamped to [0.05, 0.95].
- Classification logic: WANT kind → WANT; want signals + keywords → MIXED; want signals only → WANT; keywords or evidence → NEED; else UNCLEAR.
- `checked` validates classification ∈ CLASSES, confidence is a finite number, flags/reasons are short string lists (≤20 items, ≤300 chars each); clamps confidence to [0.05, 0.95]; records analyser name (truncated to 40 chars).

**Behavior (on failure)**:
- `AnalysisRefused` for unknown category, malformed plugged-in result, out-of-bounds confidence, oversized flags/reasons.

**Invariants**:
- Confidence never reaches 1.0 (advisory only).
- A want signal in a NEED category always produces `want_signal_in_need` flag.
- Plugged-in analyser never carries more weight than rule-based (same clamping).

### 3.3 `book.py`

**Role**: The book of need — requests, approvals, releases, receipts, disputes, simulated bankroll.

**Public interface**:
- `NeedRefused` — exception for validation failures.
- `NeedBook(dag, record, institutions, clock, commit, real_money=False, analyzer, analyzer_name)` — constructor.
- `deposit(party_id, cents, nonce, sig)` — signed deposit, fresh nonce, whole cents 1–10^8.
- `submit(party_id, category, amount_cents, payee, purpose, evidence, nonce, sig) -> request_id` — validated request; runs analysis; records `NEED_REQUEST` and `NEED_ANALYSIS`.
- `approve(request_id, party_id, sig)` — validates role, not requester, signature binds flags hash.
- `decline(request_id, party_id, sig)` — validates role, not requester; sets state `declined`.
- `release(request_id, signed=None)` — requires approvals, no declines, caps, balance, payee, evidence; optional jacket Commit for `spend_funds`; burn-then-record.
- `safety_net_release(request_id)` — constitution safety_net enabled, category listed, timeout elapsed, institution payee, max cap, no prior answers.
- `proof_of_payment(request_id, institution, receipt_hash, at, sig) -> bool` — verifies receipt matches release; returns `False` on mismatch (records DISCREPANCY).
- `overdue(after_seconds) -> list[request_id]` — released but unpaid past threshold.
- `dispute(request_id, party_id, reason, sig)` — only requester, only declined requests.
- `resolve(request_id, outcome, sigs: dict)` — per constitution method; required signers enforced.
- `report() -> dict` — balance, request state counts, spent_this_month, unpaid list.

**Behavior (guarantees on success)**:
- `real_money=True` refused at construction.
- Constructor refuses inactive constitution.
- Deposit: fresh nonce (8–64 chars), valid signature, cents 1–10^8; replay rejected.
- Request: category exists, amount 1–10^8, payee valid id, purpose 3–300 printable, evidence ≤10 hex64, nonce 8–64, valid signature; duplicate request_id rejected; analysis attached; purpose text never hits chain (only hash).
- Approval: role in category.approvals, not requester, signature over `request_id|flags_sha`.
- Decline: role in category.approvals, not requester; state → `declined`.
- Release: state ∈ {submitted, resolved_approved}; all required roles covered; no declines; amount ≤ balance; monthly cap not exceeded; payee rule satisfied; evidence rule satisfied; if `commit` configured, `signed` Commit for `spend_funds` with exact request/amount/payee required; chain entry written before balance decrement.
- Safety-net release: only for `submitted` with no approvals/declines; timeout elapsed; payee ∈ institutions; amount ≤ safety_net.max_cents; chain entry written.
- Proof of payment: release exists, not yet paid; institution matches payee; receipt hash valid; time integer; signature verifies; returns `True` on success, `False` on mismatch (records DISCREPANCY).
- Dispute: only requester, only declined state; reason 3–300 chars, signature over `request_id|sha256(reason)`.
- Resolve: state `disputed`; outcome ∈ {reverse_decline, uphold}; signers per constitution method (arbiter or both_parties); signatures over `request_id|outcome`; reverse_decline clears declines, state → `resolved_approved`.

**Behavior (on failure)**:
- Every validation failure raises `NeedRefused`; state unchanged; chain entry not written (or if chain write fails, balance not moved — see `test_if_the_chain_cannot_be_written_the_money_does_not_move`).

**Invariants**:
- Burn-then-record: chain entry written before balance moves.
- Single-use: request released once; receipt accepted once; Commit single-use.
- Decline is final unless resolved per constitution.
- Monthly cap tracked per `(category, month_window)`.
- Purpose text never in chain.

### 3.4 `income.py`

**Role**: Privacy-preserving proof that a hidden number ≥ threshold, vouched by issuer.

**Public interface**:
- `IncomeRefused` — exception (unused in current code; delegates to zk).
- `issue(issuer_private, value: int, label: str) -> (commitment: bytes, blinding: int, attestation: str)` — Pedersen commit + attestation via `zk`.
- `prove_at_least(value: int, blinding: int, threshold: int, bits: int, context: bytes) -> dict` — ZK proof via `zk.prove_at_least`.
- `verify_at_least(issuer_public: bytes, commitment: bytes, label: str, attestation: str, threshold: int, bits: int, proof, context: bytes) -> bool` — verifies attestation + ZK proof.

**Behavior (guarantees on success)**:
- Delegates to `vega_superproof.seal.zk` (classical security, not quantum-proof, plain Python, not independently reviewed).
- Proof reveals nothing about `value` beyond `value ≥ threshold`.
- Proof bound to `context` (e.g., `b"for:landlord-1|2026-10"`); different context → verification fails.
- Issuer attestation binds commitment to `label`; different label → verification fails.
- Different issuer key → verification fails.
- Different commitment → verification fails.

**Behavior (on failure)**:
- `zk.ZKRefused` if threshold > value (no honest proof possible).
- `verify_at_least` returns `False` on any mismatch.

**Invariants**:
- Zero-knowledge: verifier learns only that `value ≥ threshold`.
- Context binding prevents replay across verifiers/scenarios.
- Issuer attestation binds the commitment to a semantic label.

## 4. Guarantees and non-guarantees

### Guarantees

| Guarantee | Module | Test demonstrating it |
|---|---|---|
| Constitution active iff every party signed exact document | `constitution.Record` | `test_it_is_active_only_when_every_party_signed_this_exact_document` |
| Amendment only from active, version monotonic, prev digest matches | `constitution.amend` | `test_an_amendment_is_the_next_version_and_everyone_signs_again` |
| Malformed constitutions refused | `constitution._check` | `test_malformed_constitutions_are_refused` |
| Advisory classification with clamped confidence, want signals flagged | `analysis.analyse` | `test_a_plain_need_is_a_need_with_reasons_and_never_full_confidence`, `test_a_want_dressed_as_a_need_is_flagged_and_loses_confidence` |
| Plugged-in analyser validated and clamped | `analysis.checked` | `test_a_plugged_in_analyser_is_validated_and_clamped` |
| No real money accepted | `NeedBook.__init__` | `test_no_real_money_and_no_inactive_constitution` |
| Deposits signed, fresh nonce, whole cents, replay rejected | `NeedBook.deposit` | `test_deposits_are_signed_fresh_and_counted_in_whole_cents` |
| Requests validated, signed, analysed, purpose off-chain | `NeedBook.submit` | `test_requests_are_validated_signed_and_analysed_and_the_purpose_stays_off_the_chain` |
| Duplicate requests rejected | `NeedBook.submit` | `test_the_same_request_cannot_be_submitted_twice` |
| Pluggable analyser cannot approve; crashing analyser blocks request | `NeedBook.submit` | `test_a_pluggable_analyser_cannot_approve_and_a_crashing_one_blocks_the_request` |
| Approvals from required roles only, never requester, bind flags | `NeedBook.approve` | `test_approvals_come_from_the_right_roles_never_the_requester_and_are_bound_to_the_flags_seen` |
| Release needs all approvals, no declines | `NeedBook.release` | `test_a_release_needs_every_required_role_and_no_decline` |
| Caps, balance, payee rule, evidence rule enforced | `NeedBook.release` | `test_the_caps_the_balance_the_payee_rule_and_the_evidence_rule` |
| WANT category runs to cap without approvals | `NeedBook.release` | `test_a_want_category_with_no_approver_runs_only_to_its_cap` |
| Jacket Commit required for spend_funds, single-use, bound to request | `NeedBook.release` | `test_with_a_jacket_the_release_needs_the_owners_human_commitment_for_exactly_this_request` |
| Safety net: institutions only, after timeout, max cap, no prior answers | `NeedBook.safety_net_release` | `test_the_safety_net_pays_institutions_only_after_the_wait_and_never_over_a_decline` |
| Receipt matches payee, amount, hash, signature | `NeedBook.proof_of_payment` | `test_a_receipt_from_the_right_institution_for_the_right_amount_marks_it_paid` |
| Disputes follow constitution method | `NeedBook.dispute/resolve` | `test_disputes_follow_the_constitutions_method`, `test_the_arbiter_method` |
| Chain intact; report adds up | `NeedBook.report`, `dag.verify` | `test_the_chain_is_intact_and_the_report_adds_up` |
| Chain write failure → money does not move | `NeedBook.release` | `test_if_the_chain_cannot_be_written_the_money_does_not_move` |
| Income proof: at-least without revealing number, bound to issuer/context | `income` | `test_at_least_is_proved_without_the_number_and_bound_to_the_issuer_and_context` |

### Non-guarantees

| Non-guarantee | Explanation |
|---|---|
| Real-money safety | `real_money=True` refused; no KYC/AML/custody/COPPA cleared. |
| Independent security review | Not done; automated review + 2 red-team passes only. |
| Cryptographic expert review | Ed25519 and ZK use plain Python libraries; not independently reviewed. |
| OS-level containment | Process-level only; compromised process bypasses gates. |
| Legal advice | Licence draft not reviewed by attorney; minor assent ≠ legal consent. |
| Income truth | Proof shows range; issuer's word on underlying fact. |
| Durable storage | In-memory only; real system needs persistence. |
| Freedom experiments / savings | DESIGNED ONLY — not built. |

## 5. Failure modes

| Failure mode | Behavior | Test |
|---|---|---|
| Tampered constitution | `Record.active` false; `missing` lists all parties; amendment refused | `test_it_is_active_only_when_every_party_signed_this_exact_document` |
| Missing commitment (release with jacket) | `NeedRefused` — "this book needs the device owner's human commitment" | `test_with_a_jacket_the_release_needs_the_owners_human_commitment_for_exactly_this_request` |
| Expired/reused commitment | `CommitRefused` → `NeedRefused` | Same test |
| Replay (deposit nonce, request, commitment) | `NeedRefused` — duplicate rejected | `test_deposits_are_signed_fresh_and_counted_in_whole_cents`, `test_the_same_request_cannot_be_submitted_twice`, jacket test |
| Corrupt record (chain write fail) | `NeedRefused` from `_event`; balance unchanged; state unchanged | `test_if_the_chain_cannot_be_written_the_money_does_not_move` |
| Wrong payee / amount / institution on receipt | `proof_of_payment` returns `False`; DISCREPANCY recorded | `test_a_receipt_from_the_right_institution_for_the_right_amount_marks_it_paid` |
| Declined request released | `NeedRefused` — "a party declined" | `test_a_release_needs_every_required_role_and_no_decline` |
| Safety net over decline | `NeedRefused` — "the safety net is only for a request nobody has answered" | `test_the_safety_net_pays_institutions_only_after_the_wait_and_never_over_a_decline` |
| Income proof below threshold | `zk.ZKRefused` — no honest proof | `test_at_least_is_proved_without_the_number_and_bound_to_the_issuer_and_context` |

## 6. Dependencies and layer rules

Registry entry (verbatim from `vega-umbrella-sdk`):
```
vega-proof-of-need-sdk: {layer: "proof-of-need", requires: ["custody", "jacket", "superproof", "identity"]}
```

Dependencies point down layers only (custody=0, jacket=1, superproof=2, identity=3), never up or sideways. No cycles. This SDK owns exactly one concern: **proof of need and proof of payment**.

## 7. Conformance

A third party can verify conformance by:
1. Installing the SDK and its declared dependencies.
2. Running `python -m unittest tests.redteam_1_need -v` — all 32 tests must pass.
3. Running the mutation test: `python tests/mutations_need.py` — 0 survivors expected for a fully mutation-resistant build (currently 4 survivors documented).

**What passing means**: The reference implementation behaves as specified for the tested scenarios (constitution lifecycle, analysis rules, book flow, income proofs). The guarantees in §4 hold for the code paths exercised by the tests.

**What passing does NOT mean**: No independent security review; no production hardening; no real-money readiness; no legal compliance; no durability guarantees; no protection against compromised host/OS; no quantum-resistant cryptography; no guarantee that mutation survivors don't indicate real bugs (4 currently documented).