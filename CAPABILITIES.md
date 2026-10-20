# vega-proof-of-need-sdk — Capabilities

Deep capability brief per owner directive 2026-10-18: per-capability inventory (capability / why a policy-or-prompt-level approach structurally cannot provide it / where enforced in this repo's code / which test file demonstrates it / honest limit), closing with this repo's part in the family predictive loop.

## 1. Co-signed constitution lifecycle

| Aspect | Detail |
|---|---|
| **Capability** | A transparent rule set (parties, categories, caps, want-signals, safety-net, dispute method) that takes effect **only when every party has signed the exact document hash**. Amendments require a new version (monotonic, names previous digest) and **every party signs again**. |
| **Why policy/prompt cannot provide it** | A prompt or policy is a unilateral declaration. It can be ignored, overridden, or hallucinated around by the model. Co-signing requires cryptographic proof that each named human authorized this exact document; a model cannot forge Ed25519 signatures without the private keys (which never leave the human's device). |
| **Where enforced in code** | `constitution.Record.active` property (`constitution.py:133-135`): `not self.missing` where `missing` lists parties whose `verify(public, "CONST", digest, sig)` fails. `constitution.amend` (`constitution.py:144-150`) refuses if `prev.active` is false, version not `prev+1`, or `prev` digest mismatch. |
| **Test demonstrating it** | `tests/redteam_1_need.py::ConstitutionTests::test_it_is_active_only_when_every_party_signed_this_exact_document`, `test_an_amendment_is_the_next_version_and_everyone_signs_again`, `test_malformed_constitutions_are_refused` |
| **Honest limit** | A minor's signature is an assent, not legal consent (code cannot answer who may sign for whom). The constitution governs only requests that parties choose to submit; it does not surveil or control off-ledger behavior. |

## 2. Advisory need analysis with clamped confidence and want-signal flagging

| Aspect | Detail |
|---|---|
| **Capability** | Rule-based classification (NEED/WANT/MIXED/UNCLEAR) derived **only from the constitution's own words** (category keywords, want_signals, evidence_required, payee rule). Confidence **never exceeds 0.95** (clamped). Want signals in a NEED category produce `want_signal_in_need` flag. A pluggable model analyser is **validated and clamped to the same bounds** — its opinion never carries more weight than the rule-based one. |
| **Why policy/prompt cannot provide it** | A prompt asking "is this a need?" gives a single answer with no audit trail, no binding to the written rules, no confidence bound, and no flag for want signals. The model can be steered to say "yes" regardless of the actual category definitions. This code applies the rules mechanically and records the reasoning; the model cannot suppress the `want_signal_in_need` flag. |
| **Where enforced in code** | `analysis.analyse` (`analysis.py:21-62`): computes confidence from keyword matches, evidence, want signals, payee rule; clamps to [0.05, 0.95]; sets `want_signal_in_need` flag when `cat["kind"] == "NEED"` and want signals present. `analysis.checked` (`analysis.py:65-75`): validates plugged-in result shape, clamps confidence, records analyser name. |
| **Test demonstrating it** | `tests/redteam_1_need.py::AnalysisTests::test_a_plain_need_is_a_need_with_reasons_and_never_full_confidence`, `test_a_want_dressed_as_a_need_is_flagged_and_loses_confidence`, `test_a_plugged_in_analyser_is_validated_and_clamped` |
| **Honest limit** | Advisory only — **does not approve anything**. Confidence is a heuristic, not a probability. The rule-based analyser only sees the request text; it has no external context. A model analyser is clamped but not audited for alignment. |

## 3. Human-approved releases from a simulated bankroll with burn-then-record

| Aspect | Detail |
|---|---|
| **Capability** | Requests are submitted signed, analysed, then **approved by required roles (not the requester) with signatures binding the analysis flags they saw**. Any decline blocks release. Release requires **all approvals, no declines, monthly cap, balance, payee rule, evidence rule**. Optional `vega-governance-jacket-sdk` Commit for `spend_funds` — single-use, bound to exact request/amount/payee. **Burn-then-record**: chain entry written before simulated balance moves. |
| **Why policy/prompt cannot provide it** | A prompt saying "only release with approval" is enforceable only by the model's willingness to obey. The model can ignore it, hallucinate approvals, or be tricked into releasing. This code **requires cryptographic signatures from the required roles**, verifies them against the constitution's role list, binds them to the flags hash, and **refuses release if any check fails**. The jacket Commit adds a human's single-use signature that the model cannot mint. The burn-then-record order prevents "money moved but chain failed" inconsistency. |
| **Where enforced in code** | `book.NeedBook.approve` (`book.py:135-148`): verifies role ∈ category.approvals, party ≠ requester, signature over `request_id|flags_sha`. `decline` (`book.py:149-160`): same role check, sets `declined`. `release` (`book.py:190-208`): checks `_roles_covered`, `declines`, `_check_release` (balance, cap, payee, evidence), optional jacket Commit; `_do_release` writes `NEED_RELEASE` event **before** `balance -= amount`. `safety_net_release` (`book.py:210-224`): strict conditions (timeout, institution, max, no prior answers). |
| **Test demonstrating it** | `tests/redteam_1_need.py::BookTests::test_a_release_needs_every_required_role_and_no_decline`, `test_the_caps_the_balance_the_payee_rule_and_the_evidence_rule`, `test_with_a_jacket_the_release_needs_the_owners_human_commitment_for_exactly_this_request`, `test_the_safety_net_pays_institutions_only_after_the_wait_and_never_over_a_decline`, `test_if_the_chain_cannot_be_written_the_money_does_not_move` |
| **Honest limit** | **NO REAL MONEY** — balances are in-memory integers. Real money needs licensing, KYC/AML, custody, COPPA — none cleared. The jacket Commit is only as strong as the human's key security. Mutation testing shows 3 survivors in this area: `decline blocks release`, `released once`, `human commitment required` (mutation test did not kill these — see mutation report). |

## 4. Institution receipts with discrepancy recording

| Aspect | Detail |
|---|---|
| **Capability** | After release, the payee institution signs a receipt (`request_id|amount|receipt_hash|time`). `proof_of_payment` verifies the signature **and** that the institution matches the release payee, the amount matches, the hash matches, and the time is valid. **Mismatches return `False` and record `NEED_DISCREPANCY`**; the release stays unpaid. Only one receipt accepted per release. |
| **Why policy/prompt cannot provide it** | A prompt "verify the receipt" relies on the model to check all fields correctly and not be tricked. This code **mechanically verifies every field** (payee match, amount match, hash match, time integer, Ed25519 signature) and **records every mismatch** in the immutable chain. The model cannot suppress the discrepancy event. |
| **Where enforced in code** | `book.NeedBook.proof_of_payment` (`book.py:227-244`): checks `rel["paid"]` false, institution = `r["payee"]`, `receipt_hash` hex64, `at` integer, `C.verify(pub, "RECEIPT", text, sig)`; on failure → `NEED_DISCREPANCY` event + return `False`; on success → `rel["paid"]=True`, `state="paid"`, `NEED_PAID` event. |
| **Test demonstrating it** | `tests/redteam_1_need.py::BookTests::test_a_receipt_from_the_right_institution_for_the_right_amount_marks_it_paid` (verifies 3 discrepancies recorded for wrong institution/wrong amount/wrong signer) |
| **Honest limit** | Receipt hash is provided by the institution; the SDK does not verify the underlying invoice/document. The institution's key must be registered at `NeedBook` construction. |

## 5. Constitution-governed disputes with two resolution methods

| Aspect | Detail |
|---|---|
| **Capability** | Disputes only on **declined** requests, only by the **requester**, with a signed reason. Resolution follows the constitution's method: `both_parties` (requester + decliner sign) or `arbiter` (named party signs). Outcome `reverse_decline` clears declines and allows re-release; `uphold` finalizes decline. Required signers enforced mechanically. |
| **Why policy/prompt cannot provide it** | A prompt "let them dispute" has no enforcement — the model can ignore the dispute, accept a fake resolution, or allow the wrong parties to sign. This code **requires signatures from exactly the parties the constitution names**, over `request_id|outcome`, and **refuses resolution if the signer set is wrong**. |
| **Where enforced in code** | `book.NeedBook.dispute` (`book.py:251-260`): validates state=`declined`, party=requester, reason 3-300 chars, signature over `request_id|sha256(reason)`. `resolve` (`book.py:262-274`): computes `needed` signers from constitution (`arbiter` or `{requester} ∪ declines`), verifies all signatures over `request_id|outcome`; `reverse_decline` → clears declines, state=`resolved_approved`. |
| **Test demonstrating it** | `tests/redteam_1_need.py::BookTests::test_disputes_follow_the_constitutions_method`, `test_the_arbiter_method` |
| **Honest limit** | The constitution's dispute method is fixed at creation; changing it requires an amendment (all parties sign again). No external arbitration or court integration. |

## 6. Privacy-preserving proof of income (ZK range proof)

| Aspect | Detail |
|---|---|
| **Capability** | An issuer (employer, bank) commits to a hidden number with a **Pedersen commitment** and signs the commitment with a label (e.g., `monthly_income_cents`). The holder proves in **zero knowledge** that the committed number ≥ threshold, **bound to a context** (who, when). The verifier checks the issuer's attestation + ZK proof; **the number is never revealed**. |
| **Why policy/prompt cannot provide it** | A prompt "prove you earn at least X" requires revealing the number or trusting the model's claim. This code uses **cryptographic commitments and ZK proofs** (via `vega_superproof.seal.zk`) where the verifier learns only `value ≥ threshold`, nothing else. The proof is bound to a context string preventing replay across verifiers. |
| **Where enforced in code** | `income.issue` (`income.py:14-17`): `zk.commit(value)` + `zk.attest(issuer_private, commitment, label)`. `prove_at_least` (`income.py:20-21`): `zk.prove_at_least(value, blinding, threshold, bits, context)`. `verify_at_least` (`income.py:24-25`): `zk.verify_attestation` + `zk.verify_at_least`. |
| **Test demonstrating it** | `tests/redteam_1_need.py::IncomeTests::test_at_least_is_proved_without_the_number_and_bound_to_the_issuer_and_context` (verifies proof works for 4200 ≥ 3000, fails for 3001, fails for different context, fails for different label, fails for different issuer, fails for different commitment) |
| **Honest limit** | **Classical security only** (not quantum-proof). **Plain Python, not independently reviewed**. The proof shows the number is in range; **whether the number is TRUE is the issuer's word** — the SDK does not verify the issuer's honesty. Do not put real financial figures through this before expert review. |

## 7. Family predictive loop — this repo's part

Per `ORGANISM_MAP.md`, the family predictive loop runs:

```
custody records → librarian distils lessons → dkg-lattice builds knowledge graph (origin + licence per fact)
  → reasoning/galaxy forecast from the lattice
  → harness pre-registers predicted paths
  → metacog gates completion on evidence
  → feed/galaxy show it all to the human, who decides again
```

**This repo's contribution:**

| Stage | This repo's role |
|---|---|
| **Records** | `NeedBook` writes `NEED_*` events to `vega_custody.dag.Dag` — every deposit, request, analysis, approval, decline, release, safety-net, receipt, discrepancy, dispute, resolution. Chain is hash-chained; `dag.verify()` proves integrity. |
| **Lessons** | Not directly produced here; `vega-librarian-sdk` (layer 5) would consume `NEED_*` events to distil patterns (e.g., recurring want signals, cap breaches, safety-net triggers). |
| **Knowledge graph** | `vega-dkg-lattice-sdk` (layer 7) would ingest constitution definitions, category rules, and outcome patterns as facts with origin (which constitution version, which parties) and licence (family internal). |
| **Reasoning/forecast** | `vega-reasoning-sdk` (layer 11) / `vega-galaxy-sdk` could forecast: "given this constitution and history, next month's school cap will be hit with 80% probability" or "safety-net likely to trigger for medical category." |
| **Harness pre-registration** | `vega-harness-sdk` (layer 6) could pre-register predicted paths for common request flows (e.g., "school tuition → guardian approval → release → school receipt"). |
| **Metacog gating** | `vega-metacog-sdk` (layer 12) would demand evidence rungs before a release completes (already enforced by `evidence_required` flag in constitution). |
| **Feed/galaxy → human** | `vega-governance-feed-sdk` (layer 13) / `vega-galaxy-sdk` would show the human: "Sam's school request approved by mum, released $100, school receipt pending" — the human decides next (e.g., amend constitution, adjust caps). |

**This repo does NOT**: run the lattice, produce predictions, or gate completions. It **provides the tamper-evident event stream** that the upper layers consume. The authority to decide stays with the human (via constitution amendments, jacket commitments, dispute resolutions).

## 8. A category of its own: honest differentiation

This SDK is not a budgeting app, a parental control tool, or a payment processor. It is a **governance primitive** for "proof of need and proof of payment" with these architectural differentiators:

| Differentiator | What THIS design does |
|---|---|
| **Governance-first (authority outside the model)** | The model (or any automated process) **never holds the signing keys**. Human commitments (`vega-governance-jacket-sdk`) and party signatures (`constitution.Record`) are verified by code the model cannot bypass. Authority is single-use and non-transitive — a model cannot mint or widen it. |
| **Deterministic conductor (no model in the loop)** | `NeedBook` state transitions are pure functions of signatures and rules. No LLM decides "approved" — the cryptographic checks do. |
| **Pre-registered predicted paths** | The constitution **is** the pre-registered path: categories, caps, approvers, payee rules, evidence rules, safety-net, dispute method are all declared upfront and co-signed. |
| **Single-use human commitments** | `spend_funds` Commit is consumed on release; cannot be replayed for another request/amount/payee. |
| **Chain-of-custody by default** | Every state change is a `NEED_*` event in a hash-chained DAG. `dag.verify()` proves the complete history without trusting the model, the vendor, or the project. |
| **Lattice-informed foresight** | The event stream feeds `vega-dkg-lattice-sdk` → `vega-reasoning-sdk` → `vega-harness-sdk` → `vega-metacog-sdk` → `vega-governance-feed-sdk` for human decision support. |

> Every differentiation claim above is phrased as what THIS design does. The argument that "authority held outside the model cannot be replicated by prompt-level policy" follows from the architecture (single-use signed commitments verified by deterministic gates) — not from characterizing any competitor's product.

---

**Patent pending (U.S. provisional application 64/178,949 and others).** This document describes the design and the reference code. It makes no claim about any particular deployment.
