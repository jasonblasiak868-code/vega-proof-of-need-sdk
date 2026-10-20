# vega-proof-of-need-sdk — Architecture

## 1. The organism (family picture)

The Vega SDK family is a 16-layer stack (0 = foundation, 15 = assembly). This repo is a **companion SDK** (layer `proof-of-need`) that consumes down-layer SDKs but is not in the public 17-repo stack.

```
                 ┌──────────────────────────┐
                 │   THE HUMAN (the owner)  │  holds the only signing key;
                 │  authority starts here   │  spends it one action at a time
                 └────────────┬─────────────┘
                              v single-use signed commitments
 15 assemble   vega-umbrella-sdk        the family as one organism: one keyed
                                        ledger, one approval check, one anchor,
                                        registry + pre-deploy audit
 14 deliberate vega-council-sdk         multi-brain deliberation, design-first builder
               vega-galaxy-sdk          the galaxy view of the knowledge lattice:
                                        levels, convergence, futures above the present
 13 watch      vega-governance-feed-sdk  live view of every chain + tamper alarms
 12 verify     vega-metacog-sdk          evidence rungs and the completion gate
 11 reason     vega-reasoning-sdk        fidelity, forecasting, routing: the lattice
                                        that predicts steps ahead
 10 observe    vega-trace-sdk            telemetry of reasoning: layer traces, entropy,
                                        harmonic echo, reference signature
  9 interface  vega-terminal-sdk         gated command execution for people and agents
  8 learn      vega-train-sdk            governed training + freeze cards: records
                                        exactly what a model learned from
  7 knowledge  vega-dkg-lattice-sdk      the knowledge graph: every fact with origin
                                        and licence; repo-library processing
  6 conduct    vega-harness-sdk          deterministic workflow conduct, pre-registered
                                        predicted paths, library use gate
  5 memory     vega-librarian-sdk        lessons and memory of past incidents
  4 contain    vega-two-gate-sdk         containment between two gates + the hard stop
  3 adapt      vega-pareah-sdk            adapters, cards, quarantine of inbound code:
                                        the dead-end room for the unannounced
  2 seal       vega-superproof-sdk       layered sealing and proof tiers  <<< DEPENDS
  1 authority  vega-governance-jacket-sdk human-only actions, single-use signed
                                        commitments, entry and exit gates   <<< DEPENDS
  0 record     vega-custody-sdk          capsules, DAG, hash-chained ledger, safe paths,
                                        bounded processes — the foundation  <<< DEPENDS
```

**This repo (proof-of-need) depends on (down-layer only):**
- **vega-custody-sdk** (layer 0): DAG/ledger for immutable event chain (`NEED_*` events), `dag.verify()` for integrity.
- **vega-governance-jacket-sdk** (layer 1): `Commit` for human `spend_funds` commitments; single-use, bound to exact request/amount/payee.
- **vega-superproof-sdk** (layer 2): `zk` module for Pedersen commitments and ZK range proofs (income proofs).
- **vega-identity-sdk** (layer 3): Institution identity (public keys) for receipt verification.

**Who consumes this**: Not yet integrated into the public stack; designed as a companion for need/payment governance use cases.

> One family, one organism: every SDK owns exactly one concern and uses the owner of every other concern instead of growing its own copy.

## 2. Internal drawing (ASCII box diagram)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           vega_need (this SDK)                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌───────────┐  │
│  │ constitution │    │  analysis    │    │    book      │    │  income   │  │
│  │              │    │              │    │              │    │           │  │
│  │ Record       │    │ analyse()    │    │ NeedBook     │    │ issue()   │  │
│  │   .active    │    │ checked()    │    │   .deposit() │    │ prove_    │  │
│  │   .missing   │    │              │    │   .submit()  │    │   at_least│  │
│  │   .sign_as() │    │ flags:       │    │   .approve() │    │ verify_   │  │
│  │   .amend()   │    │   want_      │    │   .decline() │    │   at_least│  │
│  │              │    │   signal_    │    │   .release() │    │           │  │
│  │ parties,     │    │   in_need    │    │   .safety_   │    │ uses      │  │
│  │ categories,  │    │   evidence_  │    │   net_release│    │ vega_     │  │
│  │ want_signals,│    │   missing    │    │   .proof_of_ │    │ superproof│  │
│  │ safety_net,  │    │   payee_not_ │    │   payment()  │    │ .seal.zk  │  │
│  │ dispute,     │    │   an_        │    │   .overdue() │    │           │  │
│  │ version, prev│    │   institution│    │   .dispute() │    │           │  │
│  └──────┬───────┘    └──────┬───────┘    │   .resolve() │    └───────────┘  │
│         │                   │            │   .report()  │                   │
│         │                   │            └──────┬───────┘                   │
│         │                   │                   │                           │
│         ▼                   ▼                   ▼                           │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         DATA FLOW                                    │   │
│  │  constitution.Record  ──►  analysis.analyse()  ──►  NeedBook        │   │
│  │     (active?)              (advisory)            .submit()          │   │
│  │                                │                  │                  │   │
│  │                                ▼                  ▼                  │   │
│  │                         NEED_ANALYSIS         NEED_REQUEST          │   │
│  │                            event                  event              │   │
│  │                                │                  │                  │   │
│  │                                ▼                  ▼                  │   │
│  │                      approvals/declines      releases/safety-net    │   │
│  │                         (signatures)          (burn-then-record)    │   │
│  │                                │                  │                  │   │
│  │                                ▼                  ▼                  │   │
│  │                         NEED_APPROVAL/        NEED_RELEASE/         │   │
│  │                         NEED_DECLINE          NEED_DISCREPANCY/     │   │
│  │                                                NEED_PAID            │   │
│  │                                │                  │                  │   │
│  │                                ▼                  ▼                  │   │
│  │                         disputes/resolves    overdue/report         │   │
│  │                         NEED_DISPUTE/        NEED_RESOLVED          │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         AUTHORITY FLOW                               │   │
│  │  Human (jacket Commit) ──► spend_funds ──► NeedBook.release()       │   │
│  │       │                                    │                          │   │
│  │       ▼                                    ▼                          │   │
│  │  single-use, bound to              chain entry written               │   │
│  │  exact request/amount/payee        BEFORE balance moves              │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Module names match real `src/vega_need/` files:**
- `constitution.py` → `Constitution`, `Record`, `Party`, `amend`, `verify`
- `analysis.py` → `analyse`, `checked`, `CLASSES`
- `book.py` → `NeedBook`, `NeedRefused`
- `income.py` → `issue`, `prove_at_least`, `verify_at_least`

## 3. Mermaid version of internal diagram

```mermaid
graph TD
    A[Constitution Record] -->|active?| B(Analysis)
    B -->|advisory: class/conf/flags| C[NeedBook.submit]
    C -->|NEED_REQUEST + NEED_ANALYSIS| D[DAG/Chain]
    C -->|approvals/declines| E[NeedBook.approve/decline]
    E -->|NEED_APPROVAL/NEED_DECLINE| D
    E -->|all approvals, no declines| F[NeedBook.release]
    F -->|jacket Commit?| G[Human spend_funds Commit]
    G -->|single-use, bound| F
    F -->|burn-then-record| D
    F -->|NEED_RELEASE| D
    F -->|safety_net_release| H[NeedBook.safety_net_release]
    H -->|timeout, institutions, max| D
    F -->|proof_of_payment| I[NeedBook.proof_of_payment]
    I -->|match?| J[NEED_PAID or NEED_DISCREPANCY]
    J --> D
    E -->|decline| K[NeedBook.dispute]
    K -->|requester only| L[NeedBook.resolve]
    L -->|constitution method| M[NEED_RESOLVED]
    M --> D
    D -->|verify()| N[Chain Integrity]
    O[Income] -->|issue/prove/verify| P[vega_superproof.seal.zk]
```

## 4. Sequence: main scenario end to end

**Scenario**: A party submits a school-tuition request; guardians approve; human commits; release; institution receipts.

```
Human (owner)                    Party (sam)              Guardian (mum)           Guardian (dad)           Institution (school)      DAG/Chain
    │                              │                          │                        │                        │                         │
    │                              │  submit(request)         │                        │                        │                         │
    │                              │─────────────────────────►│                        │                        │                         │
    │                              │                          │                        │                        │                         │
    │                              │                          │  approve(request,      │                        │                         │
    │                              │                          │  flags_sha)            │                        │                         │
    │                              │                          │◄───────────────────────│                        │                         │
    │                              │                          │                        │  approve(request,      │                         │
    │                              │                          │                        │  flags_sha)            │                         │
    │                              │                          │                        │◄───────────────────────│                         │
    │                              │                          │                        │                        │                         │
    │  commit(spend_funds,         │                          │                        │                        │                         │
    │  {request, amount, payee})   │                          │                        │                        │                         │
    │◄─────────────────────────────│                          │                        │                        │                         │
    │                              │                          │                        │                        │                         │
    │                              │  release(request,        │                        │                        │                         │
    │                              │  commit)                 │                        │                        │                         │
    │                              │─────────────────────────►│                        │                        │                         │
    │                              │                          │                        │                        │                         │
    │                              │                          │                        │                        │                         │
    │                              │                    NEED_RELEASE event             │                         │
    │                              │                          │                        │                        │  receipt(request,       │
    │                              │                          │                        │                        │  amount, hash, time)    │
    │                              │                          │                        │                        │◄───────────────────────│
    │                              │                          │                        │                        │                         │
    │                              │  proof_of_payment(       │                        │                        │                         │
    │                              │  receipt)                │                        │                        │                         │
    │                              │─────────────────────────►│                        │                        │                         │
    │                              │                          │                        │                        │                         │
    │                              │                    NEED_PAID event                │                         │
```

## 5. Trust boundaries

| Boundary | What crosses | Enforcement |
|---|---|---|
| **Human → Model** | Signed `Commit` for `spend_funds` | `vega-governance-jacket-sdk` verifies human signature; model never holds signing key; commitment single-use, bound to exact request/amount/payee. |
| **Model → Constitution** | Request text, approvals, declines | `constitution.verify()` validates Ed25519 signatures over exact digests; `Record.active` requires every party; `amend` requires version monotonicity + prev digest. |
| **Constitution → Analysis** | Category keywords, want_signals, evidence rules | `analysis.analyse()` applies constitution's own words; confidence clamped [0.05, 0.95]; `want_signal_in_need` flag on NEED categories. |
| **Analysis → Book** | Classification, confidence, flags | `NeedBook.submit()` runs analysis (rule-based or plugged-in validated by `checked()`); flags hash bound to approval signatures. |
| **Book → DAG/Ledger** | All `NEED_*` events | `vega_custody.dag.Dag` append-only; `dag.verify()` returns chain integrity; burn-then-record (chain entry before balance move). |
| **Book → Jacket** | `spend_funds` commitment | `vega_jacket.commit.Commit` verifies human commitment; `CommitRefused` → `NeedRefused`; single-use enforced by jacket. |
| **Book → Institutions** | Receipt verification | `NeedBook.proof_of_payment()` verifies institution Ed25519 signature over `request|amount|hash|time`; mismatch → `False` + `NEED_DISCREPANCY`. |
| **Income → Superproof** | Pedersen commitment, ZK proof | `vega_superproof.seal.zk` — classical security, not quantum-proof, not independently reviewed; proof bound to context. |
| **This SDK → Down-layer SDKs** | All external calls | Dependencies point down only (custody, jacket, superproof, identity); no up/sideways imports; no cycles. |

## 6. Fail-closed constraint points (computational workflow)

```
┌────────────────────────────────────────────────────────────────────────────────────┐
│                        FAIL-CLOSED CONSTRAINT POINTS                               │
├────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                    │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐ │
│  │ Constitution│    │   Analysis  │    │   Request   │    │    Approval         │ │
│  │  Record     │    │             │    │   Submit    │    │                     │ │
│  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘    └──────────┬──────────┘ │
│         │                  │                  │                        │           │
│         ▼                  ▼                  ▼                        ▼           │
│  [CONST-1] Active?      [AN-1] Classify     [REQ-1] Valid?           [APP-1]     │
│  │ active=True  │       │ confidence        │ category exists        │ Role ok?  │
│  │              │       │ ∈ [0.05,0.95]     │ amount 1..1e8          │ Not self? │
│  └──────┬──────┘       │ want_signal       │ payee valid            │ Sig ok?   │
│         │              │ flagged           │ purpose 3..300 print   │ Binds     │
│         ▼              │ plugged-in        │ evidence ≤10 hex64     │ flags_sha?│
│  [CONST-2] Amendment?  │ clamped           │ nonce 8..64 fresh      └─────┬─────┘
│  │ prev.active  │      └──────┬───────────┘ sig over digest            │
│  │ version+1    │             │                                         ▼
│  │ prev=digest  │             ▼                              [APP-2] Decline?
│  └──────┬──────┘       [AN-2] Plugged-in                   │ blocks release
│         │              │ validated?                         │
│         ▼              │ clamped?                           ▼
│  [CONST-3] Sign?     └──────┬───────────┘           [REL-1] Release?
│  │ verify(pub,  │             │                      │ all approvals?
│  │  tag, text,  │             ▼                      │ no declines?
│  │  sig)        │       [REQ-2] Duplicate?            │ caps ok?
│  └──────┬──────┘       │ request_id exists?           │ balance ok?
│         │              └──────┬───────────┘            │ payee rule?
│         ▼                     │                        │ evidence rule?
│  [CONST-4] All    [REQ-3] Analysis?                  │ jacket Commit?
│  │ signed?     │  rule-based or plugged-in             └──────┬───────┘
│  └─────────────┘  (validated/clamped)                      │
│                   │                                        ▼
│                   ▼                               [REL-2] Safety Net?
│             [REQ-4] Purpose off-chain?              │ timeout elapsed?
│             │ hash only on chain                   │ institution payee?
│             ▼                                      │ max cap?
│             [REQ-5] Chain write?                   │ no prior answers?
│             │ fail → no balance move               └──────┬───────┘
│             ▼                                           │
│       [CHAIN-1] dag.record()                         ▼
│       │ NEED_REQUEST, NEED_ANALYSIS              [REC-1] Receipt?
│       └──────┬───────────────────────────────────│ payee match?
│              │                                    │ amount match?
│              ▼                                    │ hash match?
│       [CHAIN-2] dag.verify()                     │ sig verify?
│       │ integrity check                         └──────┬───────┘
│       └─────────────────────────────────────────────►│
│                                                      ▼
│                                              [REC-2] Discrepancy?
│                                              │ recorded, False
│                                              ▼
│                                      [DISP-1] Dispute?
│                                      │ requester only?
│                                      │ declined state?
│                                      ▼
│                                      [DISP-2] Resolve?
│                                      │ method: both_parties/arbiter
│                                      │ all required signers?
│                                      ▼
│                              [INC-1] Income proof?
│                              │ attestation verify?
│                              │ ZK proof verify?
│                              │ context match?
│                              ▼
│                          [ALL] Any validation fail
│                          │ → typed exception
│                          │ → state unchanged
│                          │ → chain entry not written
│                          ▼
│                     FAIL CLOSED (deny by default)
│                                                                                    │
└────────────────────────────────────────────────────────────────────────────────────┘
```

**Key fail-closed mechanisms (module + function):**
- `constitution.Record.active` — property returns `False` if any signature missing/invalid.
- `constitution.verify` — catches `InvalidSignature, ValueError, TypeError` → `False`.
- `constitution.amend` — raises `ConstitutionRefused` if prev not active, version wrong, prev digest wrong.
- `analysis.analyse` — raises `AnalysisRefused` for unknown category; confidence clamped.
- `analysis.checked` — raises `AnalysisRefused` for malformed input; clamps confidence.
- `NeedBook.__init__` — raises `NeedRefused` if `real_money=True` or constitution not active.
- `NeedBook.deposit` — raises `NeedRefused` on bad signature, replayed nonce, bad cents.
- `NeedBook.submit` — raises `NeedRefused` on any validation failure; duplicate request rejected.
- `NeedBook.approve` — raises `NeedRefused` if not approving role, is requester, sig doesn't bind flags.
- `NeedBook.decline` — raises `NeedRefused` if not approving role, is requester; sets `declined`.
- `NeedBook._check_release` — raises `NeedRefused` on already released, over balance, over cap, payee rule, evidence rule.
- `NeedBook.release` — raises `NeedRefused` if state wrong, approvals incomplete, declines exist; jacket Commit required if configured.
- `NeedBook.safety_net_release` — raises `NeedRefused` if safety_net disabled, category not listed, timeout not elapsed, payee not institution, over max, prior answers exist.
- `NeedBook.proof_of_payment` — returns `False` (not exception) on mismatch; records `NEED_DISCREPANCY`.
- `NeedBook.dispute` — raises `NeedRefused` if not declined, not requester, bad reason/sig.
- `NeedBook.resolve` — raises `NeedRefused` if not disputed, bad outcome, missing required signers.
- `income.verify_at_least` — returns `False` on any attestation/ZK/context mismatch.
- `zk` layer — raises `ZKRefused` if threshold > value (no honest proof possible).

## 7. Custom constraint extension points

This version publishes **no user-defined constraint hooks**. Constraints are fixed by the module and the jurisdiction floor (via `vega-jurisdiction-sdk` when integrated).

> User-defined constraints may be STRICTER than the legal minimum for the applicable jurisdiction, never looser. Jurisdictional legal minimums are defined by the jurisdiction registry (vega-jurisdiction-sdk); a custom constraint that would drop below a registered minimum is rejected at the gate.