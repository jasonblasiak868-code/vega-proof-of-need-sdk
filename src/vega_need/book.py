"""book.py - the book of need: requests, advisory analysis, human approvals, releases from a SIMULATED bankroll, institution receipts, disputes.

NO REAL MONEY. This is a paper simulation: balances are whole numbers of cents in memory, 'release' moves a number, and constructing a book with real_money=True is refused. Moving real money
needs money-transmission licensing, KYC/AML, custody and, for children, COPPA and consent; none of that is cleared (see the owner's handoff). The SDK exists so the rules can be tested and shown first.

THE FLOW
  submit      a party asks for an amount for a category, a payee and a purpose (signed). The purpose text is kept in memory only; the chain gets its hash. An ADVISORY analysis is attached (analysis.py).
  approve     a party with a role the category requires signs the request id AND the analysis flags it saw. Every required role must be covered by someone other than the requester. Any such party may decline.
  release     only when approvals cover the roles, nothing declined, the category's monthly cap, the balance, the payee rule and the evidence rule all hold. If a jacket Commit is configured, the release also needs the
              device owner's human commitment for the HUMAN_ONLY action 'spend_funds' over exactly this request. Burn-then-record: the chain entry is written, and the money moves only after it.
  safety_net  if the constitution allows it and approvers have not answered for the agreed time, money may go to a REGISTERED INSTITUTION for a listed category up to a maximum, on the standing authority of the
              co-signed constitution (that is what the parties agreed to in advance); any decline blocks it.
  proof_of_payment  the institution signs a receipt; it must match the release's payee and amount, else a DISCREPANCY is recorded and the release stays unpaid.
  dispute / resolve  per the constitution: both parties sign, or the named arbiter signs.
NOT BUILT: the freedom experiments (they would collect children's behaviour data: needs a consent and privacy model first) and the saving-and-investing mechanic (securities territory).
State lives in this object; a real system needs durable storage and the legal structure above."""
import functools
import hashlib
import json
import re
import threading
import time

from vega_custody.dag.dag import DagError
from vega_jacket.commit.commit import CommitRefused
from vega_need import analysis, constitution as C

HEX64 = re.compile(r"^[0-9a-f]{64}$")
MONTH = 30 * 86400
MAX_CENTS = 10 ** 8
RELEASE_ACTION = "spend_funds"


class NeedRefused(ValueError):
    pass


def _sha(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()


def _cents(v, name):
    if isinstance(v, bool) or not isinstance(v, int) or not 1 <= v <= MAX_CENTS:
        raise NeedRefused("%s is a whole number of cents from 1 to %d" % (name, MAX_CENTS))
    return v


def _atomic(fn):
    """Every operation that checks and then changes the book runs alone: a check ('already released?', 'nonce unused?', 'within the monthly cap?') and the change that follows it are
    one step. Without this, concurrent calls could release one request twice, credit one deposit twice, or pass the cap together."""
    @functools.wraps(fn)
    def inner(self, *a, **k):
        with self._lock:
            return fn(self, *a, **k)
    return inner


class NeedBook:
    def __init__(self, dag, record: C.Record, institutions=None, clock=time.time, commit=None, real_money: bool = False, analyzer=None, analyzer_name: str = "custom"):
        if real_money:
            raise NeedRefused("no real money: licensing, KYC and custody gates are not cleared; this is a simulation")
        if not isinstance(record, C.Record) or not record.active:
            raise NeedRefused("the constitution is not active: every party must sign it first")
        self.dag, self.record, self._clock, self.commit = dag, record, clock, commit
        self._lock = threading.RLock()
        self.doc = record.doc
        self.institutions = {}
        for iid, pub in (institutions or {}).items():
            if not isinstance(iid, str) or not C.NAME.fullmatch(iid) or not isinstance(pub, str) or not HEX64.fullmatch(pub):
                raise NeedRefused("an institution has a plain id and a public key")
            self.institutions[iid] = pub
        self.analyzer, self.analyzer_name = analyzer, analyzer_name
        self.balance = 0
        self.requests, self.releases, self._nonces, self.spent = {}, {}, set(), {}
        self._event("NEED_ACTIVATED", constitution=record.digest, version=self.doc["version"])

    # ---- helpers -------------------------------------------------------------------------------------------------
    def _event(self, kind, **kw):
        try:
            self.dag.record(kind, kw)
        except DagError as exc:
            raise NeedRefused("the chain could not be written: %s" % exc) from exc

    def _party(self, pid):
        p = self.doc["parties"].get(pid) if isinstance(pid, str) else None
        if p is None:
            raise NeedRefused("not a party to this constitution")
        return p

    def _req(self, rid):
        r = self.requests.get(rid) if isinstance(rid, str) else None
        if r is None:
            raise NeedRefused("unknown request")
        return r

    def _window(self):
        return int(self._clock() // MONTH)

    # ---- money in (simulated) -----------------------------------------------------------------------------------------
    @_atomic
    def deposit(self, party_id, cents, nonce, sig):
        p = self._party(party_id)
        _cents(cents, "cents")
        if not isinstance(nonce, str) or not 8 <= len(nonce) <= 64 or nonce in self._nonces:
            raise NeedRefused("a fresh nonce of 8 to 64 characters is required")
        if not C.verify(p["public"], "DEPOSIT", "%d|%s" % (cents, nonce), sig):
            raise NeedRefused("not signed by that party")
        self._event("NEED_DEPOSIT", party=party_id, cents=cents, nonce_sha256=hashlib.sha256(nonce.encode()).hexdigest())
        self._nonces.add(nonce)
        self.balance += cents

    # ---- requests -----------------------------------------------------------------------------------------------------------
    @_atomic
    def submit(self, party_id, category, amount_cents, payee, purpose, evidence, nonce, sig) -> str:
        p = self._party(party_id)
        cat = self.doc["categories"].get(category) if isinstance(category, str) else None
        if cat is None:
            raise NeedRefused("the constitution has no such category")
        _cents(amount_cents, "amount_cents")
        if not isinstance(payee, str) or not C.NAME.fullmatch(payee):
            raise NeedRefused("payee is a plain id")
        if not isinstance(purpose, str) or not 3 <= len(purpose) <= 300 or not purpose.isprintable():
            raise NeedRefused("purpose is 3 to 300 printable characters")
        if not isinstance(evidence, list) or len(evidence) > 10 or not all(isinstance(e, str) and HEX64.fullmatch(e) for e in evidence):
            raise NeedRefused("evidence is up to 10 document hashes")
        if not isinstance(nonce, str) or not 8 <= len(nonce) <= 64:
            raise NeedRefused("a nonce of 8 to 64 characters is required")
        body = {"party": party_id, "category": category, "amount_cents": amount_cents, "payee": payee, "purpose_sha256": hashlib.sha256(purpose.encode("utf-8")).hexdigest(), "evidence": sorted(evidence), "nonce": nonce}
        rid = _sha(body)
        if rid in self.requests:
            raise NeedRefused("this request already exists")
        if not C.verify(p["public"], "REQUEST", rid, sig):
            raise NeedRefused("not signed by that party")
        request = {"category": category, "purpose": purpose, "payee": payee, "evidence": list(evidence)}
        try:
            if self.analyzer is not None:
                result = analysis.checked(self.analyzer(dict(request, amount_cents=amount_cents), self.doc), self.analyzer_name)
            else:
                result = analysis.analyse(request, self.doc, set(self.institutions))
        except analysis.AnalysisRefused:
            raise
        except Exception as exc:                                    # noqa: BLE001 - a crashing analyser must not block or approve anything
            raise NeedRefused("the analyser failed: %s" % type(exc).__name__) from exc
        self._event("NEED_REQUEST", request=rid, party=party_id, category=category, amount_cents=amount_cents, payee=payee, purpose_sha256=body["purpose_sha256"])
        self._event("NEED_ANALYSIS", request=rid, analyzer=result["analyzer"], classification=result["classification"], confidence=result["confidence"], flags=result["flags"])
        self.requests[rid] = {"party": party_id, "category": category, "amount": amount_cents, "payee": payee, "evidence": sorted(evidence), "analysis": result,
                              "flags_sha": _sha(result["flags"]), "approvals": {}, "declines": set(), "state": "submitted", "submitted_at": self._clock(), "release": None, "resolved": None}
        return rid

    @_atomic
    def approve(self, request_id, party_id, sig):
        r, p = self._req(request_id), self._party(party_id)
        cat = self.doc["categories"][r["category"]]
        if party_id == r["party"]:
            raise NeedRefused("nobody approves their own request")
        if p["role"] not in cat["approvals"]:
            raise NeedRefused("that party's role does not approve this category")
        if r["state"] != "submitted":
            raise NeedRefused("the request is %s" % r["state"])
        if not C.verify(p["public"], "APPROVE", "%s|%s" % (request_id, r["flags_sha"]), sig):
            raise NeedRefused("not signed by that party for this request and the flags it carries")
        self._event("NEED_APPROVAL", request=request_id, party=party_id)
        r["approvals"][party_id] = sig

    @_atomic
    def decline(self, request_id, party_id, sig):
        r, p = self._req(request_id), self._party(party_id)
        cat = self.doc["categories"][r["category"]]
        if party_id == r["party"] or p["role"] not in cat["approvals"]:
            raise NeedRefused("only an approving party other than the requester can decline")
        if r["state"] not in ("submitted",):
            raise NeedRefused("the request is %s" % r["state"])
        if not C.verify(p["public"], "DECLINE", request_id, sig):
            raise NeedRefused("not signed by that party")
        self._event("NEED_DECLINE", request=request_id, party=party_id)
        r["declines"].add(party_id)
        r["state"] = "declined"

    def _roles_covered(self, r):
        need = set(self.doc["categories"][r["category"]]["approvals"])
        have = {self.doc["parties"][pid]["role"] for pid in r["approvals"]}
        return need <= have

    # ---- release ---------------------------------------------------------------------------------------------------------------
    def _check_release(self, r, via):
        cat = self.doc["categories"][r["category"]]
        if r["release"] is not None:
            raise NeedRefused("already released")
        if r["amount"] > self.balance:
            raise NeedRefused("the bankroll does not hold that much")
        if self.spent.get((r["category"], self._window()), 0) + r["amount"] > cat["monthly_cap_cents"]:
            raise NeedRefused("this would pass the category's monthly cap")
        if cat["payee"] == "institution_only" and r["payee"] not in self.institutions:
            raise NeedRefused("this category pays registered institutions only")
        if cat["evidence_required"] and not r["evidence"]:
            raise NeedRefused("this category requires evidence")

    def _do_release(self, rid, r, via, params):
        self._event("NEED_RELEASE", request=rid, amount_cents=r["amount"], payee=r["payee"], via=via, **params)
        self.balance -= r["amount"]
        key = (r["category"], self._window())
        self.spent[key] = self.spent.get(key, 0) + r["amount"]
        r["state"] = "released"
        r["release"] = {"via": via, "at": self._clock(), "paid": False}
        self.releases[rid] = r

    @_atomic
    def release(self, request_id, signed=None):
        r = self._req(request_id)
        if r["state"] not in ("submitted", "resolved_approved"):
            raise NeedRefused("the request is %s" % r["state"])
        if r["state"] == "submitted" and not self._roles_covered(r):
            raise NeedRefused("not every required role has approved")
        if r["declines"]:
            raise NeedRefused("a party declined")
        self._check_release(r, "approval")
        params = {}
        if self.commit is not None:
            if signed is None:
                raise NeedRefused("this book needs the device owner's human commitment for spend_funds")
            try:
                out = self.commit.commit(RELEASE_ACTION, {"request": request_id, "amount_cents": r["amount"], "payee": r["payee"]}, signed, route="human")
            except CommitRefused as exc:
                raise NeedRefused("the human commitment was refused: %s" % exc) from exc
            params = {"commit_entry": out["entry"]}
        self._do_release(request_id, r, "approval", params)

    @_atomic
    def safety_net_release(self, request_id):
        r = self._req(request_id)
        sn = self.doc["safety_net"]
        if not sn["enabled"] or r["category"] not in sn["categories"]:
            raise NeedRefused("the constitution does not allow a safety-net release for this category")
        if r["state"] != "submitted" or r["declines"] or r["approvals"]:
            raise NeedRefused("the safety net is only for a request nobody has answered")
        if self._clock() - r["submitted_at"] < sn["unreachable_after_seconds"]:
            raise NeedRefused("the approvers have not been unreachable long enough")
        if r["payee"] not in self.institutions:
            raise NeedRefused("the safety net pays registered institutions only")
        if r["amount"] > sn["max_cents"]:
            raise NeedRefused("above the safety-net maximum")
        self._check_release(r, "safety_net")
        self._do_release(request_id, r, "safety_net", {})

    # ---- proof of payment -----------------------------------------------------------------------------------------------------------
    @_atomic
    def proof_of_payment(self, request_id, institution, receipt_hash, at, sig) -> bool:
        r = self._req(request_id)
        rel = r["release"]
        if rel is None:
            raise NeedRefused("nothing was released for this request")
        if rel["paid"]:
            raise NeedRefused("a receipt was already accepted")
        pub = self.institutions.get(institution)
        if pub is None or not isinstance(receipt_hash, str) or not HEX64.fullmatch(receipt_hash) or isinstance(at, bool) or not isinstance(at, int):
            raise NeedRefused("a registered institution, a receipt hash and a time are required")
        text = "%s|%d|%s|%d" % (request_id, r["amount"], receipt_hash, at)
        if institution != r["payee"] or not C.verify(pub, "RECEIPT", text, sig):
            self._event("NEED_DISCREPANCY", request=request_id, institution=institution)
            return False
        self._event("NEED_PAID", request=request_id, institution=institution, receipt_sha256=receipt_hash)
        rel["paid"] = True
        r["state"] = "paid"
        return True

    def overdue(self, after_seconds: int = 7 * 86400):
        now = self._clock()
        return sorted(rid for rid, r in self.releases.items() if not r["release"]["paid"] and now - r["release"]["at"] >= after_seconds)

    # ---- disputes ---------------------------------------------------------------------------------------------------------------------------
    @_atomic
    def dispute(self, request_id, party_id, reason, sig):
        r, p = self._req(request_id), self._party(party_id)
        if r["state"] != "declined":
            raise NeedRefused("only a declined request can be disputed")
        if party_id != r["party"]:
            raise NeedRefused("only the requester disputes a decline")
        if not isinstance(reason, str) or not 3 <= len(reason) <= 300 or not C.verify(p["public"], "DISPUTE", "%s|%s" % (request_id, hashlib.sha256(reason.encode()).hexdigest()), sig):
            raise NeedRefused("a reason and the requester's signature are required")
        self._event("NEED_DISPUTE", request=request_id, reason_sha256=hashlib.sha256(reason.encode()).hexdigest())
        r["state"] = "disputed"

    @_atomic
    def resolve(self, request_id, outcome, sigs: dict):
        r = self._req(request_id)
        if r["state"] != "disputed":
            raise NeedRefused("the request is not in dispute")
        if outcome not in ("reverse_decline", "uphold"):
            raise NeedRefused("outcome is reverse_decline or uphold")
        dp = self.doc["dispute"]
        needed = {dp["arbiter"]} if dp["method"] == "arbiter" else ({r["party"]} | set(r["declines"]))
        if not isinstance(sigs, dict) or not needed <= set(sigs) or not all(C.verify(self._party(pid)["public"], "RESOLVE", "%s|%s" % (request_id, outcome), sigs[pid]) for pid in needed):
            raise NeedRefused("the resolution is not signed by everyone the constitution requires")
        self._event("NEED_RESOLVED", request=request_id, outcome=outcome, method=dp["method"])
        r["state"] = "resolved_approved" if outcome == "reverse_decline" else "declined_final"
        r["declines"] = set() if outcome == "reverse_decline" else r["declines"]

    def report(self):
        return {"balance_cents": self.balance, "requests": {s: sum(1 for r in self.requests.values() if r["state"] == s) for s in sorted({r["state"] for r in self.requests.values()})},
                "spent_this_month": {c: v for (c, w), v in self.spent.items() if w == self._window()}, "unpaid": sorted(rid for rid, r in self.releases.items() if not r["release"]["paid"])}
