"""Tests and attacks for proof of need and proof of payment: constitution, analysis, the book, receipts, disputes, income proofs."""
import copy
import json
import pathlib
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vega_custody.dag.dag import Dag, DagError
from vega_custody.ledger.backend_local import LocalBackend
from vega_custody.ledger.ledger import Ledger
from vega_jacket import humanauth
from vega_jacket.commit.commit import Commit
from vega_jacket.humanauth import human_signer
from vega_need import analysis, book as B, constitution as C, income

T0 = 1_800_000_000.0
PW, DEV, SURF = "correct horse battery", "dev-t", "surf-t"


def make_doc(parties, **over):
    doc = {"parties": {pid: {"role": role, "public": p.public} for pid, (role, p) in parties.items()},
           "categories": {
               "school": {"kind": "NEED", "keywords": ["school", "tuition", "books", "lunch"], "monthly_cap_cents": 50000, "payee": "institution_only", "evidence_required": True, "approvals": ["guardian"]},
               "clothing": {"kind": "NEED", "keywords": ["coat", "shoes", "boots"], "monthly_cap_cents": 20000, "payee": "any", "evidence_required": False, "approvals": ["guardian"]},
               "medical": {"kind": "NEED", "keywords": ["doctor", "dentist", "prescription"], "monthly_cap_cents": 100000, "payee": "institution_only", "evidence_required": False, "approvals": ["guardian"]},
               "fun": {"kind": "WANT", "keywords": ["game", "cinema"], "monthly_cap_cents": 5000, "payee": "any", "evidence_required": False, "approvals": []}},
           "want_signals": ["skin", "candy", "toy", "gadget"],
           "safety_net": {"enabled": True, "categories": ["medical", "school"], "unreachable_after_seconds": 7 * 86400, "max_cents": 30000},
           "dispute": {"method": "both_parties"}, "version": 1, "prev": None}
    doc.update(over)
    return doc


class World:
    def __init__(self, commit=False, **over):
        self.p1, self.p2, self.kid = C.Party(), C.Party(), C.Party()
        self.parties = {"mum": ("guardian", self.p1), "dad": ("guardian", self.p2), "sam": ("member", self.kid)}
        self.school, self.clinic = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        self.pub = lambda k: k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        self.doc = make_doc(self.parties, **over)
        self.record = C.Record(self.doc, {})
        for pid, (role, party) in self.parties.items():
            self.record.sign_as(pid, party.sign("CONST", self.record.digest))
        t = pathlib.Path(tempfile.mkdtemp())
        self.dag = Dag([t / "c.jsonl"], [t / "l.jsonl"])
        self.now = {"t": T0}
        self.commit = None
        if commit:
            self.blob, pub = human_signer.generate(PW)
            self.commit = Commit(humanauth.Verifier(pub, DEV, SURF), Ledger([LocalBackend(t / "led.jsonl")]), self.dag)
        self.book = B.NeedBook(self.dag, self.record, {"greenfield-school": self.pub(self.school), "city-clinic": self.pub(self.clinic)}, clock=lambda: self.now["t"], commit=self.commit)
        self.n = 0

    def nonce(self):
        self.n += 1
        return "nonce-%06d" % self.n

    def fund(self, cents=100000, who="mum"):
        n = self.nonce()
        self.book.deposit(who, cents, n, self.parties[who][1].sign("DEPOSIT", "%d|%s" % (cents, n)))

    def request(self, category="school", amount=10000, payee="greenfield-school", purpose="school tuition for the autumn term", evidence=None, who="sam"):
        ev = ["ab" * 32] if evidence is None else evidence
        n = self.nonce()
        body = {"party": who, "category": category, "amount_cents": amount, "payee": payee, "purpose_sha256": B.hashlib.sha256(purpose.encode()).hexdigest(), "evidence": sorted(ev), "nonce": n}
        rid = B._sha(body)
        return self.book.submit(who, category, amount, payee, purpose, ev, n, self.parties[who][1].sign("REQUEST", rid))

    def approve(self, rid, who="mum"):
        r = self.book.requests[rid]
        self.book.approve(rid, who, self.parties[who][1].sign("APPROVE", "%s|%s" % (rid, r["flags_sha"])))

    def decline(self, rid, who="dad"):
        self.book.decline(rid, who, self.parties[who][1].sign("DECLINE", rid))

    def human(self, rid, amount, payee, lease=300, action="spend_funds"):
        return human_signer.sign(self.blob, PW, DEV, SURF, action, {"request": rid, "amount_cents": amount, "payee": payee}, lease)

    def receipt(self, rid, institution="greenfield-school", amount=None, signer=None, at=None):
        r = self.book.requests[rid]
        amount = r["amount"] if amount is None else amount
        at = int(self.now["t"]) if at is None else at
        h = "cd" * 32
        key = signer or self.school
        sig = key.sign(b"VEGA-NEED-RECEIPT-1|" + ("%s|%d|%s|%d" % (rid, amount, h, at)).encode()).hex()
        return rid, institution, h, at, sig


class ConstitutionTests(unittest.TestCase):
    def test_it_is_active_only_when_every_party_signed_this_exact_document(self):
        w = World()
        self.assertTrue(w.record.active)
        r = C.Record(w.doc, {})
        self.assertEqual(r.missing, ["dad", "mum", "sam"])
        r.sign_as("mum", w.p1.sign("CONST", r.digest))
        self.assertFalse(r.active)
        with self.assertRaises(C.ConstitutionRefused):
            r.sign_as("dad", w.p1.sign("CONST", r.digest))                         # mum's key for dad
        with self.assertRaises(C.ConstitutionRefused):
            r.sign_as("dad", w.p2.sign("CONST", "0" * 64))                          # a signature for another document
        with self.assertRaises(C.ConstitutionRefused):
            r.sign_as("nobody", "00" * 64)
        r.sign_as("dad", w.p2.sign("CONST", r.digest))
        r.sign_as("sam", w.kid.sign("CONST", r.digest))
        self.assertTrue(r.active)
        changed = copy.deepcopy(w.doc)
        changed["categories"]["fun"]["monthly_cap_cents"] = 999999
        stolen = C.Record(changed, r.sigs)                                          # the old signatures on an edited document
        self.assertFalse(stolen.active)
        self.assertEqual(len(stolen.missing), 3)

    def test_an_amendment_is_the_next_version_and_everyone_signs_again(self):
        w = World()
        doc2 = copy.deepcopy(w.doc)
        doc2.update(version=2, prev=w.record.digest)
        doc2["categories"]["fun"]["monthly_cap_cents"] = 8000
        r2 = C.amend(w.record, doc2)
        self.assertFalse(r2.active)
        for pid, (role, party) in w.parties.items():
            r2.sign_as(pid, party.sign("CONST", r2.digest))
        self.assertTrue(r2.active)
        bad = copy.deepcopy(doc2)
        bad["prev"] = "0" * 64
        with self.assertRaises(C.ConstitutionRefused):
            C.amend(w.record, bad)
        bad = copy.deepcopy(doc2)
        bad["version"] = 3
        with self.assertRaises(C.ConstitutionRefused):
            C.amend(w.record, bad)
        with self.assertRaises(C.ConstitutionRefused):
            C.amend(C.Record(w.doc, {}), doc2)                                      # an inactive constitution cannot be amended

    def test_malformed_constitutions_are_refused(self):
        w = World()

        def mutate(fn):
            d = copy.deepcopy(w.doc)
            fn(d)
            return d
        bad = [
            lambda d: d.pop("categories"), lambda d: [d["parties"].pop("sam"), d["parties"].pop("dad")], lambda d: d["parties"]["sam"].update(public=d["parties"]["mum"]["public"]),
            lambda d: d["parties"]["sam"].update(role="Bad Role"), lambda d: d["parties"]["sam"].update(public="zz"),
            lambda d: d["categories"]["school"].update(monthly_cap_cents=-1), lambda d: d["categories"]["school"].update(monthly_cap_cents=True),
            lambda d: d["categories"]["school"].update(keywords=["School"]), lambda d: d["categories"]["school"].update(kind="MAYBE"),
            lambda d: d["categories"]["school"].update(payee="whoever"), lambda d: d["categories"]["school"].update(approvals=["boss"]),
            lambda d: d["categories"]["school"].update(approvals=[]), lambda d: d["categories"]["school"].update(evidence_required="yes"),
            lambda d: d.update(want_signals=["Toy"]), lambda d: d.update(want_signals="toy"),
            lambda d: d["safety_net"].update(categories=["nothing"]), lambda d: d["safety_net"].update(categories=["clothing"]), lambda d: d["safety_net"].update(unreachable_after_seconds=10),
            lambda d: d["safety_net"].update(max_cents=0), lambda d: d["safety_net"].update(categories=[]), lambda d: d.pop("safety_net"),
            lambda d: d.update(dispute={"method": "arbiter", "arbiter": "stranger"}), lambda d: d.update(dispute={"method": "coin_toss"}),
            lambda d: d.update(version=0), lambda d: d.update(prev="0" * 64), lambda d: d.update(version=2), lambda d: d.update(version=True),
            lambda d: d.update(extra=float("nan")),
        ]
        for fn in bad:
            with self.assertRaises(C.ConstitutionRefused):
                C.Record(mutate(fn), {})
        with self.assertRaises(C.ConstitutionRefused):
            C.Record("text", {})


class AnalysisTests(unittest.TestCase):
    def setUp(self):
        self.doc = World().doc
        self.inst = {"greenfield-school"}

    def a(self, **kw):
        base = {"category": "school", "purpose": "school tuition", "payee": "greenfield-school", "evidence": ["ab" * 32]}
        return analysis.analyse(dict(base, **kw), self.doc, self.inst)

    def test_a_plain_need_is_a_need_with_reasons_and_never_full_confidence(self):
        r = self.a()
        self.assertEqual(r["classification"], "NEED")
        self.assertEqual(r["flags"], [])
        self.assertTrue(0.05 <= r["confidence"] <= 0.95)
        self.assertTrue(r["reasons"])

    def test_a_want_dressed_as_a_need_is_flagged_and_loses_confidence(self):
        plain = self.a()
        dressed = self.a(purpose="school books and a gadget skin")
        self.assertIn("want_signal_in_need", dressed["flags"])
        self.assertEqual(dressed["classification"], "MIXED")
        self.assertLess(dressed["confidence"], plain["confidence"])
        pure = self.a(purpose="candy and a toy")
        self.assertEqual(pure["classification"], "WANT")

    def test_missing_evidence_wrong_payee_and_unclear_purposes(self):
        self.assertIn("evidence_missing", self.a(evidence=[])["flags"])
        self.assertIn("payee_not_an_institution", self.a(payee="cousin-vinny")["flags"])
        self.assertEqual(self.a(purpose="money please", evidence=[])["classification"], "UNCLEAR")

    def test_the_want_categories_are_wants_and_confidence_is_clamped(self):
        self.assertEqual(self.a(category="fun", purpose="a game")["classification"], "WANT")
        floor = self.a(purpose="toy toy candy gadget skin", payee="x", evidence=[])
        self.assertEqual(floor["confidence"], 0.05)
        with self.assertRaises(analysis.AnalysisRefused):
            self.a(category="nothing")

    def test_a_plugged_in_analyser_is_validated_and_clamped(self):
        ok = analysis.checked({"classification": "NEED", "confidence": 1.0, "flags": ["x"], "reasons": ["why"]}, "model-1")
        self.assertEqual((ok["confidence"], ok["analyzer"]), (0.95, "model-1"))
        self.assertEqual(analysis.checked({"classification": "WANT", "confidence": -5}, "m")["confidence"], 0.05)
        for bad in (None, [], {"classification": "SURE"}, {"classification": "NEED"}, {"classification": "NEED", "confidence": True}, {"classification": "NEED", "confidence": float("nan")},
                    {"classification": "NEED", "confidence": 0.5, "flags": "x"}, {"classification": "NEED", "confidence": 0.5, "reasons": ["x" * 301]}, {"classification": "NEED", "confidence": 0.5, "flags": ["a"] * 21}):
            with self.assertRaises(analysis.AnalysisRefused):
                analysis.checked(bad, "m")


class BookTests(unittest.TestCase):
    def test_no_real_money_and_no_inactive_constitution(self):
        w = World()
        with self.assertRaises(B.NeedRefused):
            B.NeedBook(w.dag, w.record, real_money=True)
        with self.assertRaises(B.NeedRefused):
            B.NeedBook(w.dag, C.Record(w.doc, {}))
        with self.assertRaises(B.NeedRefused):
            B.NeedBook(w.dag, "text")
        for inst in ({"BAD ID": "ab" * 32}, {"ok": "zz"}, {"ok": 5}):
            with self.assertRaises(B.NeedRefused):
                B.NeedBook(w.dag, w.record, inst)

    def test_deposits_are_signed_fresh_and_counted_in_whole_cents(self):
        w = World()
        w.fund(5000)
        self.assertEqual(w.book.balance, 5000)
        n = w.nonce()
        sig = w.p1.sign("DEPOSIT", "100|%s" % n)
        w.book.deposit("mum", 100, n, sig)
        with self.assertRaises(B.NeedRefused):
            w.book.deposit("mum", 100, n, sig)                                       # replayed
        for who, cents, nonce, key in (("mum", 100, w.nonce(), w.p2), ("nobody", 100, w.nonce(), w.p1), ("mum", 0, w.nonce(), w.p1), ("mum", -5, w.nonce(), w.p1), ("mum", True, w.nonce(), w.p1),
                                       ("mum", 1.5, w.nonce(), w.p1), ("mum", 10 ** 9, w.nonce(), w.p1), ("mum", 100, "short", w.p1)):
            with self.assertRaises(B.NeedRefused):
                w.book.deposit(who, cents, nonce, key.sign("DEPOSIT", "%s|%s" % (cents, nonce)))
        self.assertEqual(w.book.balance, 5100)

    def test_requests_are_validated_signed_and_analysed_and_the_purpose_stays_off_the_chain(self):
        w = World()
        rid = w.request(purpose="school tuition for the autumn term")
        self.assertEqual(w.book.requests[rid]["analysis"]["classification"], "NEED")
        blob = json.dumps([e["payload"] for e in w.dag.content.entries() if e["kind"].startswith("NEED_")])
        self.assertNotIn("tuition", blob)
        self.assertIn(rid, blob)
        n = w.nonce()
        kw = dict(party_id="sam", category="school", amount_cents=100, payee="greenfield-school", purpose="school stuff", evidence=[], nonce=n)
        for edit in ({"category": "nothing"}, {"amount_cents": 0}, {"amount_cents": True}, {"amount_cents": 10 ** 9}, {"payee": "Bad Payee"}, {"purpose": "x"}, {"purpose": "a\x00bc"},
                     {"evidence": ["short"]}, {"evidence": ["ab" * 32] * 11}, {"evidence": "ab" * 32}, {"nonce": "short"}, {"party_id": "nobody"}):
            with self.assertRaises(B.NeedRefused, msg=str(edit)):
                w.book.submit(**dict(kw, **edit), sig="00" * 64)
        with self.assertRaises(B.NeedRefused):
            w.book.submit(**kw, sig=w.p1.sign("REQUEST", "x"))                       # a signature for something else

    def test_the_same_request_cannot_be_submitted_twice(self):
        w = World()
        purpose, n = "school tuition for the autumn term", "nonce-fixed-1"
        body = {"party": "sam", "category": "school", "amount_cents": 10000, "payee": "greenfield-school", "purpose_sha256": B.hashlib.sha256(purpose.encode()).hexdigest(), "evidence": ["ab" * 32], "nonce": n}
        sig = w.kid.sign("REQUEST", B._sha(body))
        w.book.submit("sam", "school", 10000, "greenfield-school", purpose, ["ab" * 32], n, sig)
        with self.assertRaises(B.NeedRefused):
            w.book.submit("sam", "school", 10000, "greenfield-school", purpose, ["ab" * 32], n, sig)

    def test_a_pluggable_analyser_cannot_approve_and_a_crashing_one_blocks_the_request(self):
        w = World()
        w.book.analyzer, w.book.analyzer_name = (lambda req, doc: {"classification": "NEED", "confidence": 0.99}), "model-x"
        rid = w.request()
        self.assertEqual(w.book.requests[rid]["analysis"]["confidence"], 0.95)
        self.assertEqual(w.book.requests[rid]["state"], "submitted")                  # the analysis approved nothing
        w.book.analyzer = lambda req, doc: 1 / 0
        with self.assertRaises(B.NeedRefused):
            w.request()
        w.book.analyzer = lambda req, doc: "not a dict"
        with self.assertRaises(analysis.AnalysisRefused):
            w.request()

    def test_approvals_come_from_the_right_roles_never_the_requester_and_are_bound_to_the_flags_seen(self):
        w = World()
        rid = w.request()
        with self.assertRaises(B.NeedRefused):
            w.approve(rid, "sam")                                                     # a member cannot approve a need
        w2 = World()
        rid2 = w2.request(who="mum", category="clothing", payee="shop", purpose="winter coat", evidence=[])
        with self.assertRaises(B.NeedRefused):
            w2.approve(rid2, "mum")                                                   # nobody approves their own request
        r = w.book.requests[rid]
        by_mum = w.request(who="mum", category="clothing", payee="shop", purpose="winter coat", evidence=[])
        with self.assertRaises(B.NeedRefused):
            w.book.approve(by_mum, "sam", w.kid.sign("APPROVE", "%s|%s" % (by_mum, w.book.requests[by_mum]["flags_sha"])))      # a member's role does not approve a need
        with self.assertRaises(B.NeedRefused):
            w.book.approve(rid, "mum", w.p1.sign("APPROVE", "%s|%s" % (rid, "0" * 64)))   # signed for different flags than the ones shown
        with self.assertRaises(B.NeedRefused):
            w.book.approve(rid, "mum", w.p2.sign("APPROVE", "%s|%s" % (rid, r["flags_sha"])))
        with self.assertRaises(B.NeedRefused):
            w.book.approve("nosuch", "mum", "00" * 64)
        w.approve(rid)
        w.approve(rid)                                                                # twice is still one approval
        self.assertEqual(list(r["approvals"]), ["mum"])

    def test_a_release_needs_every_required_role_and_no_decline(self):
        w = World()
        w.fund()
        rid = w.request()
        with self.assertRaises(B.NeedRefused):
            w.book.release(rid)                                                       # nobody approved
        w.approve(rid)
        w.book.release(rid)
        self.assertEqual((w.book.balance, w.book.requests[rid]["state"]), (90000, "released"))
        with self.assertRaises(B.NeedRefused):
            w.book.release(rid)                                                       # once only
        rid2 = w.request()
        w.approve(rid2)
        with self.assertRaises(B.NeedRefused):
            w.book.decline(rid2, "sam", w.kid.sign("DECLINE", rid2))                  # only an approving role declines
        with self.assertRaises(B.NeedRefused):
            w.book.decline(rid2, "dad", w.p1.sign("DECLINE", rid2))
        w.decline(rid2)
        self.assertEqual(w.book.requests[rid2]["state"], "declined")
        with self.assertRaises(B.NeedRefused):
            w.book.release(rid2)

    def test_the_caps_the_balance_the_payee_rule_and_the_evidence_rule(self):
        w = World()
        w.fund(1_000_000)
        rid = w.request(amount=40000)
        w.approve(rid)
        w.book.release(rid)
        over = w.request(amount=20000)                                                # 40000 + 20000 passes the 50000 cap
        w.approve(over)
        with self.assertRaises(B.NeedRefused):
            w.book.release(over)
        w.now["t"] += 31 * 86400                                                       # a new month
        w.book.release(over)
        poor = World()
        poor.fund(500)
        r1 = poor.request(amount=10000)
        poor.approve(r1)
        with self.assertRaises(B.NeedRefused):
            poor.book.release(r1)                                                     # the bankroll does not hold it
        cousin = w.request(payee="cousin-vinny", amount=100)
        w.approve(cousin)
        with self.assertRaises(B.NeedRefused):
            w.book.release(cousin)                                                    # school pays institutions only
        noev = w.request(evidence=[], amount=100)
        w.approve(noev)
        with self.assertRaises(B.NeedRefused):
            w.book.release(noev)

    def test_a_want_category_with_no_approver_runs_only_to_its_cap(self):
        w = World()
        w.fund()
        a = w.request(category="fun", payee="cinema", purpose="a game at the cinema", evidence=[], amount=3000)
        w.book.release(a)
        b = w.request(category="fun", payee="cinema", purpose="a game at the cinema", evidence=[], amount=3000)
        with self.assertRaises(B.NeedRefused):
            w.book.release(b)

    def test_with_a_jacket_the_release_needs_the_owners_human_commitment_for_exactly_this_request(self):
        w = World(commit=True)
        w.fund()
        rid = w.request()
        w.approve(rid)
        with self.assertRaises(B.NeedRefused):
            w.book.release(rid)                                                       # no commitment
        with self.assertRaises(B.NeedRefused):
            w.book.release(rid, {"nonce": "n", "expiry": 1, "signature": "00"})
        other = w.request(amount=500)
        with self.assertRaises(B.NeedRefused):
            w.book.release(rid, w.human(other, 500, "greenfield-school"))              # signed for another request
        with self.assertRaises(B.NeedRefused):
            w.book.release(rid, w.human(rid, 10000, "greenfield-school", action="release_public"))
        good = w.human(rid, 10000, "greenfield-school")
        w.book.release(rid, good)
        self.assertEqual(w.book.balance, 90000)
        self.assertTrue(any(e["kind"] == "NEED_RELEASE" and "commit_entry" in e["payload"] for e in w.dag.content.entries()))
        w.approve(other)
        with self.assertRaises(B.NeedRefused):
            w.book.release(other, good)                                               # a spent commitment cannot be reused

    def test_the_safety_net_pays_institutions_only_after_the_wait_and_never_over_a_decline(self):
        w = World()
        w.fund()
        rid = w.request(category="medical", payee="city-clinic", purpose="doctor visit for a fever", evidence=[], amount=12000)
        with self.assertRaises(B.NeedRefused):
            w.book.safety_net_release(rid)                                            # not unreachable yet
        w.now["t"] += 7 * 86400
        w.book.safety_net_release(rid)
        self.assertEqual(w.book.requests[rid]["release"]["via"], "safety_net")
        w2 = World()
        w2.fund()
        for kw in ({"category": "clothing", "payee": "shop", "purpose": "winter coat", "evidence": []}, {"category": "medical", "payee": "cousin-vinny", "purpose": "dentist visit"},
                   {"category": "medical", "payee": "city-clinic", "purpose": "dentist visit", "amount": 40000}):
            r = w2.request(**dict({"evidence": []}, **kw))
            w2.now["t"] += 8 * 86400
            with self.assertRaises(B.NeedRefused, msg=str(kw)):
                w2.book.safety_net_release(r)
        w3 = World()
        w3.fund()
        r = w3.request(category="medical", payee="city-clinic", purpose="dentist visit", evidence=[], amount=100)
        w3.decline(r)
        w3.now["t"] += 8 * 86400
        with self.assertRaises(B.NeedRefused):
            w3.book.safety_net_release(r)
        w4 = World()
        w4.fund()
        r = w4.request(category="medical", payee="city-clinic", purpose="dentist visit", evidence=[], amount=100)
        w4.approve(r)
        w4.now["t"] += 8 * 86400
        with self.assertRaises(B.NeedRefused):
            w4.book.safety_net_release(r)                                             # someone answered: the normal route applies
        off = World(safety_net={"enabled": False})
        off.fund()
        r = off.request(category="medical", payee="city-clinic", purpose="dentist visit", evidence=[], amount=100)
        off.now["t"] += 30 * 86400
        with self.assertRaises(B.NeedRefused):
            off.book.safety_net_release(r)

    def test_a_receipt_from_the_right_institution_for_the_right_amount_marks_it_paid(self):
        w = World()
        w.fund()
        rid = w.request()
        w.approve(rid)
        with self.assertRaises(B.NeedRefused):
            w.book.proof_of_payment(*w.receipt(rid))                                  # nothing released yet
        w.book.release(rid)
        w.now["t"] += 8 * 86400
        self.assertEqual(w.book.overdue(), [rid])
        self.assertFalse(w.book.proof_of_payment(*w.receipt(rid, signer=w.clinic)))               # signed by another institution's key
        self.assertFalse(w.book.proof_of_payment(*w.receipt(rid, institution="city-clinic", signer=w.clinic)))   # a different institution than the payee
        self.assertFalse(w.book.proof_of_payment(*w.receipt(rid, amount=9999)))                    # not the released amount
        self.assertEqual(sum(1 for e in w.dag.content.entries() if e["kind"] == "NEED_DISCREPANCY"), 3)
        self.assertTrue(w.book.proof_of_payment(*w.receipt(rid)))
        self.assertEqual((w.book.overdue(), w.book.requests[rid]["state"]), ([], "paid"))
        with self.assertRaises(B.NeedRefused):
            w.book.proof_of_payment(*w.receipt(rid))
        rid2 = w.request()
        w.approve(rid2)
        w.book.release(rid2)
        for bad in (("unknown-inst", "cd" * 32, 1, "00" * 64), ("greenfield-school", "short", 1, "00" * 64), ("greenfield-school", "cd" * 32, True, "00" * 64)):
            with self.assertRaises(B.NeedRefused):
                w.book.proof_of_payment(rid2, *bad)

    def test_disputes_follow_the_constitutions_method(self):
        w = World()
        w.fund()
        rid = w.request()
        with self.assertRaises(B.NeedRefused):
            w.book.resolve(rid, "uphold", {})
        w.decline(rid)
        reason = "the school year starts next week"
        rh = B.hashlib.sha256(reason.encode()).hexdigest()
        with self.assertRaises(B.NeedRefused):
            w.book.dispute(rid, "mum", reason, w.p1.sign("DISPUTE", "%s|%s" % (rid, rh)))      # only the requester disputes
        w.book.dispute(rid, "sam", reason, w.kid.sign("DISPUTE", "%s|%s" % (rid, rh)))
        sigs = {"sam": w.kid.sign("RESOLVE", "%s|reverse_decline" % rid)}
        with self.assertRaises(B.NeedRefused):
            w.book.resolve(rid, "reverse_decline", sigs)                               # the decliner must sign too
        with self.assertRaises(B.NeedRefused):
            w.book.resolve(rid, "reverse_decline", dict(sigs, dad=w.p1.sign("RESOLVE", "%s|reverse_decline" % rid)))
        with self.assertRaises(B.NeedRefused):
            w.book.resolve(rid, "maybe", sigs)
        w.book.resolve(rid, "reverse_decline", dict(sigs, dad=w.p2.sign("RESOLVE", "%s|reverse_decline" % rid)))
        w.book.release(rid)                                                           # the resolution stands in for the approvals
        self.assertEqual(w.book.requests[rid]["state"], "released")

    def test_the_arbiter_method(self):
        w = World(dispute={"method": "arbiter", "arbiter": "dad"})
        w.fund()
        rid = w.request()
        w.decline(rid, "mum")
        reason = "please reconsider this"
        rh = B.hashlib.sha256(reason.encode()).hexdigest()
        w.book.dispute(rid, "sam", reason, w.kid.sign("DISPUTE", "%s|%s" % (rid, rh)))
        with self.assertRaises(B.NeedRefused):
            w.book.resolve(rid, "uphold", {"mum": w.p1.sign("RESOLVE", "%s|uphold" % rid)})
        w.book.resolve(rid, "uphold", {"dad": w.p2.sign("RESOLVE", "%s|uphold" % rid)})
        self.assertEqual(w.book.requests[rid]["state"], "declined_final")
        with self.assertRaises(B.NeedRefused):
            w.book.release(rid)

    def test_the_chain_is_intact_and_the_report_adds_up(self):
        w = World()
        w.fund()
        rid = w.request()
        w.approve(rid)
        w.book.release(rid)
        rep = w.book.report()
        self.assertEqual((rep["balance_cents"], rep["unpaid"], rep["spent_this_month"]), (90000, [rid], {"school": 10000}))
        self.assertTrue(w.dag.verify()[0])

    def test_if_the_chain_cannot_be_written_the_money_does_not_move(self):
        w = World()
        w.fund()
        rid = w.request()
        w.approve(rid)
        real = w.dag.record

        def failing(kind, payload, parents=None):
            raise DagError("disk full")
        w.dag.record = failing
        with self.assertRaises(B.NeedRefused):
            w.book.release(rid)
        self.assertEqual((w.book.balance, w.book.requests[rid]["state"]), (100000, "submitted"))
        w.dag.record = real
        w.book.release(rid)
        self.assertEqual(w.book.balance, 90000)


class IncomeTests(unittest.TestCase):
    def test_at_least_is_proved_without_the_number_and_bound_to_the_issuer_and_context(self):
        issuer = Ed25519PrivateKey.generate()
        pub = issuer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        value = 4200
        commitment, blinding, att = income.issue(issuer, value, "monthly_income_cents")
        proof = income.prove_at_least(value, blinding, 3000, 12, b"for:landlord-1|2026-10")
        self.assertTrue(income.verify_at_least(pub, commitment, "monthly_income_cents", att, 3000, 12, proof, b"for:landlord-1|2026-10"))
        self.assertFalse(income.verify_at_least(pub, commitment, "monthly_income_cents", att, 3001, 12, proof, b"for:landlord-1|2026-10"))
        self.assertFalse(income.verify_at_least(pub, commitment, "monthly_income_cents", att, 3000, 12, proof, b"for:landlord-2|2026-10"))
        self.assertFalse(income.verify_at_least(pub, commitment, "monthly_rent_cents", att, 3000, 12, proof, b"for:landlord-1|2026-10"))
        other = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.assertFalse(income.verify_at_least(other, commitment, "monthly_income_cents", att, 3000, 12, proof, b"for:landlord-1|2026-10"))
        c2, _, _ = income.issue(issuer, value, "monthly_income_cents")
        self.assertFalse(income.verify_at_least(pub, c2, "monthly_income_cents", att, 3000, 12, proof, b"for:landlord-1|2026-10"))
        from vega_superproof.seal import zk
        with self.assertRaises(zk.ZKRefused):
            income.prove_at_least(value, blinding, 5000, 12, b"x")                      # below the bar: no honest proof


if __name__ == "__main__":
    unittest.main()
