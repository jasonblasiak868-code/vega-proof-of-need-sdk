"""Regression tests (2026-10-22): with the 'arbiter' dispute method the arbiter could be the requester, so a requester could decline-dispute-resolve their own request."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from redteam_1_need import World  # noqa: E402
from vega_need import book as B  # noqa: E402


class Arbiter(unittest.TestCase):
    def test_the_requester_cannot_arbitrate_their_own_dispute(self):
        w = World(dispute={"method": "arbiter", "arbiter": "sam"})        # sam is the child who makes the request
        w.fund()
        rid = w.request()
        w.decline(rid, "mum")
        reason = "please reconsider this"
        rh = B.hashlib.sha256(reason.encode()).hexdigest()
        w.book.dispute(rid, "sam", reason, w.kid.sign("DISPUTE", "%s|%s" % (rid, rh)))
        with self.assertRaises(B.NeedRefused):
            w.book.resolve(rid, "reverse_decline", {"sam": w.kid.sign("RESOLVE", "%s|reverse_decline" % rid)})
        self.assertEqual(w.book.requests[rid]["state"], "disputed")


class SafetyNetNeedsTheCommitment(unittest.TestCase):
    """The safety-net release never consulted the book's configured human commitment, so money moved with no human commitment on a book that promised one for spend_funds."""

    def test_a_book_with_a_jacket_needs_the_commitment_for_the_safety_net_too(self):
        w = World(commit=True)
        w.fund()
        rid = w.request(category="medical", payee="city-clinic", purpose="doctor visit for a fever", evidence=[], amount=12000)
        w.now["t"] += 7 * 86400
        with self.assertRaises(B.NeedRefused):
            w.book.safety_net_release(rid)                                            # no commitment
        with self.assertRaises(B.NeedRefused):
            w.book.safety_net_release(rid, w.human(rid, 99, "city-clinic"))           # signed for another amount
        self.assertEqual((w.book.balance, w.book.requests[rid]["state"]), (100000, "submitted"))
        w.book.safety_net_release(rid, w.human(rid, 12000, "city-clinic"))
        self.assertEqual((w.book.requests[rid]["release"]["via"], w.book.balance), ("safety_net", 88000))
        self.assertTrue(any(e["kind"] == "NEED_RELEASE" and "commit_entry" in e["payload"] for e in w.dag.content.entries()))


if __name__ == "__main__":
    unittest.main()
