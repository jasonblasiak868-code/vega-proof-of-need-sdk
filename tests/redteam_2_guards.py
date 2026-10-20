"""Second pass: each guard on a release is tested ON ITS OWN, by the reason it gives, so one guard cannot hide behind another. Run: python tests/redteam_2_guards.py"""
import unittest

from redteam_1_need import World, B


class Guards(unittest.TestCase):
    def test_a_decline_blocks_release_by_itself(self):
        w = World()
        w.fund()
        rid = w.request()
        w.approve(rid)
        w.book.requests[rid]["declines"] = ["dad"]                                  # approved by the required role AND declined by a party
        with self.assertRaises(B.NeedRefused) as cm:
            w.book.release(rid)
        self.assertIn("declined", str(cm.exception))
        self.assertEqual(w.book.balance, 100000)

    def test_a_request_that_was_already_released_cannot_be_released_again_by_the_released_flag(self):
        w = World()
        w.fund()
        rid = w.request()
        w.approve(rid)
        w.book.release(rid)
        w.book.requests[rid]["state"] = "resolved_approved"                         # even if the state were wrongly reopened
        with self.assertRaises(B.NeedRefused) as cm:
            w.book.release(rid)
        self.assertIn("already released", str(cm.exception))
        self.assertEqual(w.book.balance, 90000)

    def test_with_a_jacket_release_without_a_commitment_is_refused_for_that_reason(self):
        w = World(commit=True)
        w.fund()
        rid = w.request()
        w.approve(rid)
        with self.assertRaises(B.NeedRefused) as cm:
            w.book.release(rid)
        self.assertIn("needs the device owner", str(cm.exception))
        self.assertEqual(w.book.balance, 100000)

    def test_the_safety_net_refuses_an_unregistered_payee_for_that_reason(self):
        w = World()
        w.fund()
        r = w.request(category="medical", payee="cousin-vinny", purpose="dentist visit", evidence=[], amount=100)
        w.now["t"] += 8 * 86400
        with self.assertRaises(B.NeedRefused) as cm:
            w.book.safety_net_release(r)
        self.assertIn("safety net pays", str(cm.exception))
        self.assertEqual(w.book.balance, 100000)


if __name__ == "__main__":
    unittest.main()
