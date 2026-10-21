"""Regression tests (2026-10-20): the book's checks ('already released?', 'nonce unused?', 'request exists?', 'within the cap?') and their effects were separate steps, so
concurrent calls could release one request twice, credit one deposit twice, or pass the monthly cap together."""
import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from redteam_1_need import World  # noqa: E402
from vega_need import book as B  # noqa: E402


def race(n, fn):
    gate, out, lock = threading.Barrier(n), [], threading.Lock()

    def go(i):
        gate.wait()
        try:
            fn(i)
            r = "ok"
        except B.NeedRefused:
            r = "refused"
        with lock:
            out.append(r)
    ts = [threading.Thread(target=go, args=(i,)) for i in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(30)
    return sorted(out)


def slow_event(w, seconds=0.02):
    """Writing the chain takes a moment (a disk write): widens the window between a check and the state change that follows it."""
    inner = w.book._event

    def wrapped(kind, **kw):
        time.sleep(seconds)
        return inner(kind, **kw)
    w.book._event = wrapped


class AtomicBook(unittest.TestCase):
    def test_one_request_is_released_once_under_concurrency(self):
        for _ in range(5):
            w = World()
            w.fund(100000)
            rid = w.request(amount=10000)
            w.approve(rid)
            slow_event(w)
            self.assertEqual(race(3, lambda i: w.book.release(rid)), ["ok", "refused", "refused"])
            self.assertEqual(w.book.balance, 90000)
            self.assertEqual(len([e for e in w.dag.content.entries() if e["kind"] == "NEED_RELEASE"]), 1)

    def test_one_deposit_signature_credits_once_under_concurrency(self):
        w = World()
        n = w.nonce()
        sig = w.parties["mum"][1].sign("DEPOSIT", "%d|%s" % (5000, n))
        slow_event(w)
        self.assertEqual(race(3, lambda i: w.book.deposit("mum", 5000, n, sig)), ["ok", "refused", "refused"])
        self.assertEqual(w.book.balance, 5000)

    def test_the_monthly_cap_holds_when_requests_are_released_together(self):
        w = World()
        w.fund(100000)
        rids = []
        for _ in range(3):
            rid = w.request(category="school", amount=25000)           # school's monthly cap is 50000, so only two of three can be released
            w.approve(rid)
            rids.append(rid)
        slow_event(w)
        self.assertEqual(race(3, lambda i: w.book.release(rids[i])), ["ok", "ok", "refused"])
        self.assertEqual(w.book.balance, 50000)


if __name__ == "__main__":
    unittest.main()
