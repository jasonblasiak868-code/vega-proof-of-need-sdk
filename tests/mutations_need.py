"""Mutation check for proof of need: each rule removed in a COPY must make tests/redteam_1_need.py fail."""
import os, pathlib, shutil, subprocess, sys, tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent
CO, AN, BK, IN = "constitution.py", "analysis.py", "book.py", "income.py"
MUTATIONS = [
    ("active means every signature", CO, "return not self.missing", "return True"),
    ("only an active constitution is amended", CO, "if not prev.active:", "if False:"),
    ("an amendment is the next version", CO, 'if new_doc["version"] != prev.doc["version"] + 1 or new_doc["prev"] != prev.digest:', "if False:"),
    ("no shared party keys", CO, "if len(pubs) != len(parties):", "if False:"),
    ("a need needs an approver", CO, 'if c["kind"] == "NEED" and not ap:', "if False:"),
    ("safety net pays institutions only", CO, 'if any(cats[c]["payee"] != "institution_only" for c in sn["categories"]):', "if False:"),
    ("want signal in a need is flagged", AN, 'if cat["kind"] == "NEED":\n            flags.append("want_signal_in_need")', 'if False:\n            flags.append("want_signal_in_need")'),
    ("confidence is clamped", AN, '"confidence": round(min(0.95, max(0.05, conf)), 2)', '"confidence": round(conf, 2)'),
    ("plugged-in confidence is clamped", AN, '"confidence": round(min(0.95, max(0.05, float(c))), 2)', '"confidence": round(float(c), 2)'),
    ("payee flag", AN, 'if cat["payee"] == "institution_only" and request["payee"] not in institutions:', "if False:"),
    ("evidence flag", AN, 'elif cat["evidence_required"]:', "elif False:"),
    ("no real money", BK, "if real_money:", "if False:"),
    ("constitution must be active", BK, " or not record.active", ""),
    ("deposit nonce replay", BK, " or nonce in self._nonces", ""),
    ("request signature", BK, 'if not C.verify(p["public"], "REQUEST", rid, sig):', "if False:"),
    ("duplicate request", BK, "if rid in self.requests:", "if False:"),
    ("nobody approves their own", BK, 'if party_id == r["party"]:\n            raise NeedRefused("nobody approves their own request")', 'if False:\n            raise NeedRefused("nobody approves their own request")'),
    ("approving role", BK, 'if p["role"] not in cat["approvals"]:\n            raise NeedRefused("that party\'s role does not approve this category")', 'if False:\n            raise NeedRefused("that party\'s role does not approve this category")'),
    ("approval binds the flags", BK, '"%s|%s" % (request_id, r["flags_sha"])', "request_id"),
    ("decline by approving role only", BK, 'if party_id == r["party"] or p["role"] not in cat["approvals"]:', "if False:"),
    ("every role covered", BK, "return need <= have", "return True"),
    ("a decline blocks release", BK, 'if r["declines"]:\n            raise NeedRefused("a party declined")', 'if False:\n            raise NeedRefused("a party declined")'),
    ("monthly cap", BK, '> cat["monthly_cap_cents"]', "> 10 ** 12"),
    ("balance", BK, 'if r["amount"] > self.balance:', "if False:"),
    ("payee rule", BK, 'if cat["payee"] == "institution_only" and r["payee"] not in self.institutions:', "if False:"),
    ("evidence rule", BK, 'if cat["evidence_required"] and not r["evidence"]:', "if False:"),
    ("released once", BK, 'if r["release"] is not None:', "if False:"),
    ("human commitment required", BK, "if signed is None:", "if False:"),
    ("safety net wait", BK, 'if self._clock() - r["submitted_at"] < sn["unreachable_after_seconds"]:', "if False:"),
    ("safety net institutions", BK, 'if r["payee"] not in self.institutions:\n            raise NeedRefused("the safety net pays', 'if False:\n            raise NeedRefused("the safety net pays'),
    ("safety net maximum", BK, 'if r["amount"] > sn["max_cents"]:', "if False:"),
    ("safety net only when unanswered", BK, ' or r["declines"] or r["approvals"]:', ' or r["declines"]:'),
    ("receipt matches payee and signature", BK, 'if institution != r["payee"] or not C.verify(pub, "RECEIPT", text, sig):', "if False:"),
    ("one receipt", BK, 'if rel["paid"]:', "if False:"),
    ("only the requester disputes", BK, 'if party_id != r["party"]:', "if False:"),
    ("resolution signers", BK, 'needed = {dp["arbiter"]} if dp["method"] == "arbiter" else ({r["party"]} | set(r["declines"]))', "needed = set()"),
    ("income needs the issuer's attestation", IN, "zk.verify_attestation(issuer_public, commitment, label, attestation) and ", ""),
]
if __name__ != "__main__":
    MUTATIONS = []
survivors = []
for name, fname, old, new in MUTATIONS:
    tmp = pathlib.Path(tempfile.mkdtemp())
    shutil.copytree(REPO / "src" / "vega_need", tmp / "vega_need")
    f = tmp / "vega_need" / fname
    text = f.read_text(encoding="utf-8")
    if old not in text:
        print("CANNOT APPLY", name)
        survivors.append(name + " (could not apply)")
        continue
    f.write_text(text.replace(old, new, 1), encoding="utf-8")
    env = dict(os.environ)
    env["PYTHONPATH"] = str(tmp) + os.pathsep + env.get("PYTHONPATH", "")
    r = subprocess.run([sys.executable, "-W", "ignore", str(REPO / "tests" / "redteam_1_need.py")], capture_output=True, text=True, env=env, timeout=600)
    print(("killed   " if r.returncode != 0 else "SURVIVED ") + name, flush=True)
    if r.returncode == 0:
        survivors.append(name)
    shutil.rmtree(tmp, ignore_errors=True)
print("survivors:", survivors or "none")
