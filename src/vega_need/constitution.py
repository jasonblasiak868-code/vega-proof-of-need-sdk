"""constitution.py - the rule set that decides what counts as NEED, written down in the open and co-signed by everyone it governs.

The design risk the owner named: defining need without becoming surveillance or control. The answer here is that the rules are TRANSPARENT (a plain document anyone party can read),
CO-SIGNED (it takes effect only when every party has signed its exact hash; one change means everyone signs again), VERSIONED (each version names the one before it) and the only thing the
system ever does with them is apply them as written. Nothing here watches anyone: it judges requests that someone chooses to make.

A document holds:
  parties      {party id: {role, public key}}      roles are free text such as 'guardian', 'member', 'arbiter'
  categories   {name: {kind NEED|WANT, keywords, monthly_cap_cents, payee 'institution_only'|'any', evidence_required, approvals [roles]}}
  want_signals words that make a request look like a want dressed as a need (the parties choose them; they are shown to everyone)
  safety_net   {enabled, categories, unreachable_after_seconds, max_cents}     when approvers cannot be reached, money may still go to an institution (school, doctor)
  dispute      {method 'both_parties'|'arbiter', arbiter party id}
  version, prev  (the digest of the version this one replaces, or null)
Signatures are Ed25519 over 'VEGA-NEED-CONST-1|' + the document's digest. A minor's signature is an assent, not legal consent: who may sign for whom is a legal question this code does not answer."""
import hashlib
import json
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

HEX64 = re.compile(r"^[0-9a-f]{64}$")
NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")
MAX_CATEGORIES, MAX_PARTIES, MAX_KEYWORDS = 40, 12, 60
PAYEE_RULES = ("institution_only", "any")
DISPUTE_METHODS = ("both_parties", "arbiter")


class ConstitutionRefused(ValueError):
    pass


def canonical(doc) -> bytes:
    try:
        return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ConstitutionRefused("the constitution must be plain data: %s" % exc) from exc


def digest(doc) -> str:
    return hashlib.sha256(b"VEGA-NEED-CONST-DOC-1|" + canonical(doc)).hexdigest()


class Party:
    """A signer. In real use the private key lives on that person's own device; this class is for tests and for a person's own signing console."""

    def __init__(self):
        self._sk = Ed25519PrivateKey.generate()
        self.public = self._sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

    def sign(self, tag: str, text: str) -> str:
        return self._sk.sign(("VEGA-NEED-%s-1|" % tag).encode("ascii") + text.encode("utf-8")).hex()


def verify(public_hex, tag: str, text: str, sig_hex) -> bool:
    try:
        if not isinstance(public_hex, str) or not HEX64.fullmatch(public_hex) or not isinstance(sig_hex, str) or len(sig_hex) != 128:
            return False
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(bytes.fromhex(sig_hex), ("VEGA-NEED-%s-1|" % tag).encode("ascii") + text.encode("utf-8"))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def _check(doc):
    if not isinstance(doc, dict):
        raise ConstitutionRefused("a constitution is an object")
    parties = doc.get("parties")
    if not isinstance(parties, dict) or not 2 <= len(parties) <= MAX_PARTIES:
        raise ConstitutionRefused("2 to %d parties" % MAX_PARTIES)
    pubs = set()
    for pid, p in parties.items():
        if not isinstance(pid, str) or not NAME.fullmatch(pid) or not isinstance(p, dict) or not isinstance(p.get("role"), str) or not NAME.fullmatch(p["role"]) \
                or not isinstance(p.get("public"), str) or not HEX64.fullmatch(p["public"]):
            raise ConstitutionRefused("each party has a plain id, a role and a public key")
        pubs.add(p["public"])
    if len(pubs) != len(parties):
        raise ConstitutionRefused("two parties cannot share a key")
    roles = {p["role"] for p in parties.values()}
    cats = doc.get("categories")
    if not isinstance(cats, dict) or not 1 <= len(cats) <= MAX_CATEGORIES:
        raise ConstitutionRefused("1 to %d categories" % MAX_CATEGORIES)
    for name, c in cats.items():
        if not isinstance(name, str) or not NAME.fullmatch(name) or not isinstance(c, dict):
            raise ConstitutionRefused("bad category")
        if c.get("kind") not in ("NEED", "WANT") or c.get("payee") not in PAYEE_RULES or not isinstance(c.get("evidence_required"), bool):
            raise ConstitutionRefused("category %s: kind, payee rule and evidence flag are required" % name)
        cap = c.get("monthly_cap_cents")
        if isinstance(cap, bool) or not isinstance(cap, int) or not 0 <= cap <= 10 ** 9:
            raise ConstitutionRefused("category %s: monthly_cap_cents is a whole number of cents" % name)
        kw = c.get("keywords")
        if not isinstance(kw, list) or len(kw) > MAX_KEYWORDS or not all(isinstance(k, str) and 2 <= len(k) <= 40 and k == k.casefold() for k in kw):
            raise ConstitutionRefused("category %s: keywords are lower-case words" % name)
        ap = c.get("approvals")
        if not isinstance(ap, list) or not set(ap) <= roles or len(set(ap)) != len(ap):
            raise ConstitutionRefused("category %s: approvals name roles that exist, once each" % name)
        if c["kind"] == "NEED" and not ap:
            raise ConstitutionRefused("category %s: a need needs at least one approving role" % name)
    ws = doc.get("want_signals")
    if not isinstance(ws, list) or len(ws) > 100 or not all(isinstance(w, str) and 2 <= len(w) <= 40 and w == w.casefold() for w in ws):
        raise ConstitutionRefused("want_signals are lower-case words")
    sn = doc.get("safety_net")
    if not isinstance(sn, dict) or not isinstance(sn.get("enabled"), bool):
        raise ConstitutionRefused("safety_net is required")
    if sn["enabled"]:
        if not set(sn.get("categories", [])) <= set(cats) or not sn.get("categories") or not isinstance(sn.get("unreachable_after_seconds"), int) or isinstance(sn["unreachable_after_seconds"], bool) \
                or not 3600 <= sn["unreachable_after_seconds"] <= 30 * 86400 or not isinstance(sn.get("max_cents"), int) or isinstance(sn["max_cents"], bool) or not 0 < sn["max_cents"] <= 10 ** 8:
            raise ConstitutionRefused("safety_net: categories that exist, an unreachable time of 1 hour to 30 days and a maximum")
        if any(cats[c]["payee"] != "institution_only" for c in sn["categories"]):
            raise ConstitutionRefused("the safety net may only cover categories that pay institutions")
    dp = doc.get("dispute")
    if not isinstance(dp, dict) or dp.get("method") not in DISPUTE_METHODS or (dp["method"] == "arbiter" and dp.get("arbiter") not in parties):
        raise ConstitutionRefused("dispute: a method, and an arbiter who is a party if the method is 'arbiter'")
    v = doc.get("version")
    if isinstance(v, bool) or not isinstance(v, int) or v < 1:
        raise ConstitutionRefused("version is a whole number from 1")
    if (v == 1) != (doc.get("prev") is None) or (doc.get("prev") is not None and not (isinstance(doc["prev"], str) and HEX64.fullmatch(doc["prev"]))):
        raise ConstitutionRefused("version 1 has no prev; later versions name the digest they replace")


class Record:
    """A constitution plus its signatures. It is ACTIVE only when every party has validly signed this exact document."""

    def __init__(self, doc, sigs):
        _check(doc)
        self.doc, self.sigs, self.digest = doc, dict(sigs) if isinstance(sigs, dict) else {}, digest(doc)

    @property
    def missing(self):
        return sorted(pid for pid, p in self.doc["parties"].items() if not verify(p["public"], "CONST", self.digest, self.sigs.get(pid)))

    @property
    def active(self) -> bool:
        return not self.missing

    def sign_as(self, party_id: str, sig: str):
        p = self.doc["parties"].get(party_id)
        if p is None or not verify(p["public"], "CONST", self.digest, sig):
            raise ConstitutionRefused("not a valid signature of that party for this exact document")
        self.sigs[party_id] = sig


def amend(prev: Record, new_doc) -> Record:
    """A new version that replaces an ACTIVE one. It starts unsigned: every party signs the new digest, including parties who are unchanged."""
    if not prev.active:
        raise ConstitutionRefused("only an active constitution can be amended")
    r = Record(new_doc, {})
    if new_doc["version"] != prev.doc["version"] + 1 or new_doc["prev"] != prev.digest:
        raise ConstitutionRefused("an amendment is the next version and names the digest it replaces")
    return r
