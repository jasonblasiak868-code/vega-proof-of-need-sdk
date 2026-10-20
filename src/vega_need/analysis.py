"""analysis.py - the need analysis: ADVISORY, with a confidence that is never 1.0, and the reasons it gives in plain words.

The rule-based analyser applies the constitution's OWN words and nothing else: the claimed category's keywords, the parties' want-signal words, whether evidence is attached, and whether the
payee fits the category's payee rule. It produces a classification (NEED, WANT, MIXED, UNCLEAR), a confidence between 0.05 and 0.95 and a list of reasons and flags. A want dressed as a need shows
up as a 'want_signal_in_need' flag. It does NOT approve anything: approval is a human act under the constitution (see bankroll.py).
A model-based analyser can be plugged in (analyzer=callable(request, doc) -> result). Whatever it returns is checked for shape and clamped to the same bounds, and the analyser's name is recorded:
a model's opinion never carries more weight than this rule-based one."""
import re

CLASSES = ("NEED", "WANT", "MIXED", "UNCLEAR")


class AnalysisRefused(ValueError):
    pass


def _words(text):
    return set(re.findall(r"[^\W_]+", str(text).casefold()))


def analyse(request: dict, doc: dict, institutions: set = frozenset()) -> dict:
    cat = doc["categories"].get(request["category"])
    if cat is None:
        raise AnalysisRefused("the constitution has no category %r" % request["category"])
    words = _words(request["purpose"])
    kw = {k for k in cat["keywords"] if k in words}
    want = sorted(w for w in doc["want_signals"] if w in words)
    reasons, flags = [], []
    conf = 0.5
    if kw:
        conf += 0.2
        reasons.append("the purpose uses the category's own words: %s" % ", ".join(sorted(kw)))
    elif cat["keywords"]:
        conf -= 0.1
        reasons.append("the purpose uses none of the category's words")
    if request["evidence"]:
        conf += 0.15
        reasons.append("evidence is attached")
    elif cat["evidence_required"]:
        conf -= 0.2
        flags.append("evidence_missing")
        reasons.append("the category requires evidence and none is attached")
    if want:
        conf -= 0.25 * len(want)
        reasons.append("the purpose contains want-signal words: %s" % ", ".join(want))
        if cat["kind"] == "NEED":
            flags.append("want_signal_in_need")
    if cat["payee"] == "institution_only" and request["payee"] not in institutions:
        flags.append("payee_not_an_institution")
        conf -= 0.3
        reasons.append("this category pays institutions only and the payee is not a registered one")
    if cat["kind"] == "WANT":
        cls = "WANT"
    elif want and kw:
        cls = "MIXED"
    elif want:
        cls = "WANT"
    elif kw or request["evidence"]:
        cls = "NEED"
    else:
        cls = "UNCLEAR"
    return {"analyzer": "rules-1", "classification": cls, "confidence": round(min(0.95, max(0.05, conf)), 2), "flags": sorted(set(flags)), "reasons": reasons}


def checked(result, name: str) -> dict:
    """A plugged-in analyser's output, validated and clamped."""
    if not isinstance(result, dict) or result.get("classification") not in CLASSES:
        raise AnalysisRefused("an analysis has a classification of %s" % (CLASSES,))
    c = result.get("confidence")
    if isinstance(c, bool) or not isinstance(c, (int, float)) or c != c:
        raise AnalysisRefused("confidence is a number")
    flags, reasons = result.get("flags", []), result.get("reasons", [])
    if not isinstance(flags, list) or not isinstance(reasons, list) or not all(isinstance(x, str) and len(x) <= 300 for x in flags + reasons) or len(flags) > 20 or len(reasons) > 20:
        raise AnalysisRefused("flags and reasons are short texts")
    return {"analyzer": str(name)[:40], "classification": result["classification"], "confidence": round(min(0.95, max(0.05, float(c))), 2), "flags": sorted(set(flags)), "reasons": list(reasons)}
