"""income.py - prove a hidden number is at least a threshold ('income at least X', 'balance at least X') without showing the number, vouched for by whoever issued it.

An ISSUER (an employer, a bank, a school) commits to the number with a Pedersen commitment and signs the commitment with a label such as 'monthly_income_cents'. The HOLDER later proves, in zero
knowledge, that the committed number is at least a threshold, bound to a context (who it is for and when). The VERIFIER checks the issuer's signature and the proof; it never learns the number.
It uses the superproof SDK's privacy tier (zk.py): classical security (not quantum-proof), plain Python, not independently reviewed. The proof shows the number is in a range; whether the number is
TRUE is the issuer's word. Do not put a real person's financial figures through this before a review."""
from vega_superproof.seal import zk


class IncomeRefused(ValueError):
    pass


def issue(issuer_private, value: int, label: str):
    """-> (commitment bytes, blinding, attestation hex). The holder keeps value and blinding secret and never sends them."""
    commitment, blinding = zk.commit(value)
    return commitment, blinding, zk.attest(issuer_private, commitment, label)


def prove_at_least(value: int, blinding: int, threshold: int, bits: int, context: bytes) -> dict:
    return zk.prove_at_least(value, blinding, threshold, bits, context)


def verify_at_least(issuer_public: bytes, commitment: bytes, label: str, attestation: str, threshold: int, bits: int, proof, context: bytes) -> bool:
    return zk.verify_attestation(issuer_public, commitment, label, attestation) and zk.verify_at_least(commitment, threshold, bits, proof, context)
