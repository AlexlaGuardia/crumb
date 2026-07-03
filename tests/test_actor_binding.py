"""
Tests for verify_actor_binding — cryptographic confirmation of the recorded human.

Convention (matches test_verify_entries): isolated temp ledger + fresh keys per
test; never touch data/. The federation is built in-process from throwaway issuers.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

from crumb import auth
from crumb.federation import Federation, Issuer
from crumb.ledger import Ledger, canonical
from crumb.verify import verify_actor_binding, verify_entries

RESOURCE = "read_record"


def _cross_issuer_token():
    """A stapled A->B delegation token rooted at alice, plus a verifier federation
    that trusts both issuers."""
    idp_a = Issuer("https://idp-a.local")
    idp_b = Issuer("https://idp-b.local")
    verifier = Federation().trust(idp_a).trust(idp_b)
    alice = auth.login("alice", directives=(RESOURCE,))
    tok_a = idp_a.exchange(alice.token, "planner", RESOURCE, Federation())
    tok_b = idp_b.exchange(tok_a, "researcher", RESOURCE, Federation().trust(idp_a))
    return tok_b, verifier


def _bound_crumb(token, human="alice"):
    return {
        "actor_identity": human,
        "agent_id": "researcher",
        "action": RESOURCE,
        "resource_id": {"record_id": 42},
        "directive": RESOURCE,
        "on_behalf_assertion": "delegated",
        "outcome": "success",
        "transport": "mcp",
        "ts": "2026-07-03T10:00:00+00:00",
        "actor_chain": ["researcher", "planner"],
        "actor_token": token,
    }


def test_binding_confirms_the_human():
    token, verifier = _cross_issuer_token()
    report = verify_actor_binding([_bound_crumb(token)], verifier)
    assert report.ok
    assert report.checked == 1


def test_binding_catches_a_forged_human_even_when_resigned():
    """The operator holds the ledger key and rewrites the human, re-signing a
    self-consistent log. Integrity passes; binding must still reject."""
    token, verifier = _cross_issuer_token()
    with tempfile.TemporaryDirectory() as d:
        ledger = Ledger(str(Path(d) / "l.jsonl"), str(Path(d) / "l.key"))
        pub = Path(d, "l.pub").read_bytes()
        ledger.append(_bound_crumb(token))

        rec = json.loads(ledger.path.read_text().splitlines()[0])
        rec["actor_identity"] = "mallory"                       # the lie
        core = {k: v for k, v in rec.items() if k not in ("entry_hash", "signature")}
        eh = hashlib.sha256(canonical(core)).hexdigest()
        sig = ledger.signing_key.sign(eh.encode()).hex()        # operator re-signs
        forged = [{**core, "entry_hash": eh, "signature": "ed25519:" + sig}]

        assert verify_entries(forged, pub).ok                   # integrity fooled
        binding = verify_actor_binding(forged, verifier)        # binding is not
        assert not binding.ok
        assert "mallory" in binding.issues[0][1]
        assert "alice" in binding.issues[0][1]


def test_untokened_crumbs_are_skipped_not_failed():
    """Additive by construction: a ledger with no actor_token verifies clean and
    reports zero checked — existing ledgers are unaffected."""
    _, verifier = _cross_issuer_token()
    plain = {"actor_identity": "alice", "action": RESOURCE}
    report = verify_actor_binding([plain], verifier)
    assert report.ok
    assert report.checked == 0


def test_unfederated_issuer_is_rejected():
    """A verifier that doesn't trust the root issuer refuses the token rather than
    accepting the operator's word for the human."""
    token, _ = _cross_issuer_token()
    empty = Federation()  # trusts no one
    report = verify_actor_binding([_bound_crumb(token)], empty)
    assert not report.ok
    assert report.checked == 1
