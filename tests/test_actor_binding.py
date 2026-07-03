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

from cryptography.hazmat.primitives import serialization

from crumb import auth
from crumb.cli import _load_federation, _run_verification, _verify_local
from crumb.federation import Federation, Issuer
from crumb.ledger import Ledger, canonical
from crumb.verify import verify_actor_binding, verify_entries

RESOURCE = "read_record"


def _pub_pem(issuer) -> str:
    return issuer.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


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


# ── CLI integration: `crumb verify --federation` ─────────────────────────────


def _bound_ledger_on_disk(tmp: Path):
    """Write a bound crumb to a real ledger (+ .pub) and a federation manifest.
    Returns (ledger, ledger_path, federation, manifest_path)."""
    idp_a = Issuer("https://idp-a.local")
    idp_b = Issuer("https://idp-b.local")
    alice = auth.login("alice", directives=(RESOURCE,))
    tok_a = idp_a.exchange(alice.token, "planner", RESOURCE, Federation())
    tok_b = idp_b.exchange(tok_a, "researcher", RESOURCE, Federation().trust(idp_a))

    ledger = Ledger(str(tmp / "ledger.jsonl"), str(tmp / "ledger.key"))
    ledger.append(_bound_crumb(tok_b))

    manifest = tmp / "fed.json"
    manifest.write_text(json.dumps({
        "https://idp-a.local": _pub_pem(idp_a),
        "https://idp-b.local": _pub_pem(idp_b),
    }))
    return ledger, ledger.path, _load_federation(str(manifest)), manifest


def test_cli_binding_verifies_with_federation():
    with tempfile.TemporaryDirectory() as d:
        _, path, fed, _ = _bound_ledger_on_disk(Path(d))
        result = _verify_local(str(path), fed)
        assert result["binding"]["ok"] is True
        assert result["binding"]["checked"] == 1


def test_cli_binding_is_a_visible_skip_without_federation():
    """No --federation: the human is NOT silently passed. ok is None with a note
    that says it went unchecked."""
    with tempfile.TemporaryDirectory() as d:
        _, path, _, _ = _bound_ledger_on_disk(Path(d))
        result = _verify_local(str(path), None)
        assert result["binding"]["ok"] is None
        assert "not cryptographically checked" in result["binding"]["note"].lower()


def test_cli_binding_catches_resigned_tamper():
    with tempfile.TemporaryDirectory() as d:
        ledger, path, fed, _ = _bound_ledger_on_disk(Path(d))
        rec = json.loads(path.read_text().splitlines()[0])
        rec["actor_identity"] = "mallory"
        core = {k: v for k, v in rec.items() if k not in ("entry_hash", "signature")}
        eh = hashlib.sha256(canonical(core)).hexdigest()
        sig = ledger.signing_key.sign(eh.encode()).hex()
        path.write_text(json.dumps({**core, "entry_hash": eh,
                                    "signature": "ed25519:" + sig}) + "\n")
        result = _verify_local(str(path), fed)
        assert result["chain"]["ok"] is True        # integrity fooled
        assert result["binding"]["ok"] is False      # binding is not
        assert "mallory" in result["binding"]["issues"][0][1]


def test_cli_binding_none_for_unbound_ledger():
    """An ordinary (untokened) ledger reports binding as 'no bound crumbs', so the
    layer never turns a plain ledger red."""
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        ledger = Ledger(str(tmp / "l.jsonl"), str(tmp / "l.key"))
        ledger.append({"actor_identity": "alice", "action": RESOURCE,
                       "resource_id": {}, "directive": RESOURCE,
                       "on_behalf_assertion": "delegated", "outcome": "success",
                       "transport": "openai", "agent_id": "a1", "ts": "2026-07-03T00:00:00+00:00"})
        result = _verify_local(str(tmp / "l.jsonl"), None)
        assert result["binding"]["ok"] is None
        assert result["binding"]["note"] == "no bound crumbs"
