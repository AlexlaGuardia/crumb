"""
verify — prove a Crumb ledger wasn't altered, without trusting whoever holds it.

Re-walks the log and checks three things per entry:
  1. integrity — recompute the entry hash from its fields; it must match.
  2. chain     — each entry's prev_hash must equal the previous entry's hash.
  3. signature — each entry hash must verify against the published Ed25519 key.

Any edit, deletion, or reorder of a past entry breaks at least one of these. The
verifier needs only the log and the public key — never the operator's word.

Run: python -m crumb.verify [ledger.jsonl] [ledger.pub]
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

import jwt
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from .federation import CrossIssuerError, verify_chain
from .ledger import GENESIS, canonical

ENVELOPE = ("entry_hash", "signature")  # everything else is signed-over core


@dataclass
class Report:
    ok: bool
    checked: int
    issues: list = field(default_factory=list)  # (seq, reason)


def verify_entries(entries: list[dict], pub_pem: bytes) -> Report:
    """Pure in-memory verification — no file I/O. Runs the same per-entry
    integrity, chain, and Ed25519-signature checks as verify_ledger but over a
    list already loaded into memory. Used by the CLI (remote verification) and
    by tests.

    Args:
        entries:  list of dicts parsed from ledger JSONL (one per crumb).
        pub_pem:  raw PEM bytes of the Ed25519 public key.

    Returns:
        Report(ok, checked, issues)  — identical shape to verify_ledger's return.
    """
    pub = serialization.load_pem_public_key(pub_pem)
    issues: list = []
    prev_hash = GENESIS

    for i, rec in enumerate(entries):
        seq = rec.get("seq", i)
        core = {k: v for k, v in rec.items() if k not in ENVELOPE}

        if hashlib.sha256(canonical(core)).hexdigest() != rec["entry_hash"]:
            issues.append((seq, "entry hash mismatch (a field was edited)"))
        elif rec["prev_hash"] != prev_hash:
            issues.append((seq, "broken chain link (entry inserted, removed, or reordered)"))
        else:
            sig = bytes.fromhex(rec["signature"].removeprefix("ed25519:"))
            try:
                pub.verify(sig, rec["entry_hash"].encode())
            except InvalidSignature:
                issues.append((seq, "bad signature (forged or re-signed without the key)"))

        prev_hash = rec["entry_hash"]

    return Report(ok=not issues, checked=len(entries), issues=issues)


def verify_ledger(path: str = "data/ledger.jsonl",
                  pubkey_path: str = "data/ledger.pub") -> Report:
    """Verify a ledger file on disk. Thin wrapper around verify_entries."""
    pub_pem = Path(pubkey_path).read_bytes()
    lines = Path(path).read_text().splitlines()
    entries = [json.loads(ln) for ln in lines if ln.strip()]
    return verify_entries(entries, pub_pem)


def find_unauthorized(path: str = "data/ledger.jsonl") -> list[dict]:
    """Reconcile intent: return every crumb for an action the human never directed.

    Tamper-evidence (verify_ledger) asks 'was the record altered?'. This asks a
    different question the directive leg now lets us answer: 'did a human actually
    authorize this action?'. A crumb with on_behalf_assertion == 'unauthorized'
    (directive is null) is an action that reached a tool without a human directive
    behind it — the signature of a hijacked / prompt-injected call. The record is
    genuine and unaltered; what it proves is that the AGENT, not the human, is
    accountable for it.
    """
    p = Path(path)
    if not p.exists():
        return []
    crumbs = [json.loads(ln) for ln in p.read_text().splitlines() if ln.strip()]
    return [c for c in crumbs if c.get("on_behalf_assertion") == "unauthorized"]


def verify_actor_binding(entries: list[dict], federation) -> Report:
    """Cryptographically confirm the human named in each crumb — without trusting
    the operator who wrote it.

    verify_entries proves the log wasn't ALTERED. It does not prove the recorded
    `actor_identity` is real: that string is the operator's assertion. An operator
    holding the ledger key can rewrite 'alice' to 'mallory' and re-sign, and the
    tamper-evidence checks still pass over their own consistent log.

    This closes that gap for any crumb carrying `actor_token`. It re-walks the
    (possibly cross-issuer) delegation token against the federation key set — the
    same `verify_chain` the demo runs, now applied to the persisted record — and
    asserts the human the token PROVES equals the human the record CLAIMS. The
    operator can re-sign their own segments all day; they cannot sign as the root
    issuer, so a forged human dies here.

    Additive by construction: crumbs without `actor_token` are skipped, so an
    existing ledger verifies exactly as before. `resource` per entry is the outer
    token's audience, which is the crumb's `action` (the gateway scopes the token
    to the tool it calls).

    Args:
        entries:     ledger records (dicts), as loaded for verify_entries.
        federation:  a `federation.Federation` carrying the issuer public keys the
                     verifier chooses to trust. The one explicit assumption; every
                     segment is checked against it.

    Returns:
        Report(ok, checked, issues) — `checked` counts only token-bearing crumbs.
    """
    issues: list = []
    checked = 0

    for i, rec in enumerate(entries):
        token = rec.get("actor_token")
        if not token:
            continue  # additive: untokened crumbs are out of scope, not failures
        checked += 1
        seq = rec.get("seq", i)
        claimed = rec.get("actor_identity")

        try:
            resolved = verify_chain(token, rec.get("action"), federation)
        except (CrossIssuerError, jwt.PyJWTError) as e:
            issues.append((seq, f"actor token failed verification ({type(e).__name__})"))
            continue

        if resolved["human"] != claimed:
            issues.append((seq,
                f"actor binding mismatch: record claims {claimed!r} but the token "
                f"proves {resolved['human']!r}"))

        recorded_chain = rec.get("actor_chain")
        if recorded_chain is not None and resolved["actor_chain"] != recorded_chain:
            issues.append((seq,
                f"actor chain mismatch: record says {recorded_chain} but the token "
                f"carries {resolved['actor_chain']}"))

    return Report(ok=not issues, checked=checked, issues=issues)


def main() -> None:
    args = sys.argv[1:]
    path = args[0] if args else "data/ledger.jsonl"
    pub = args[1] if len(args) > 1 else "data/ledger.pub"
    report = verify_ledger(path, pub)
    if report.ok:
        print(f"  VERIFIED ✓  {report.checked} entries — chain intact, all signatures valid.")
    else:
        print(f"  MISMATCH ✗  {report.checked} entries checked, {len(report.issues)} problem(s):")
        for seq, reason in report.issues:
            print(f"    entry {seq}: {reason}")
        sys.exit(1)


if __name__ == "__main__":
    main()
