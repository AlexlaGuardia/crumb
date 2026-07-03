"""
Actor binding — make the recorded human PROVABLE from the ledger, not just asserted.

Two things Crumb already does, that never met until now:

  - `verify` proves the log wasn't ALTERED (hash chain + Ed25519 + Merkle + Rekor).
  - `verify_chain` proves a delegation token resolves to a human across issuers.

The gap between them: the persisted crumb stores `actor_identity: "alice"` as a bare
string. That string is the OPERATOR'S WORD. An operator holding the ledger key can
rewrite it to "mallory" and re-sign, and every tamper-evidence check still passes over
their own internally-consistent log. "Verify without trusting the operator" had a hole
exactly where it mattered most: the human.

This demo closes it. The crumb carries the (cross-issuer, stapled) delegation token in
`actor_token`. `verify_actor_binding` re-walks that token against the federation key set
and asserts the human it PROVES equals the human the record CLAIMS. The operator can
re-sign their own segments; they cannot sign as the root issuer. So the forged human
dies at the boundary — even in a log the operator fully controls.

Run: python -m crumb.actor_binding_demo
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

from . import auth
from .federation import Federation, Issuer, verify_chain
from .ledger import Ledger, canonical
from .verify import verify_actor_binding, verify_entries

RESOURCE = "read_record"


def _resign(rec: dict, signing_key) -> dict:
    """Recompute entry_hash + signature over a (mutated) record, exactly as
    Ledger.append does. Models an operator who edits a field and re-signs — they
    hold the key, so the result is a perfectly self-consistent forged ledger."""
    core = {k: v for k, v in rec.items() if k not in ("entry_hash", "signature")}
    entry_hash = hashlib.sha256(canonical(core)).hexdigest()
    signature = signing_key.sign(entry_hash.encode()).hex()
    return {**core, "entry_hash": entry_hash, "signature": "ed25519:" + signature}


def main() -> None:
    print("actor binding — proving WHO from the ledger alone")
    print("=" * 52)

    # ── 1. a cross-issuer delegation, stapled (same construction as P7) ──────────
    idp_a = Issuer("https://idp-a.local")
    idp_b = Issuer("https://idp-b.local")
    b_trusts_a = Federation().trust(idp_a)
    verifier = Federation().trust(idp_a).trust(idp_b)

    alice = auth.login("alice", directives=(RESOURCE,))
    tok_a = idp_a.exchange(alice.token, "planner", RESOURCE, Federation())
    tok_b = idp_b.exchange(tok_a, "researcher", RESOURCE, b_trusts_a)  # crosses A->B

    with tempfile.TemporaryDirectory() as d:
        ledger = Ledger(str(Path(d) / "ledger.jsonl"), str(Path(d) / "ledger.key"))
        pub_pem = Path(d, "ledger.pub").read_bytes()

        # ── 2. record a governed call, BINDING the token into the crumb ──────────
        ledger.append({
            "actor_identity": "alice",
            "agent_id": "researcher",
            "action": RESOURCE,
            "resource_id": {"record_id": 42},
            "directive": RESOURCE,
            "on_behalf_assertion": "delegated",
            "outcome": "success",
            "transport": "mcp",
            "ts": "2026-07-03T10:00:00+00:00",
            "actor_chain": ["researcher", "planner"],
            "actor_token": tok_b,
        })
        entries = [json.loads(ln) for ln in ledger.path.read_text().splitlines()]

        print("\n1. honest ledger")
        integ = verify_entries(entries, pub_pem)
        bind = verify_actor_binding(entries, verifier)
        print(f"   integrity            {'VERIFIED' if integ.ok else 'FAILED'}"
              f" ({integ.checked} entries)")
        resolved = verify_chain(entries[0]["actor_token"], RESOURCE, verifier)
        print(f"   actor binding        {'VERIFIED' if bind.ok else 'FAILED'}"
              f" — human {resolved['human']!r} proven across "
              f"{len(resolved['issuer_path'])} issuers, from the ledger alone")

        # ── 3. the operator rewrites the human and RE-SIGNS with their own key ───
        tampered = dict(entries[0])
        tampered["actor_identity"] = "mallory"
        tampered = _resign(tampered, ledger.signing_key)
        forged = [tampered]

        print("\n2. operator edits the human (alice -> mallory) and re-signs")
        integ2 = verify_entries(forged, pub_pem)
        bind2 = verify_actor_binding(forged, verifier)
        print(f"   integrity            {'VERIFIED' if integ2.ok else 'FAILED'}"
              "  <- tamper-evidence alone can't see it: the operator holds the key")
        status = "REJECTED" if not bind2.ok else "verified"
        reason = bind2.issues[0][1] if bind2.issues else ""
        print(f"   actor binding        {status} — {reason}")

    print("\nThe human is no longer the operator's word. It's re-derived from a token")
    print("chain the operator can't forge, because they can't sign as the root issuer.")


if __name__ == "__main__":
    main()
