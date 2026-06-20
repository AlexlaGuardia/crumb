"""
Anchor demo (P4b) — the attack the signed chain can't stop, and the one that can.

Run: python -m crumb.anchor_demo

P2 catches a careless edit because the edited row's hash stops matching. But the
operator HOLDS the signing key. So they don't just edit one row — they rewrite
history and re-sign the whole chain. Watch P2's verifier pass that forgery
without complaint. Then watch the external Rekor anchor catch it, because the
rewritten root is not the one already public.

Needs network for the real anchor; without it the checkpoint is local-only and
the demo says so (the rollback is still caught — the root mismatch is offline math).
"""

from __future__ import annotations

import datetime
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from . import anchor, auth
from .agent import ToolCall
from .gateway import Gateway
from .ledger import Ledger, canonical
from .verify import verify_ledger

LEDGER = "data/ledger.jsonl"
KEY = "data/ledger.key"
PUB = "data/ledger.pub"
LINE = "─" * 70


def _seed() -> None:
    gw = Gateway(ledger=Ledger(path=LEDGER, key_path=KEY), agent_id="crumb-agent-1")
    gw.ledger.reset()
    for who, transport, rid in [("alice", "openai", 42), ("bob", "mcp", 43),
                                ("carol", "openai", 42)]:
        gw.dispatch(auth.login(who, directives=("read_record",)),
                    ToolCall("read_record", {"record_id": rid}), transport=transport)


def _operator_rollback() -> None:
    """What a key-holding insider really does: rewrite a row, then re-chain and
    re-sign EVERY entry so the whole ledger verifies clean. Only the key is needed."""
    key = serialization.load_pem_private_key(Path(KEY).read_bytes(), password=None)
    rows = [json.loads(ln) for ln in Path(LEDGER).read_text().splitlines() if ln.strip()]
    rows[1]["actor_identity"] = "alice"  # frame alice for bob's access to record 43
    prev = "0" * 64
    for r in rows:
        core = {k: v for k, v in r.items() if k not in ("entry_hash", "signature")}
        core["prev_hash"] = prev
        eh = hashlib.sha256(canonical(core)).hexdigest()
        r.clear()
        r.update(core)
        r["entry_hash"] = eh
        r["signature"] = "ed25519:" + key.sign(eh.encode()).hex()
        prev = eh
    Path(LEDGER).write_text("\n".join(json.dumps(r) for r in rows) + "\n")


def main() -> None:
    _seed()
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()

    print(LINE)
    print("  3 crumbs written. Taking a Merkle checkpoint and anchoring it…")
    print(LINE)
    a = anchor.checkpoint(ts)
    print(f"  root {a['root'][:32]}…  (tree_size {a['tree_size']})")
    if a["anchored"]:
        print(f"  anchored to Rekor ✓  logIndex {a['rekor']['logIndex']}")
        print(f"  public, operator can't alter it: {a['rekor']['url']}")
    else:
        print(f"  Rekor unreachable — local checkpoint only ({a['rekor']['error']}).")
        print("  (the rollback below is still caught: the mismatch is offline math.)")

    print("\n  Chain verify + anchor verify, before any tampering:")
    print(f"    chain:  {'VERIFIED' if verify_ledger(LEDGER, PUB).ok else 'MISMATCH'}")
    print(f"    anchor: {'MATCH' if anchor.verify_anchors()['ok'] else 'MISMATCH'}")

    print("\n" + LINE)
    print("  Operator rolls back history — rewrites a row AND re-signs the whole chain.")
    print(LINE)
    _operator_rollback()

    chain = verify_ledger(LEDGER, PUB)
    av = anchor.verify_anchors()
    print(f"    chain verify:  {'VERIFIED ✓' if chain.ok else 'MISMATCH ✗'}"
          "   ← the signed chain is fooled. The forgery is internally perfect.")
    print(f"    anchor verify: {'MATCH ✓' if av['ok'] else 'MISMATCH ✗'}"
          "   ← the external anchor catches it.")
    if not av["ok"]:
        print(f"        anchored root  {av['anchored_root'][:32]}…")
        print(f"        rewritten root {av['recomputed_root'][:32]}…")

    print("\n" + LINE)
    print("  Per-entry signatures stop everyone but the key-holder.")
    print("  Anchoring the root to a log you don't control stops the key-holder too.")
    print(LINE)


if __name__ == "__main__":
    main()
