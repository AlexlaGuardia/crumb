"""
Tamper demo — the money shot.

Writes a few real crumbs, verifies the ledger (VERIFIED), then hand-edits one
past entry the way an insider covering their tracks would — and watches
verification catch it.

Run: python -m crumb.tamper_demo
"""

from __future__ import annotations

import json
from pathlib import Path

from . import auth
from .agent import ToolCall
from .gateway import Gateway
from .ledger import Ledger
from .verify import verify_ledger

LEDGER = "data/ledger.jsonl"
KEY = "data/ledger.key"
PUB = "data/ledger.pub"
LINE = "─" * 66


def _act(gateway: Gateway, who: str, record_id: int) -> None:
    session = auth.login(who)
    gateway.dispatch(session, ToolCall(name="read_record", arguments={"record_id": record_id}))


def main() -> None:
    ledger = Ledger(path=LEDGER, key_path=KEY)
    ledger.reset()
    gw = Gateway(ledger=ledger, agent_id="crumb-agent-1")

    # A few real actions, each leaving a signed crumb.
    _act(gw, "alice", 42)   # alice reads record 42
    _act(gw, "bob", 43)     # bob reads record 43
    _act(gw, "alice", 99)   # alice hits a record that doesn't exist → denied

    print(LINE)
    print("  3 crumbs written (alice→42, bob→43, alice→99 denied). Verifying…")
    print(LINE)
    r = verify_ledger(LEDGER, PUB)
    print(f"  VERIFIED ✓  {r.checked} entries — chain intact, all signatures valid.\n")

    # Now tamper, the way an insider would: pin bob's lookup on alice.
    lines = Path(LEDGER).read_text().splitlines()
    victim = json.loads(lines[1])
    print(LINE)
    print(f"  Tampering entry 1:  actor_identity {victim['actor_identity']!r} → 'alice'")
    print("  (framing alice for bob's access to record 43)")
    print(LINE)
    victim["actor_identity"] = "alice"
    lines[1] = json.dumps(victim)
    Path(LEDGER).write_text("\n".join(lines) + "\n")

    print("  Re-verifying the edited ledger…\n")
    r = verify_ledger(LEDGER, PUB)
    if r.ok:
        print("  VERIFIED ✓  — this should not happen.")
    else:
        print(f"  MISMATCH ✗  {r.checked} entries checked, {len(r.issues)} problem(s):")
        for seq, reason in r.issues:
            print(f"    entry {seq}: {reason}")

    print()
    print(LINE)
    print("  The edit changed the data but not the math. The crumb can't be faked.")
    print(LINE)


if __name__ == "__main__":
    main()
