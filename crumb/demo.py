"""
Crumb demo — the gap, then the crumb that closes it.

Run: python -m crumb.demo

Act 1: a human authenticates, an agent decides to read a regulated record, and
the tool call goes out with no idea who's behind it. The gap.

Act 2: the same call routed through the gateway. It pulls the human from the
session, binds them to the agent in a delegation token, the tool serves data
only against that token, and a signed crumb lands in the ledger. The trail now
leads back to the human — provably.
"""

from __future__ import annotations

from . import auth, tokens
from .agent import FakeModel
from .gateway import Gateway
from .ledger import Ledger

LINE = "─" * 66


def main() -> None:
    # The human authenticates. We capture their identity once, up front.
    session = auth.login("alice", directives=("read_record",))
    print(LINE)
    print(f"  Human authenticated.  sub = {session.human!r}")
    print(LINE)

    # The agent decides what to do. This is a bare model tool call — no identity.
    model = FakeModel()
    prompt = "Please read patient record 42."
    call = model.decide(prompt)

    print("\n  ACT 1 — the gap")
    print("  The tool call the model emitted (what a naive log records):")
    print("\n".join("    " + ln for ln in call.as_wire_json().splitlines()))
    print("  → no actor. A service-account log would just say read_record(42).\n")

    # Now route the SAME call through the gateway.
    ledger = Ledger(path="data/ledger.jsonl", key_path="data/ledger.key")
    ledger.reset()  # fresh chain so the demo output is deterministic
    gateway = Gateway(ledger=ledger, agent_id="crumb-agent-1")
    dispatch = gateway.dispatch(session, call)

    print("  ACT 2 — the gateway closes it")
    claims = tokens.verify_delegation(dispatch.token, resource=call.name)
    print(f"  Delegation token binds:  human {claims['sub']!r}  +  "
          f"agent {claims['act']['sub']!r}  (scoped to {claims['aud']!r})")
    print(f"  Tool served:  {dispatch.result}\n")

    print("  The signed crumb written to the ledger:")
    rec = dispatch.record
    for k in ("actor_identity", "agent_id", "action", "resource_id", "outcome", "ts"):
        print(f"    {k:15} {rec[k]}")
    print(f"    {'seq':15} {rec['seq']}")
    print(f"    {'prev_hash':15} {rec['prev_hash'][:24]}…")
    print(f"    {'entry_hash':15} {rec['entry_hash'][:24]}…")
    print(f"    {'signature':15} {rec['signature'][:32]}…")

    print()
    print(LINE)
    print(f"  The crumb leads back to {rec['actor_identity']!r}.")
    print("  Every entry is hash-chained to the last and Ed25519-signed.")
    print("  P2: edit any past field and the chain breaks — the `verify` demo.")
    print(LINE)


if __name__ == "__main__":
    main()
