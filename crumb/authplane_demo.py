"""
AuthPlane delegation claims → Crumb per-call record. The consume side, over a real wire.

Run: python -m crumb.authplane_demo

An authorization server proves entitlement ONCE, at mint time, before any of the
calls it will authorize exist yet. One token then covers hundreds of tool calls.
So the token can say a human delegated to an agent; it cannot say which calls
that agent went on to make. Those are two different records and they live in two
different places — mint-time provenance at the AS, call-time record at the
resource server.

This demo is the join. It stands `records-mcp` up as a real HTTP Resource Server,
sends it AuthPlane-shaped bearer tokens over actual TCP, and shows what the
per-call record looks like on the other side: the AS's `act` chain consumed as
the identity anchor, then written into a hash-chained, Ed25519-signed crumb that
a third party can verify without trusting either of us.

  [1] flat agent_id + agent_chain   — the fast path the flat claims exist for
  [2] chain emitted oldest-first    — normalized against the authoritative actor
  [3] plain nested `act`            — a stock RFC 8693 issuer, no flat mirrors
  [4] service account, no actor     — the human is gone; the gap Crumb records
  [5] flat vs nested disagreeing    — reported, not smoothed away

SCOPE, stated plainly: these tokens are AuthPlane-SHAPED, not AuthPlane-issued.
The claim names (`agent_id`, `agent_chain`, `actor_type`) are taken from
docs.authplane.ai/sdks/python and the signature here is Crumb's local dev key, so
what this proves is the consume path, not a live federation handshake. Pointing
it at a real AuthPlane tenant is a JWKS URL away — Crumb already verifies
issuer-signed tokens against a live `.well-known` (see crumb/federation.py) — and
that is the next leg, not this one.
"""

from __future__ import annotations

import threading
import time

import httpx
import jwt
import uvicorn

from . import tokens
from .ledger import Ledger
from .mcp_http import app
from .verify import verify_ledger

LEDGER = "data/authplane.jsonl"
KEY = "data/authplane.key"
PUB = "data/authplane.pub"
HOST, PORT = "127.0.0.1", 8734
MCP_URL = f"http://{HOST}:{PORT}/mcp"
ISSUER = "https://as.authplane.ai"
RESOURCE = "read_record"
LINE = "─" * 74


def _serve() -> uvicorn.Server:
    server = uvicorn.Server(uvicorn.Config(app, host=HOST, port=PORT, log_level="error"))
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(100):
        if server.started:
            return server
        time.sleep(0.05)
    raise RuntimeError("records-mcp did not start")


def _token(**claims) -> str:
    """An AuthPlane-shaped bearer, signed with Crumb's dev key (see SCOPE above)."""
    now = int(time.time())
    body = {"iss": ISSUER, "aud": RESOURCE, "iat": now, "exp": now + 300, **claims}
    return jwt.encode(body, tokens._secret(), algorithm="HS256")


def _call(bearer: str) -> dict:
    """One governed tool call over the real wire, token in the Authorization header."""
    resp = httpx.post(
        MCP_URL,
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
              "params": {"name": RESOURCE, "arguments": {"record_id": 42}}},
        headers={"Authorization": f"Bearer {bearer}"},
        timeout=10.0,
    )
    return resp.json()["result"]["_actor"]


CASES = [
    (
        "flat agent_id + agent_chain",
        "the fast path — one lookup, no nested descent per call",
        {"sub": "alice", "agent_id": "planner",
         "agent_chain": ["planner", "researcher"], "actor_type": "agent",
         "act": {"sub": "planner", "act": {"sub": "researcher"}}},
    ),
    (
        "agent_chain emitted oldest-first",
        "orientation decided by the authoritative actor, never assumed",
        {"sub": "alice", "agent_id": "planner",
         "agent_chain": ["researcher", "planner"], "actor_type": "agent"},
    ),
    (
        "plain nested act, no flat mirrors",
        "a stock RFC 8693 issuer still resolves, via the walk",
        {"sub": "alice", "act": {"sub": "planner", "act": {"sub": "researcher"}}},
    ),
    (
        "service account, no actor at all",
        "what most MCP deployments send — the human never rode it",
        {"sub": "svc-records-bot"},
    ),
    (
        "flat chain disagrees with nested act",
        "one token, two representations, contradiction preserved",
        {"sub": "alice", "agent_id": "planner",
         "agent_chain": ["planner", "researcher"], "actor_type": "agent",
         "act": {"sub": "planner", "act": {"sub": "ghost"}}},
    ),
]


def main() -> None:
    server = _serve()
    try:
        ledger = Ledger(path=LEDGER, key_path=KEY)
        ledger.reset()
        written = []

        print(LINE)
        print(f"  records-mcp live at {MCP_URL}   issuer: {ISSUER}")
        print("  AuthPlane-shaped bearers over real TCP. What survives to the record?")
        print(LINE)

        for i, (title, why, claims) in enumerate(CASES, 1):
            actor = _call(_token(**claims))
            print(f"\n  [{i}] {title}")
            print(f"      {why}")
            print(f"      resolved   human={actor['human']!r}  agent={actor['agent']!r}")
            print(f"      chain      {actor['chain']!r}  (most-recent first, "
                  f"read from {actor['source']!r})")
            if actor["actor_type"]:
                print(f"      actor_type {actor['actor_type']!r}")
            if actor["discrepancy"]:
                print(f"      ⚠ {actor['discrepancy']}")

            # What downstream actually does with the claim: it stops being an
            # assertion about entitlement and becomes a record of one call.
            fields = {
                "actor_identity": actor["human"],
                "agent_id": actor["agent"],
                "action": RESOURCE,
                "resource_id": {"record_id": 42},
                "on_behalf_assertion": "delegated" if actor["human"] else "service-account",
                "outcome": "success",
                "transport": "mcp",
                "claim_source": actor["source"],     # which representation answered
                "issuer": ISSUER,
            }
            if actor["chain"]:
                fields["actor_chain"] = actor["chain"]
            if actor["actor_type"]:
                fields["actor_type"] = actor["actor_type"]
            if actor["discrepancy"]:
                fields["claim_discrepancy"] = actor["discrepancy"]
            rec = ledger.append(fields)
            written.append(rec)
            print(f"      crumb #{rec['seq']}  {rec['entry_hash'][:16]}…")

        print("\n" + LINE)
        print("  The ledger those five calls produced:")
        print(LINE)
        print(f"  {'seq':>3}  {'actor_identity':<16}  {'agent_id':<16}  "
              f"{'src':<5}  chain")
        for rec in written:
            print(f"  {rec['seq']:>3}  {str(rec['actor_identity']):<16}  "
                  f"{rec['agent_id']:<16}  {rec['claim_source']:<5}  "
                  f"{rec.get('actor_chain', [])}")

        print("\n  Verifying…")
        r = verify_ledger(LEDGER, PUB)
        print(f"  VERIFIED ✓  {r.checked} entries — chain intact, signatures valid."
              if r.ok else f"  MISMATCH ✗  {len(r.issues)} problem(s).")

        print("\n" + LINE)
        print("  The token asserted delegation once, before any of these calls existed.")
        print("  seq 0-2 resolve identically from three different wire shapes, which is")
        print("  the point: the record doesn't care how the AS spelled the chain.")
        print("  seq 3 is the gap — same wire, no actor, the human unrecoverable.")
        print("  seq 4 is why the record is not just a copy of the claim: a token that")
        print("  disagrees with itself still produced an answerable call, and the")
        print("  contradiction is now in a signed record instead of nowhere.")
        print(LINE)
    finally:
        server.should_exit = True


if __name__ == "__main__":
    main()
