"""
Cross-vendor demo (P3) — same action, two protocols, one recorder.

Run: python -m crumb.cross_vendor_demo

The claim Crumb makes is that attribution is a property of the runtime, not the
wire. So it has to survive a change of wire. Here one human ('alice') drives the
same action — read patient record 42 — twice: once as an OpenAI function-call,
once as an MCP `tools/call`. Both go through the SAME gateway and land in ONE
tamper-evident schema, distinguished only by a `transport` field. Then we verify
the combined ledger.

If the two crumbs carry the same `actor_identity` over two different transports,
the attribution lives in the gateway, exactly as advertised.
"""

from __future__ import annotations

from . import auth, mcp_server
from .agent import ToolCall
from .gateway import Gateway
from .ledger import Ledger
from .verify import verify_ledger

LEDGER = "data/ledger.jsonl"
KEY = "data/ledger.key"
PUB = "data/ledger.pub"
LINE = "─" * 70


def main() -> None:
    session = auth.login("alice")
    ledger = Ledger(path=LEDGER, key_path=KEY)
    ledger.reset()  # fresh chain so the side-by-side is deterministic
    gw = Gateway(ledger=ledger, agent_id="crumb-agent-1")

    print(LINE)
    print(f"  Human authenticated once.  sub = {session.human!r}")
    print("  Same action, two protocols. Watch where the identity comes from.")
    print(LINE)

    # ---- OpenAI function-calling: identity is nowhere on the wire ----------
    openai_wire = {"name": "read_record", "arguments": {"record_id": 42}}
    openai_call = ToolCall.from_openai(openai_wire)
    print("\n  [1] OpenAI function-call wire:")
    print(f"      {openai_wire}")
    print("      → no actor field. Identity is runtime convention, not protocol.")
    d_openai = gw.dispatch(session, openai_call, transport="openai")

    # ---- MCP tools/call: identity rides the Authorization header -----------
    mcp_wire = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "read_record", "arguments": {"record_id": 42}},
    }
    mcp_call = ToolCall.from_mcp(mcp_wire)
    print("\n  [2] MCP tools/call wire (JSON-RPC):")
    print(f"      {mcp_wire['params']}")
    print("      → still no actor in params. The token carries it, out-of-band.")
    d_mcp = gw.dispatch(session, mcp_call, transport="mcp")
    actor = d_mcp.result["_actor"]
    print(f"      MCP resource server read sub from the token: "
          f"human {actor['human']!r} + agent {actor['agent']!r}")

    # ---- Two crumbs, one schema -------------------------------------------
    print("\n" + LINE)
    print("  Two crumbs, one canonical schema (transport is the only delta):")
    print(LINE)
    hdr = f"  {'seq':>3}  {'transport':<9}  {'actor_identity':<14}  {'action':<12}  outcome"
    print(hdr)
    for rec in (d_openai.record, d_mcp.record):
        print(f"  {rec['seq']:>3}  {rec['transport']:<9}  {rec['actor_identity']:<14}  "
              f"{rec['action']:<12}  {rec['outcome']}")

    # ---- Prove the combined ledger is intact ------------------------------
    print("\n  Verifying the combined ledger…")
    r = verify_ledger(LEDGER, PUB)
    status = (f"  VERIFIED ✓  {r.checked} entries — chain intact, all signatures valid."
              if r.ok else f"  MISMATCH ✗  {len(r.issues)} problem(s).")
    print(status)

    print("\n" + LINE)
    print("  Same recorder. Two protocols. One tamper-evident schema.")
    print(f"  Both crumbs trace to {session.human!r} — attribution lives in the gateway,")
    print("  not the wire. That is the cross-vendor proof.")
    print(LINE)


if __name__ == "__main__":
    main()
