"""
Cross-vendor demo (P3) — same action, two protocols, one recorder, REAL wire.

Run: python -m crumb.cross_vendor_demo

The claim Crumb makes is that attribution is a property of the runtime, not the
wire. So it has to survive a change of wire — and an actual wire, not a function
call wearing an MCP costume. This demo stands `records-mcp` up as a real HTTP
service in a background thread, then drives one human's action — read patient
record 42 — two ways through the SAME gateway:

  [1] OpenAI function-call  (identity is nowhere on the wire, pure runtime convention)
  [2] MCP tools/call        (a real HTTP POST; the token rides Authorization: Bearer)

Both land in ONE tamper-evident schema, distinguished only by a `transport` field.

Then the part that is the actual product: over that same real wire, the same call
with two different tokens. A plain service-account bearer (what most MCP
deployments send) and Crumb's delegation token. Watch which one can still name
the human. Finally we verify the combined ledger and show the 401 a real Resource
Server returns when no token shows up at all.
"""

from __future__ import annotations

import threading
import time

import httpx
import uvicorn

from . import auth, tokens
from .agent import ToolCall
from .gateway import Gateway
from .ledger import Ledger
from .mcp_http import app
from .verify import verify_ledger

LEDGER = "data/ledger.jsonl"
KEY = "data/ledger.key"
PUB = "data/ledger.pub"
HOST, PORT = "127.0.0.1", 8731
MCP_URL = f"http://{HOST}:{PORT}/mcp"
AGENT_ID = "crumb-agent-1"
LINE = "─" * 70


def _serve() -> uvicorn.Server:
    """Bring records-mcp up on a real TCP port in a background thread."""
    server = uvicorn.Server(uvicorn.Config(app, host=HOST, port=PORT, log_level="error"))
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(100):  # wait up to ~5s for the socket to be listening
        if server.started:
            return server
        time.sleep(0.05)
    raise RuntimeError("records-mcp did not start")


def _call(rpc: dict, bearer: str | None) -> httpx.Response:
    """A raw MCP client call over the real wire — token in the header or not."""
    headers = {"Authorization": f"Bearer {bearer}"} if bearer else {}
    return httpx.post(MCP_URL, json=rpc, headers=headers, timeout=10.0)


def main() -> None:
    server = _serve()
    try:
        session = auth.login("alice", directives=("read_record",))
        ledger = Ledger(path=LEDGER, key_path=KEY)
        ledger.reset()  # fresh chain so the side-by-side is deterministic
        gw = Gateway(ledger=ledger, agent_id=AGENT_ID, mcp_url=MCP_URL)

        print(LINE)
        print(f"  records-mcp is live at {MCP_URL}")
        print(f"  Human authenticated once.  sub = {session.human!r}")
        print("  Same action, two protocols. Watch where the identity comes from.")
        print(LINE)

        # ---- [1] OpenAI function-calling: identity is nowhere on the wire -----
        openai_call = ToolCall.from_openai({"name": "read_record", "arguments": {"record_id": 42}})
        print("\n  [1] OpenAI function-call — no actor field on the wire.")
        print("      Identity is runtime convention, the gateway supplies it.")
        d_openai = gw.dispatch(session, openai_call, transport="openai")

        # ---- [2] MCP tools/call: a REAL HTTP hop, token in the header --------
        mcp_call = ToolCall.from_mcp({
            "method": "tools/call",
            "params": {"name": "read_record", "arguments": {"record_id": 42}},
        })
        print("\n  [2] MCP tools/call — real HTTP POST to records-mcp.")
        print("      Still no actor in params. The token carries it in the header.")
        d_mcp = gw.dispatch(session, mcp_call, transport="mcp")
        actor = d_mcp.result["_actor"]
        print(f"      records-mcp read the actor off the token over the wire: "
              f"human {actor['human']!r} + agent {actor['agent']!r}")

        # ---- Two crumbs, one schema ------------------------------------------
        print("\n" + LINE)
        print("  Two crumbs, one canonical schema (transport is the only delta):")
        print(LINE)
        print(f"  {'seq':>3}  {'transport':<9}  {'actor_identity':<14}  {'action':<12}  outcome")
        for rec in (d_openai.record, d_mcp.record):
            print(f"  {rec['seq']:>3}  {rec['transport']:<9}  {rec['actor_identity']:<14}  "
                  f"{rec['action']:<12}  {rec['outcome']}")

        # ---- The product: same wire, two tokens, who survives ----------------
        print("\n" + LINE)
        print("  Same call, same wire, two tokens. Which one still names the human?")
        print(LINE)
        rpc = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
               "params": {"name": "read_record", "arguments": {"record_id": 42}}}

        svc_token = tokens.mint_service_account("svc-records-bot", resource="read_record")
        svc_actor = _call(rpc, svc_token).json()["result"]["_actor"]
        print(f"\n  service-account token (what most deployments send):")
        print(f"      server can prove: human {svc_actor['human']!r}, agent {svc_actor['agent']!r}")
        print("      → the human is gone. the audit log can only blame a bot.")

        deleg_token = tokens.mint_delegation("alice", AGENT_ID, resource="read_record")
        deleg_actor = _call(rpc, deleg_token).json()["result"]["_actor"]
        print(f"\n  Crumb delegation token (sub + act):")
        print(f"      server can prove: human {deleg_actor['human']!r}, agent {deleg_actor['agent']!r}")
        print("      → the human survived the wire. that delta is the product.")

        # ---- Real Resource-Server behavior: no token, no data ----------------
        no_token = _call(rpc, None)
        print(f"\n  No token at all → HTTP {no_token.status_code} "
              f"{no_token.headers.get('www-authenticate', '')}")

        # ---- Drive it yourself ----------------------------------------------
        print("\n  Reproduce the wire with any client:")
        print(f"    curl -s {MCP_URL} -H 'Authorization: Bearer {deleg_token[:24]}…' \\")
        print("      -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\","
              "\"params\":{\"name\":\"read_record\",\"arguments\":{\"record_id\":42}}}'")

        # ---- Prove the combined ledger is intact -----------------------------
        print("\n  Verifying the combined ledger…")
        r = verify_ledger(LEDGER, PUB)
        print(f"  VERIFIED ✓  {r.checked} entries — chain intact, all signatures valid."
              if r.ok else f"  MISMATCH ✗  {len(r.issues)} problem(s).")

        print("\n" + LINE)
        print("  One recorder. Two protocols, one a real HTTP hop. One schema.")
        print("  Attribution lives in the gateway and the token, not the wire.")
        print("  That is the cross-vendor proof.")
        print(LINE)
    finally:
        server.should_exit = True


if __name__ == "__main__":
    main()
