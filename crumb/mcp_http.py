"""
records-mcp over a real wire (P3) — the MCP Resource Server as an HTTP service.

Until now the "MCP path" was a function call in the same process labeled
`transport="mcp"`. Honest about the auth, fake about the wire. This makes it
real: `records-mcp` becomes a separate HTTP service that anyone's MCP client can
reach over the network. The delegation token rides a real `Authorization:
Bearer` header — which is the entire reason MCP runs over HTTP and not stdio,
since stdio has no headers and the token has nowhere to live.

It speaks plain JSON-RPC over HTTP (POST a request, get a JSON response). That is
a valid MCP HTTP transport; the Streamable-HTTP/SSE framing (session ids, event
streams) is the documented upgrade, not needed to prove attribution survives the
wire. The auth behavior is the real thing: a `tools/call` with no valid token
gets a 401 with `WWW-Authenticate`, exactly as an OAuth 2.1 Resource Server must.

Run: uvicorn crumb.mcp_http:app --host 127.0.0.1 --port 8731

Then any client can drive it, e.g.:
    curl -s localhost:8731/mcp -H 'Authorization: Bearer <token>' \
      -d '{"jsonrpc":"2.0","id":1,"method":"tools/call",
           "params":{"name":"read_record","arguments":{"record_id":42}}}'
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from . import mcp_server

app = FastAPI(title="records-mcp", docs_url=None, redoc_url=None)

# Where a real RS points unauthenticated callers to learn how to get a token.
_WWW_AUTH = 'Bearer resource_metadata="/.well-known/oauth-protected-resource"'


def _bearer(request: Request) -> str:
    """Pull the token out of the Authorization header — out-of-band from params."""
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    return token if scheme.lower() == "bearer" else ""


@app.post("/mcp")
async def mcp(request: Request) -> JSONResponse:
    """One MCP JSON-RPC endpoint. Auth is read from the header, never the body."""
    try:
        rpc = await request.json()
    except Exception:
        return JSONResponse(
            {"jsonrpc": "2.0", "id": None,
             "error": {"code": -32700, "message": "parse error"}},
            status_code=400,
        )

    try:
        response = mcp_server.handle(rpc, bearer=_bearer(request))
    except mcp_server.Unauthorized as e:
        # Real Resource-Server behavior: no valid token, no data, and a pointer
        # to how to get one. This is the line a service-account-only deployment
        # never has to think about — and exactly where the human gets dropped.
        return JSONResponse(
            {"jsonrpc": "2.0", "id": rpc.get("id"),
             "error": {"code": -32001, "message": str(e)}},
            status_code=401,
            headers={"WWW-Authenticate": _WWW_AUTH},
        )
    return JSONResponse(response)
