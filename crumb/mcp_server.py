"""
A minimal MCP Resource Server — the P3 cross-vendor path.

MCP servers are OAuth 2.1 Resource Servers. The MCP authorization spec PERMITS a
token-exchanged credential that carries the human (`sub`) plus the agent acting
for them (`act`). But most real deployments front the server with a shared
service-account token and never record WHICH human was behind a call. That gap
is the product.

This server speaks the MCP `tools/call` JSON-RPC envelope and, unlike most,
reads `sub` out of the delegation token the gateway hands it. The token arrives
out-of-band in the Authorization header — never in `params`, which the model
controls and a prompt-injection could forge. Same regulated datastore as the
OpenAI path (`tools._RECORDS`); the only thing that changes is the wire format.
"""

from __future__ import annotations

from . import tokens
from .tools import _RECORDS  # one source of truth for the regulated datastore

SERVER_NAME = "records-mcp"
PROTOCOL_VERSION = "2025-11-25"  # MCP authorization spec this server implements


class Unauthorized(Exception):
    """No valid bearer on a call that needs one. The HTTP layer maps this to a
    real 401 + WWW-Authenticate, the way an OAuth 2.1 Resource Server must."""


def _actor_from_token(bearer: str, resource: str) -> dict:
    """Read who is behind a call FROM THE TOKEN, never from the params.

    Returns {"human": <sub or None>, "agent": <id>}. A delegation token carries
    `act` (the agent acting for a human) → both are known. A service-account
    token has no `act` → the agent is known but the human is gone. That gap, on
    an otherwise identical wire, is the thing Crumb makes visible.
    """
    if not bearer:
        raise Unauthorized("missing bearer token")
    try:
        claims = tokens.verify_delegation(bearer, resource=resource)
    except Exception as e:  # bad signature, wrong audience, expired, malformed
        raise Unauthorized(f"invalid bearer token: {e}") from e

    act = claims.get("act")
    if act:  # delegation: human + agent both ride the token
        return {"human": claims["sub"], "agent": act["sub"]}
    return {"human": None, "agent": claims["sub"]}  # service account: human lost


def tools_list() -> dict:
    """MCP `tools/list` — a capability description with no slot for identity,
    exactly like the OpenAI function schema. The protocol never carries 'who'."""
    return {
        "tools": [
            {
                "name": "read_record",
                "description": "Read a patient record by id.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"record_id": {"type": "integer"}},
                    "required": ["record_id"],
                },
            },
            {
                "name": "export_record",
                "description": "Export a patient record to an external destination URL.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"record_id": {"type": "integer"},
                                   "destination": {"type": "string"}},
                    "required": ["record_id", "destination"],
                },
            },
        ]
    }


def handle(request: dict, *, bearer: str = "") -> dict:
    """Handle one MCP JSON-RPC request.

    `bearer` is the token, delivered the way a real Resource Server receives it:
    in the Authorization header, out-of-band from the call params (which the
    model controls and a prompt-injection could forge). We verify it and READ
    THE ACTOR from it before serving any data — the attribution most MCP servers
    drop on the floor. Raises Unauthorized on a `tools/call` with no valid token.
    """
    rid = request.get("id")
    method = request.get("method")

    # MCP lifecycle handshake — what a real client sends first. No auth needed to
    # discover the server; auth is enforced at the point data is touched.
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": rid,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": "0.1.0"},
            },
        }

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": tools_list()}

    if method == "tools/call":
        params = request.get("params", {})
        name = params.get("name")
        args = params.get("arguments", {})

        # Resource-server check: no valid token, no data. Then read the actor from
        # the token — both who, if a human is even in it.
        actor = _actor_from_token(bearer, resource=name)

        if name == "export_record":
            # The sensitive action — records the attempt, performs no real exfil.
            payload = {"exported": args["record_id"], "destination": args.get("destination"),
                       "note": "attempt recorded; no data left the lab"}
        else:
            payload = _RECORDS[args["record_id"]]
        return {
            "jsonrpc": "2.0",
            "id": rid,
            "result": {
                "content": [{"type": "text", "text": str(payload)}],
                "isError": False,
                # The attribution the spec permits and deployments skip. `human`
                # is null when the caller sent a service-account token.
                "_actor": actor,
            },
        }

    return {
        "jsonrpc": "2.0",
        "id": rid,
        "error": {"code": -32601, "message": f"method not found: {method!r}"},
    }
