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
            }
        ]
    }


def handle(request: dict, *, bearer: str) -> dict:
    """Handle one MCP JSON-RPC request.

    `bearer` is the delegation token, delivered the way a real Resource Server
    receives it: in the Authorization header, out-of-band from the call params.
    We verify it and READ THE HUMAN from it before serving any data — the
    attribution most MCP servers drop on the floor.
    """
    rid = request.get("id")
    method = request.get("method")

    if method == "tools/call":
        params = request.get("params", {})
        name = params.get("name")
        args = params.get("arguments", {})

        # Resource-server check: no valid (human + agent) token, no data.
        claims = tokens.verify_delegation(bearer, resource=name)
        human, agent = claims["sub"], claims["act"]["sub"]

        record = _RECORDS[args["record_id"]]
        return {
            "jsonrpc": "2.0",
            "id": rid,
            "result": {
                "content": [{"type": "text", "text": str(record)}],
                "isError": False,
                # The attribution the spec permits and deployments skip:
                "_actor": {"human": human, "agent": agent},
            },
        }

    return {
        "jsonrpc": "2.0",
        "id": rid,
        "error": {"code": -32601, "message": f"method not found: {method!r}"},
    }
