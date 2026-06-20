"""
The gateway — the chokepoint where attribution is enforced.

Every tool call the agent makes goes through here. The gateway pulls the human's
identity FROM THE SESSION — never from the model's arguments, which could be
prompt-injected. It mints a delegation token binding (human + agent), calls the
tool with it, and writes a signed crumb to the ledger.

This is the only place attribution can be enforced for the OpenAI path, and the
clean place for MCP too. One gateway, both protocols. If a tool call can reach a
tool without passing through here, attribution is void — so the tool refuses
calls that arrive without a valid token (see tools.read_record).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from . import auth, tokens, tools
from .agent import ToolCall
from .auth import Session
from .ledger import Ledger


@dataclass
class Dispatch:
    """The outcome of one governed tool call."""

    result: object
    record: dict   # the signed crumb written to the ledger
    token: str     # the delegation token minted for this call


class Gateway:
    def __init__(self, ledger: Ledger, agent_id: str):
        self.ledger = ledger
        self.agent_id = agent_id

    def dispatch(self, session: Session, call: ToolCall, transport: str = "openai",
                 ts: str | None = None) -> Dispatch:
        # 1. WHO + WHAT-WAS-AUTHORIZED — both come from the verified session, not
        #    from the model. `directives` is the set of actions the human approved
        #    at login; the model can't add to it.
        claims = auth.verify_session(session.token)
        human = claims["sub"]
        authorized = claims.get("directives", [])

        # 1b. RECONCILE INTENT — is this call something the human actually directed?
        #     If yes, point the crumb at the authorizing directive. If no, the crumb
        #     records the action with NO human directive and flags it unauthorized —
        #     that's how a prompt-injected/hijacked tool call is exposed and pinned
        #     on the agent, not falsely on the human.
        is_authorized = call.name in authorized
        directive = call.name if is_authorized else None
        on_behalf = "delegated" if is_authorized else "unauthorized"

        # 2. BIND — mint a delegation token carrying (human + agent), scoped to the tool.
        resource = call.name
        token = tokens.mint_delegation(human, self.agent_id, resource)

        # 3. ACT — reach the tool with the token. Whatever wire the call arrived on,
        #    it leaves the chokepoint as a governed call the resource verifies.
        outcome, result = "success", None
        try:
            if transport == "mcp":
                result = self._dispatch_mcp(call, token)
            else:
                result = self._dispatch_openai(call, token)
        except Exception as e:  # tool rejected the call, or the record didn't exist
            outcome, result = "denied", {"error": str(e)}

        # 4. RECORD — write the signed crumb. One schema, both protocols; `transport`
        #    is the only discriminator. The trail leads back to the human either way.
        record = self.ledger.append(
            {
                "actor_identity": human,
                "agent_id": self.agent_id,
                "action": call.name,
                "resource_id": call.arguments,
                "directive": directive,              # the human authority, or null
                "on_behalf_assertion": on_behalf,    # "delegated" vs "unauthorized"
                "outcome": outcome,
                "transport": transport,
                "ts": ts or datetime.now(timezone.utc).isoformat(),
            }
        )
        return Dispatch(result=result, record=record, token=token)

    def _dispatch_openai(self, call: ToolCall, token: str) -> object:
        """OpenAI path: the tool is a local function. Identity is pure runtime
        convention — the protocol gives us no place to put it on the wire."""
        fn = getattr(tools, call.name)
        return fn(token=token, **call.arguments)

    def _dispatch_mcp(self, call: ToolCall, token: str) -> object:
        """MCP path: re-issue the call to an upstream MCP server as a JSON-RPC
        `tools/call`, with the exchanged token in the Authorization header. The
        server reads `sub` from it — the same human, proven over a different wire."""
        from . import mcp_server

        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": call.name, "arguments": call.arguments},
        }
        resp = mcp_server.handle(request, bearer=token)
        if "error" in resp:
            raise RuntimeError(resp["error"]["message"])
        return resp["result"]
