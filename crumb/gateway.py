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
    def __init__(self, ledger: Ledger, agent_id: str, mcp_url: str | None = None,
                 bind_token: bool = False):
        self.ledger = ledger
        self.agent_id = agent_id
        # When True, the delegation token minted for each call is persisted into
        # the crumb as `actor_token`, so a verifier can later re-walk it and
        # cryptographically confirm the recorded human (see verify_actor_binding).
        # Default False keeps every existing crumb byte-identical — the
        # deterministic web seed and its Rekor anchor depend on stable hashes.
        self.bind_token = bind_token
        # When set, the MCP path is a real HTTP hop to records-mcp (P3). When
        # None, it falls back to an in-process call — used by the deterministic
        # web seed, which reproduces a fixed timeline and can't depend on a live
        # server being up next to it. The attribution logic is identical either
        # way; only the wire changes.
        self.mcp_url = mcp_url

    def dispatch(self, session: Session, call: ToolCall, transport: str = "openai",
                 ts: str | None = None, via: list | None = None) -> Dispatch:
        # 1. WHO + WHAT-WAS-AUTHORIZED — both come from the verified session, not
        #    from the model. `directives` is the set of actions the human approved
        #    at login; the model can't add to it.
        claims = auth.verify_session(session.token)
        human = claims["sub"]
        authorized = claims.get("directives", [])

        # 1b. RECONCILE INTENT — is this call something the human actually directed?
        #     Match on the tool name AND the argument scope the human authorized, so
        #     an authorized read_record(42) does NOT clear a same-verb read_record(43)
        #     the hijack slipped in. If a directive matches, point the crumb at it. If
        #     none does, the crumb records the action with NO human directive and flags
        #     it unauthorized — that's how a prompt-injected/hijacked call is exposed
        #     and pinned on the agent, not falsely on the human.
        is_authorized, directive = auth.authorizes(authorized, call.name, call.arguments)
        on_behalf = "delegated" if is_authorized else "unauthorized"

        # 2. BIND — get a delegation token carrying (human + agent), scoped to the tool.
        #    Passing the session token lets the bind resolve to a real RFC 8693
        #    exchange against the IdP when one is configured (CRUMB_IDP_URL); with
        #    no IdP it falls back to a local dev mint. The gateway doesn't branch.
        resource = call.name
        if via:
            # Multi-hop: the human directed via[0], who delegated down the chain to
            # via[-1], the agent that actually calls the tool. Mint the first hop,
            # then nest each subsequent actor (RFC 8693 §4.1). The human stays `sub`
            # the whole way; the token carries the full, signed delegation chain.
            token = tokens.mint_delegation(
                human, via[0], resource, session_token=session.token
            )
            for hop in via[1:]:
                token = tokens.extend_delegation(token, hop, resource)
            acting_agent = via[-1]
            # A real chain (2+ hops) records actor_chain; a single-element via is
            # just single-hop with a named agent, so it omits the field and stays
            # hash-identical to an agent_id dispatch — the determinism invariant.
            chain = list(reversed(via)) if len(via) > 1 else None  # most-recent first
        else:
            token = tokens.mint_delegation(
                human, self.agent_id, resource, session_token=session.token
            )
            acting_agent = self.agent_id
            chain = None

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
        fields = {
            "actor_identity": human,
            "agent_id": acting_agent,            # the agent that reached the tool
            "action": call.name,
            "resource_id": call.arguments,
            "directive": directive,              # the human authority, or null
            "on_behalf_assertion": on_behalf,    # "delegated" vs "unauthorized"
            "outcome": outcome,
            "transport": transport,
            "ts": ts or datetime.now(timezone.utc).isoformat(),
        }
        # Multi-hop only: record the full delegation path, most-recent actor first.
        # Single-hop crumbs omit the field entirely, so their hashes are unchanged
        # and the deterministic web seed + Rekor anchor stay byte-for-byte stable.
        if chain is not None:
            fields["actor_chain"] = chain
        # Opt-in: bind the token to the crumb so the human is later provable from
        # the ledger alone, not just asserted. Gated so untokened crumbs stay
        # hash-stable for the anchored seed.
        if self.bind_token:
            fields["actor_token"] = token
        record = self.ledger.append(fields)
        return Dispatch(result=result, record=record, token=token)

    def _dispatch_openai(self, call: ToolCall, token: str) -> object:
        """OpenAI path: the tool is a local function. Identity is pure runtime
        convention — the protocol gives us no place to put it on the wire."""
        fn = getattr(tools, call.name)
        return fn(token=token, **call.arguments)

    def _dispatch_mcp(self, call: ToolCall, token: str) -> object:
        """MCP path: re-issue the call to records-mcp as a JSON-RPC `tools/call`,
        with the exchanged token in the Authorization header. The server reads the
        actor from it — the same human, proven over a different wire.

        If `mcp_url` is set the hop is real HTTP (P3); otherwise it's an
        in-process call to the same handler (the deterministic web seed)."""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": call.name, "arguments": call.arguments},
        }

        if self.mcp_url:
            import httpx

            resp = httpx.post(
                self.mcp_url,
                json=request,
                headers={"Authorization": f"Bearer {token}"},
                timeout=10.0,
            ).json()
        else:
            from . import mcp_server

            resp = mcp_server.handle(request, bearer=token)

        if "error" in resp:
            raise RuntimeError(resp["error"]["message"])
        return resp["result"]
