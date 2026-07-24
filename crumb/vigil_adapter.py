"""
Vigil → Crumb adapter — attribute a scan-flagged tool call to the authorizing human.

Vigil's scan-tools flags a poisoned MCP tool at registration; when that tool actually
executes, Vigil's MCPWatch fires an `attributor(event)` callback. Vigil deliberately
does not resolve the human — that's this adapter's job. It reads WHO from the
authenticated session (never from the model), reconciles the call against what the
human actually authorized at login, and appends a signed, hash-chained crumb.

A scan-flagged call the human never directed lands with directive=null and
on_behalf_assertion="unauthorized" — the exact shape `verify.find_unauthorized`
already reconciles, so the same reconciliation that catches a hijacked gateway call
catches a hijacked observed call. The action pins on the AGENT, not the human.

Flight recorder, not control plane (SPEC §3): Vigil observes the call AFTER it runs,
so this records and proves — it does not prevent. That is the whole point. Prevention
at the tool definition is porous (Vigil FINDING-11: a value slot overrides a
description that swears the tool is safe), so the durable control is a tamper-evident
record of who was accountable when the call fired anyway.

The `event` dict is Vigil's hook payload (kept in sync with vigil.mcpwatch, but this
module does NOT import vigil — the contract is just the dict shape, mirroring how
Vigil doesn't import Crumb):
    {"server", "tool_name", "status", "reason", "flagged_fields": [...], "timestamp"}
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable

from . import auth
from .auth import Session
from .ledger import Ledger


class VigilAttributor:
    """A Vigil `attributor` callback backed by a Crumb ledger.

    Wire it into a Vigil-monitored host:

        attr  = VigilAttributor(ledger, session_provider=get_current_session)
        watch = instrument(mcp, attributor=attr)   # (in the host, Vigil side)

    `session_provider` returns the current authenticated Session — the host holds it
    in request context; the attributor pulls the human from it at call time, so the
    identity is read from verified claims, never asserted by the agent.
    """

    def __init__(self, ledger: Ledger, session_provider: Callable[[], Session],
                 agent_id: str = "vigil-observed"):
        self.ledger = ledger
        self.session_provider = session_provider
        self.agent_id = agent_id

    @classmethod
    def for_session(cls, ledger: Ledger, session: Session, **kw) -> "VigilAttributor":
        """Convenience for a fixed single session (tests / single-user hosts)."""
        return cls(ledger, session_provider=lambda: session, **kw)

    def __call__(self, event: dict) -> dict:
        session = self.session_provider()
        # WHO + WHAT-WAS-AUTHORIZED — both from the verified session, never the model.
        claims = auth.verify_session(session.token)
        human = claims["sub"]
        authorized = claims.get("directives", [])

        tool = event.get("tool_name", "<unknown>")
        # RECONCILE INTENT — did the human actually authorize this action? Match the
        # tool name AND the argument scope, so a same-verb call against a resource the
        # human never named has no human authority behind it. A poisoned tool that
        # fires without a matching directive lands unauthorized.
        is_authorized, _ = auth.authorizes(authorized, tool, event.get("arguments") or {})

        fields = {
            "actor_identity": human,
            "agent_id": self.agent_id,          # the agent Vigil observed reaching the tool
            "action": tool,
            "directive": tool if is_authorized else None,          # the human authority, or null
            "on_behalf_assertion": "delegated" if is_authorized else "unauthorized",
            "outcome": event.get("status", "success"),
            "transport": "vigil-hook",          # provenance: observed post-hoc, not gateway-dispatched
            # The registration-time scan finding that made this call worth recording —
            # where the directive rode in, straight from Vigil's scan-tools.
            "scan_flag": {
                "source": "vigil.scan-tools",
                "reason": event.get("reason"),
                "fields": event.get("flagged_fields", []),
            },
            "ts": event.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        }
        return self.ledger.append(fields)
