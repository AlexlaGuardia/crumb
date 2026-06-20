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

    def dispatch(self, session: Session, call: ToolCall) -> Dispatch:
        # 1. WHO — the human comes from the verified session, not from the model.
        human = auth.verify_session(session.token)["sub"]

        # 2. BIND — mint a delegation token carrying (human + agent), scoped to the tool.
        resource = call.name
        token = tokens.mint_delegation(human, self.agent_id, resource)

        # 3. ACT — call the tool with the token. The tool verifies a real human is behind it.
        outcome, result = "success", None
        try:
            fn = getattr(tools, call.name)
            result = fn(token=token, **call.arguments)
        except Exception as e:  # tool rejected the call, or the record didn't exist
            outcome, result = "denied", {"error": str(e)}

        # 4. RECORD — write the signed crumb. Now the trail leads back to the human.
        record = self.ledger.append(
            {
                "actor_identity": human,
                "agent_id": self.agent_id,
                "action": call.name,
                "resource_id": call.arguments,
                "outcome": outcome,
                "ts": datetime.now(timezone.utc).isoformat(),
            }
        )
        return Dispatch(result=result, record=record, token=token)
