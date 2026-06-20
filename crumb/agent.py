"""
The agent loop.

A real agent asks an LLM what to do, gets back a tool call, and runs it. We use
a FakeModel here so P0 runs anywhere with no API key — but the shape it returns
is exactly what OpenAI/Anthropic emit: an assistant turn with a `tool_calls`
list of `{name, arguments}`. Swap FakeModel for a real client and nothing else
changes (that's the point — the identity gap is in the protocol, not the model).

The thing to notice: the tool call has no field for the human. The agent runs
the tool with no idea who it's acting for. In P0 we just expose that gap. P1's
gateway is what closes it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass


@dataclass
class ToolCall:
    """One tool call as a model emits it. Note: no actor, no human, no identity."""

    name: str
    arguments: dict

    def as_wire_json(self) -> str:
        """How this looks on the wire — what a naive audit log would capture."""
        return json.dumps({"name": self.name, "arguments": self.arguments}, indent=2)

    @classmethod
    def from_openai(cls, tool_call: dict) -> "ToolCall":
        """Normalize an OpenAI function-call. `arguments` is a JSON string on the
        wire; either form is accepted. Neither carries a human — by protocol."""
        fn = tool_call.get("function", tool_call)
        args = fn.get("arguments", {})
        if isinstance(args, str):
            args = json.loads(args or "{}")
        return cls(name=fn["name"], arguments=args)

    @classmethod
    def from_mcp(cls, request: dict) -> "ToolCall":
        """Normalize an MCP `tools/call` JSON-RPC request to the same canonical
        shape. Different wire, same gap: identity is nowhere in the envelope."""
        params = request.get("params", {})
        return cls(name=params["name"], arguments=params.get("arguments", {}))


class FakeModel:
    """Stands in for an LLM. Returns a fixed tool call for a known prompt."""

    def decide(self, prompt: str) -> ToolCall:
        # A real model would reason over `prompt` + tools.TOOLS and return this
        # same structure. We hardcode one call so the demo is deterministic.
        if "record 42" in prompt:
            return ToolCall(name="read_record", arguments={"record_id": 42})
        raise ValueError(f"FakeModel has no canned response for: {prompt!r}")


class Agent:
    """Asks the model what to do, then reaches tools ONLY through the gateway.

    The agent has no direct path to tools — every call is dispatched through the
    gateway, which is where the human identity gets stamped on. That enforced
    chokepoint is the whole design; without it, attribution is unenforceable.
    """

    def __init__(self, gateway, session, model: FakeModel | None = None):
        self.gateway = gateway
        self.session = session
        self.model = model or FakeModel()

    def decide(self, prompt: str) -> ToolCall:
        """What the model wants to do — a bare tool call, no identity in it."""
        return self.model.decide(prompt)

    def run(self, prompt: str):
        """Decide, then dispatch through the gateway. Returns (call, Dispatch)."""
        call = self.decide(prompt)
        dispatch = self.gateway.dispatch(self.session, call)
        return call, dispatch
