"""
P0 demo — the gap, made visible.

Run: python -m crumb.demo

A human authenticates. An agent reads a regulated record on their behalf. And
we show that the tool call — the thing your audit log would capture — has no
idea who the human was. The session knew. The tool call didn't. That's the gap
Crumb closes in P1.
"""

from __future__ import annotations

from . import auth
from .agent import Agent


def main() -> None:
    line = "─" * 64

    # 1. The human authenticates. We capture their identity, once, up front.
    session = auth.login("alice")
    print(line)
    print(f"  Human authenticated.  sub = {session.human!r}")
    print(f"  (session token: {session.token[:32]}…)")
    print(line)

    # 2. The agent acts on the human's instruction.
    agent = Agent()
    prompt = "Please read patient record 42."
    print(f"\n  Prompt to agent:  {prompt!r}\n")

    call, result = agent.run(prompt)

    # 3. The tool call — exactly what a naive audit log records. Look for 'alice'.
    print("  The tool call the agent emitted (this is what gets logged):")
    print("\n".join("    " + ln for ln in call.as_wire_json().splitlines()))
    print(f"\n  Tool result:  {result}\n")

    # 4. The gap.
    print(line)
    print("  THE GAP")
    print(line)
    print("  We KNOW it was alice — the session captured it.")
    print("  But the tool call carries no actor. A service-account audit log")
    print("  would read: \"read_record(42) → success\".  No human. No 'alice'.")
    print()
    print("  EU AI Act Art. 12 requires \"the identification of the natural")
    print("  persons involved.\" This log can't answer that.")
    print()
    print("  P1: a gateway stamps every tool call with the session's human and")
    print("  writes a signed, tamper-evident record. The crumb leads back to alice.")
    print(line)


if __name__ == "__main__":
    main()
