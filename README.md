# Crumb

**Prove which human directed an AI agent's action — across MCP and OpenAI function-calling — in a tamper-evident record an auditor can verify without trusting you.**

Every agent action drops a crumb. The trail leads back to the human who directed it.

## The problem

AI agents run under service accounts and shared API keys. So when an agent reads a patient record, exports customer data, or moves money, your audit log says *the agent did it* — not *which human told it to*.

That gap is about to be illegal. The EU AI Act (Article 12, in force Aug 2 2026) requires high-risk systems to log "the identification of the natural persons involved." A service-account log can't answer that.

And it isn't a model problem you can prompt your way out of. A tool call from a model is just `{"name": ..., "arguments": ...}` — there is no field for *who*. Worse, anything the model emits can be prompt-injected, so identity must never come *from* the model. It has to be stamped by the runtime, outside the agent's reasoning.

Crumb is the runtime that stamps it.

## What it is (and isn't)

Crumb is a **flight recorder** for agent actions: read-only, after-the-fact, provable. It records who-did-what and proves the record wasn't altered.

It is **not** a control plane. It doesn't block, doesn't author policy, doesn't draw an identity graph. Those are the funded lane (Cerbos, Capsule, Astrix); Crumb stays in its lane — forensics and accountability — and points at them for enforcement.

## Roadmap

- **P0 — Skeleton** ✓ A human logs in, an agent calls a tool, and the tool call carries zero identity. The gap, made visible.
- **P1 — Gateway + signed record** ✓ The gateway pulls the human from the session (never from the model), binds them to the agent in an RFC 8693-shaped delegation token, the tool serves data only against that token, and a hash-chained, Ed25519-signed crumb lands in the ledger.
- **P2 — Verifier + tamper demo** ← *you are here.* A `verify` CLI proves the log is intact. Edit one past row and it screams `MISMATCH`.
- **P3 — Cross-vendor.** Same recorder fronts a real MCP server. One schema, two protocols.
- **P4 — Timeline view + external anchor.** One screen, and checkpoints anchored where even the operator can't rewrite them.

Full design in [`SPEC.md`](./SPEC.md).

## Quickstart (P0)

```bash
pip install -r requirements.txt
python -m crumb.demo
```

You'll watch a human authenticate, an agent decide to read a "regulated" record, and the tool call go out with no idea who's behind it. That's the problem P1 solves.
