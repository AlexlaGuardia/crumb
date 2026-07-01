You put an LLM agent into production. It runs under a service account or a shared API key, because that's how you give software credentials. It reads a record, exports a file. Sometimes it moves money. Your audit log dutifully records the action. It says *the agent did it*.

It does not say *which human told it to*.

That's fine right up until it isn't. If the agent does something it shouldn't have, "the service account did it" is not an answer anyone can act on. You can't discipline a service account. You can't tell a regulator that a bot was responsible and leave it there.

## The deadline that makes this concrete

The EU AI Act, Article 12, comes into force on August 2 2026. High-risk systems have to keep logs that allow "the identification of the natural persons involved" in an event. A natural person. Not a service account, not an agent id. The actual human.

A log built around shared credentials can't answer that question. The identity was never captured, so no amount of log retention brings it back.

## You can't prompt your way out of this

The obvious instinct is to make the model report who it's acting for. Put the user in the system prompt, have the agent include it in the tool call.

Two problems.

A tool call, on the wire, is `{"name": "export_record", "arguments": {...}}`. There is no field for *who*. OpenAI function-calling has no native identity slot. MCP permits carrying it but almost nobody implements it. So at the protocol level, the "who" has nowhere to live.

And worse, anything the model emits can be prompt-injected. If identity comes *from* the model, then the data the agent reads back from a tool can rewrite it. I tested this on the same payload delivered two ways, and the tool *description* hijacked more models than the tool *output* did. The model's output is the one surface you can never treat as trusted for identity. It has to be stamped by the runtime, outside the agent's reasoning, before the model gets a say.

So I built the runtime that stamps it. It's called Crumb. Every agent action drops a crumb; the trail leads back to the human who directed it.

## The shape of it

One gateway, every tool call passes through it.

It pulls the human's identity from the verified session, captured once at login, never from the model. It mints a short-lived delegation token that carries both identities: the human as the RFC 8693 `sub`, the agent as the `act`, scoped to the one resource being called. Then it writes a crumb to an append-only, hash-chained ledger, each entry signed with Ed25519, and calls the tool with the token. The tool refuses any call that doesn't carry a valid token, so there's no path to the data that skips it.

That delegation token isn't hand-rolled. It's a real RFC 8693 token exchange against an identity provider: the human's session goes in as the `subject_token`, an RS256 provider-signed composite comes back, and the resource verifies it against the provider's published JWKS. No shared secret. Point it at Okta or Keycloak or Zitadel and the same code path holds, because it's the standard, not a custom copy of it.

## The part that actually breaks: more than one agent

A single agent calling a tool is the easy case. Real systems don't look like that. A human directs an orchestrator. The orchestrator delegates to a sub-agent. The sub-agent calls the tool. Now who's accountable, and how do you prove it, when the human is two hops away from the action?

This is where most attribution stories quietly stop. The standards bodies haven't fully solved it either. But RFC 8693 has the mechanism hiding in section 4.1: the `act` claim can nest. Each new actor wraps the previous one, and the human stays the `sub` at the root the whole way down. Walk the nesting back and you get the full chain of who-acted-for-whom, ending at the person who started it.

So Crumb implements it end to end. Each hop nests the prior actor. The provider does the nesting over a real token exchange, not a dev shortcut. The crumb records the whole chain. And because the entire nested structure is signed as one token, there's no per-hop seam to forge at. I tried: rewrite a middle actor in the chain and re-sign it without the key, and verification rejects it on the signature. The chain holds together or it doesn't verify.

Alice authorizes one action, `read_record`, when she logs in. A planner agent takes her request and delegates to a researcher sub-agent. The researcher reads the record. The crumb traces it back through both agents to Alice, verified.

Then a hop goes rogue and calls `export_record`, which Alice never authorized. The action may technically run. But the crumb records no human directive behind it. It flags the action unauthorized and names the agent chain that did it. Alice is in the record. She's provably not the one accountable.

A service-account log can't do that. It says a bot exported the record, and stops there. This one clears Alice by name and points at the agents instead.

## Tamper-evidence, including against yourself

A signed, hash-chained log sounds tamper-proof until you remember who holds the signing key. You do. If you can re-sign, you can rewrite history and re-sign the whole chain, and per-entry verification passes the forgery, because every entry is validly signed. By you.

So the ledger checkpoints its Merkle root and publishes it to Sigstore's public Rekor transparency log. Now the operator-rollback attack falls apart: you rewrite a crumb, re-sign the entire chain, and per-entry verify still passes. But the rewritten root no longer matches the one already sitting public in Rekor, timestamped before your edit. The forgery is caught by something you don't control. There's a button on the live demo that runs exactly this and shows the anchor catching it.

## What it isn't

This is the part I want to be straight about, because attribution is a space where it's easy to overclaim.

Crumb is a flight recorder, not a control plane. Stopping things is a different and well-funded job. Cerbos, Capsule, Astrix already do it. Crumb records and proves; it points at them for the rest.

Attribution is only as strong as the gateway. Bypass it and there's no crumb, so the gateway has to be real and enforced, not optional.

The multi-hop chain is single-issuer. One provider, one trust root. A chain that spans two different identity providers is genuinely unsolved at the standards level, and I'm not going to pretend otherwise.

The ledger stores a hash of the arguments, not the raw arguments, to keep sensitive data out of the log. The tradeoff is that it proves an action happened and who directed it, not the exact bytes that were touched.

And MCP attribution is permitted by the spec but rarely implemented upstream, so Crumb can stamp the record but can't force a non-compliant server to honor the human identity.

That's the gap between what's built and what's marketing. In this space, that gap is the whole thing.

## Try to break it

The demo is live at [crumb.alexlaguardia.dev](https://crumb.alexlaguardia.dev). Seed some crumbs, tamper a row, watch verification flip. Hit the operator rollback and watch the external anchor catch a forgery that per-entry signing passes. The code is on GitHub.

If you're building agent infrastructure and you've hit this, or you think I've got something wrong, I want to hear it.