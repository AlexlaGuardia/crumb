---
title: "An AI agent acted across two companies. Whose audit log knows which human?"
published: false
description: "Single-issuer agent delegation is solved. The moment the chain crosses into a partner's identity provider, RFC 8693 throws the upstream signature away. Here's how I kept the human provable across the boundary in Crumb."
tags: ai, security, oauth, mcp
---

Alice logs into her company's tools through their identity provider. She points an agent at a task. That agent hands part of the work to a sub-agent, and the sub-agent calls a tool that lives in a partner company's system, behind a *different* identity provider. The tool does something it shouldn't. An auditor pulls the record.

Whose log knows it was alice?

Not the agent's. The agent is a process; it can claim to be anyone. Not the model's either, which reads whatever it was handed and has no idea which human is behind the session. The honest answer in most deployments today is that the partner's system can prove *a bot* called it, and can prove *which company's bot*. Then the trail goes cold. The person who actually directed the action dissolves into "some agent at the vendor."

I have been building [Crumb](https://crumb.alexlaguardia.dev) to refuse that outcome: a tamper-evident record that binds the actual person behind an agent's tool call, verifiable by someone who does not have to trust whoever ran the agent. Within a single identity provider, that chain was already working. This post is about the part that wasn't, and why it took longer than I expected.

## The single-issuer case was the easy half

When the whole chain lives under one identity provider, delegation has a clean answer, and it is a real standard. RFC 8693 token exchange lets you mint a token that carries two identities at once: the human as the `sub`, and the agent acting for them as a nested `act` claim. Add a hop and you nest again. The human stays at the root the whole way down.

```json
{
  "iss": "https://idp-a.local",
  "sub": "alice",
  "act": { "sub": "researcher", "act": { "sub": "planner" } },
  "aud": "read_record"
}
```

One provider signs that token. A resource server verifies it against that provider's public key, walks the `act` chain back to alice, and it is done. No shared secret, no trusting the gateway that minted it. I covered that build in an earlier post. It holds up.

The catch is in the assumption hiding under "one provider."

## The boundary is where it breaks

Real delegation does not stay inside one company. The interesting, dangerous case is the one that crosses.

![Sequence: alice authenticates at IdP A, an agent chain hands off into IdP B, and the tool verifies the human across both issuers](https://raw.githubusercontent.com/AlexlaGuardia/crumb/master/crumb/static/diagram-cross-issuer-chain.png)

So `planner`, holding a token IdP A signed, needs the call into B's domain to carry a token B will honor. The textbook move is another RFC 8693 exchange, this time against B. You hand B the token A issued, and B mints you a fresh one.

And right there is the problem, sitting in plain sight in the spec. When B does that exchange, it mints a token signed *only by B* and drops A's signature on the floor. The new token says `sub: alice` because B copied it across, but the cryptographic proof that A authenticated alice is gone. Downstream, all you hold is B's word: "A told me it was alice."

For most systems that is fine, because most systems were already trusting B. But Crumb's entire reason to exist is to let an auditor verify *without* trusting the operator. A cross-issuer hop that resolves to "trust B" puts the trust-me point right back in the middle of the chain I was trying to make checkable. It's the one thing I can't wave away.

## Stapling: carry the signature across, don't reissue it

The fix I landed on is to stop throwing the upstream token away.

When B exchanges A's token, two things happen. First, B verifies A's token against A's public key. B can only do that if it federates with A, so A has to be in B's trust set. That is a real relationship and I will come back to how honest it is. Second, instead of discarding A's token, B *staples* it into the one it mints: the exact inner JWS rides along in a `prv` claim, its SHA-256 in `psh`, and the inner issuer in `pis`.

```json
{
  "iss": "https://idp-b.local",
  "sub": "alice",
  "act": { "sub": "researcher", "act": { "sub": "planner" } },
  "aud": "read_record",
  "prv": "<the exact JWT that IdP A signed>",
  "psh": "sha256:5992849d649979e6...",
  "pis": "https://idp-a.local"
}
```

Now the outer token is not an assertion that alice was authenticated. It is a pointer to the original proof, hash-pinned so it can't be swapped. B signed its own segment. A already signed its segment. Nobody re-signed anybody else's.

A verifier handed the outer token walks the chain backward and checks each segment against the key of the issuer that actually signed it.

![Vanilla exchange discards A's signature so the verifier trusts B's word; stapled provenance keeps each segment verifiable against its own issuer's key](https://raw.githubusercontent.com/AlexlaGuardia/crumb/master/crumb/static/diagram-discard-vs-staple.png)

Each rule maps to one way a dishonest issuer could try to cheat:

1. **Per-segment signature.** Every token in the chain is verified against its own issuer's key, pulled from the verifier's federation set. An issuer it does not federate with has no key, so the token is refused, not verified-then-ignored.
2. **Staple integrity.** A token carrying `prv` must have `psh` equal to the hash of that `prv`. Swap the embedded provenance for a different token and the hash stops matching.
3. **Human continuity.** The `sub` has to be the same identity at every hop. An outer token claiming to act for alice while stapling a token A issued for bob is a lie the walk catches.
4. **Actor continuity.** The chain an outer token carries beneath its own actor has to equal the inner token's chain exactly. An issuer may append a hop. It may not rewrite the hops it inherited.

## What it refuses

The part I care about most is the negative space. A mechanism that only shows the happy path hasn't proven anything. So the demo verifies the real chain across two issuers, and then it tries to break it five ways and shows each one failing by name.

The sharpest of the five: a *malicious B* tries to fabricate an upstream human. It controls its own signing key, so it mints a perfectly valid B token that says it is acting for `mallory`, and it staples a forged "A token" that also names mallory. B can sign its own segment all day. What it cannot do is sign as A. The verifier checks the stapled segment against A's real key, the forgery fails there, and B's attempt to invent a human it was never handed dies at the boundary.

```
3. malicious B forges an upstream human (mallory)
   forged upstream    rejected (InvalidSignature): B can't sign as A
4. swap the stapled provenance (psh left stale)
   swapped provenance rejected (StapleMismatch): psh pins one predecessor
5. B claims alice but staples bob's token
   human discontinuity rejected (HumanDiscontinuity): same human or nothing
6. B rewrites the inherited actor chain
   rewritten chain    rejected (ActorChainBroken): append-only, no rewrite
7. upstream from an unfederated issuer
   unfederated issuer rejected (UntrustedIssuer): verifier trusts its own set
```

That last one matters more than it looks. Even when B chooses to accept some sketchy third issuer C and builds a chain on it, the verifier makes its *own* trust decision. B vouching for C buys C nothing. The verifier trusts its set, not B's.

## The part I am not going to oversell

Here is the boundary, stated plainly, because pretending it isn't there is exactly the tell I am trying to avoid.

This isn't a new standard. The `prv` and `psh` staple claims are a Crumb convention. There is no RFC that defines them, and if two vendors wanted to interoperate this way they would have to agree on the format first. And the whole thing still rests on a federation trust set. Somebody, somewhere, decides which issuers they accept. I didn't make that decision disappear.

What I did was make it the *only* thing you have to decide, and make everything downstream of it checkable. You pick your trusted issuers once, explicitly, in an object you can read. After that no single issuer gets to assert the human on its own word. Each one signs only its own segment, and the verifier re-checks all of them.

There's still no trust-free answer for cross-issuer identity. Just a smaller question: who do you federate with.

## Try it

The whole thing is one additive module and a demo you can run.

```
git clone https://github.com/AlexlaGuardia/crumb
python -m crumb.cross_issuer_demo
```

It stands up two issuers with two different keys, crosses a real delegation chain between them, verifies it back to the human, and then fails the five forgeries above. The live timeline and the rest of Crumb are at [crumb.alexlaguardia.dev](https://crumb.alexlaguardia.dev).

If you work on agent identity or authorization and you think the stapling model has a hole in it, I want to hear where.
