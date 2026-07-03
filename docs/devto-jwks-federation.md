---
title: "I pinned each issuer's public key. Then the IdP rotated it."
published: false
description: "Verifying a delegation token across two identity providers works, as long as you have their keys. I had been pinning them as static PEMs. Here's why that breaks the day an issuer rotates, and how Crumb's verifier fetches keys live without handing trust back to the operator."
tags: ai, security, oauth, mcp
cover_image: https://raw.githubusercontent.com/AlexlaGuardia/crumb/master/crumb/static/cover-jwks-federation.png
---

Last time I wrote about keeping the human provable when an agent's delegation chain crosses from one company's identity provider into another's. The verifier walks the chain backward and checks each segment against the key of the issuer that signed it. I ended that post with a line I meant as honesty about the one assumption left standing:

> You pick your trusted issuers once, explicitly, in an object you can read.

That sentence quietly skipped a question. The keys have to get *into* that object somehow. I had them going in as static PEM strings, pinned by hand. It works in a demo. It breaks the first time a real identity provider does the most ordinary thing an identity provider does.

## Pinning is fine until it isn't

Here is what the trust set looked like. A little JSON manifest, issuer to public key, loaded off disk:

```json
{
  "https://idp-a.local": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBg...",
  "https://idp-b.local": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBg..."
}
```

The verifier reads that, and now it can check any token either issuer signed. Clean. Operator-independent, too, which is the whole point of Crumb: those keys came from *you*, out of band, not from whoever is holding the log you're auditing. Nobody in the middle gets to assert their own trustworthiness.

The problem is the word "static." A signing key is not a fact about an issuer. It's a thing an issuer rotates, on a schedule, as basic hygiene, the same way you rotate any other secret. Okta rotates. Keycloak rotates. Auth0 rotates. When they do, the PEM you pinned three weeks ago is now a key nobody signs with anymore.

![Left, a verifier pinning a static PEM: the IdP rotates its key, a token signed with the new key arrives, verification fails silently and needs a redeploy. Right, a verifier that fetches JWKS by kid: the same rotation triggers one refetch and verification still passes.](https://raw.githubusercontent.com/AlexlaGuardia/crumb/master/crumb/static/diagram-pin-vs-fetch.png)

And it fails in the worst way, which is quietly. Nothing is broken at the moment you deploy. Weeks later the issuer rotates, tokens start arriving signed by a key your manifest has never heard of, and every one of them fails signature verification. Not because anything is forged. Because your copy of reality went stale and nobody told it. The fix is a human noticing, editing a file, and redeploying. That is not a verification system. That is a verification system with a standing appointment to break.

## Fetch the key, don't freeze it

The standard already solved this, and I was just not using the part that mattered. An OIDC issuer publishes its current signing keys at a JWKS endpoint, and it tells you where that endpoint is in its discovery document. Every token names, in its header, the exact key it was signed with, by `kid`.

So the verifier stops pinning keys and starts pinning *issuers*. You name the issuer you accept. The verifier reads the issuer's `/.well-known/openid-configuration`, finds its `jwks_uri`, fetches the keys there, and picks the one whose `kid` matches the token in hand.

```json
{
  "https://idp-a.local": { "discovery": "https://idp-a.local" },
  "https://idp-b.local": "https://idp-b.local/jwks"
}
```

Rotation stops being an event the verifier has to be told about. A token shows up signed by a `kid` the verifier hasn't cached, and instead of failing, the source refetches the JWKS exactly once, finds the new key sitting right there where the issuer just published it, and verifies. No redeploy. No file edit. The issuer rotated and the verifier followed, because the verifier was reading from the issuer the whole time instead of from a photograph of it.

The one refetch matters, by the way. You cache, or every token turns into a network round trip. But you can't cache so hard that a rotation locks you out. Unknown `kid` is the signal to look again, once, before giving up. Seen `kid` comes straight from cache.

## Fetching is not trusting

Now the part I had to be careful about, because it is exactly where this could quietly betray the whole premise.

Crumb exists to let someone verify who directed an action *without trusting the operator who holds the log*. If I make the verifier go fetch keys over the network, the obvious question is: fetch them from where? Get that wrong and you've handed the trust decision to whoever answers the request.

![The verifier fetches keys from the issuer's own TLS-served endpoint, a trusted path. It never fetches them from the log-holder, the server under audit, which is drawn as a crossed-out path. The verifier names the issuers it accepts out of band.](https://raw.githubusercontent.com/AlexlaGuardia/crumb/master/crumb/static/diagram-trust-boundary.png)

The keys come from the issuer's own endpoint, over TLS, which is what authenticates that you're really talking to `idp-a.local` and not someone wearing its name. They never come from the server under audit. That server is the one thing in the picture you have assumed might be lying to you. It holds the ledger it wants believed. It does not get to also supply the keys that would prove the ledger honest. The two roles stay split.

And the verifier still decides which issuers count. Fetching a key from an endpoint is not the same as trusting it. An issuer you never named has a JWKS endpoint too. That buys it nothing. The verifier only reaches for keys at issuers it already put in its own trust set, out of band, the same explicit decision as before. All that changed is that the trusted thing is now an issuer identity instead of one frozen key, and TLS carries the weight of "is this really that issuer."

So the two ways it can refuse stay distinct, and I kept them named:

- **`UntrustedIssuer`** — the token's issuer is not in the trust set at all. There is no endpoint to even ask. Refused outright.
- **`UnknownSigningKey`** — the issuer *is* trusted, but none of its published keys match the token's `kid`, even after a fresh fetch. The issuer is real; the key it claims to have signed with does not exist. Refused, not guessed.

The first is a stranger. The second is a trusted party holding up a key that isn't theirs. Collapsing those two into one "nope" would throw away the only information a debugger actually wants.

## What I am not going to oversell

TLS is doing real load-bearing work now, and I should say that out loud instead of letting it hide. "The keys come from the issuer's own endpoint" is only as true as your certificate validation. Point this at an issuer over plain HTTP, or disable cert checks because a test was annoying, and the trust boundary I just drew has a hole straight through it. In the demo below the issuers run on localhost over plain HTTP, which is fine for showing the mechanism and would be a real hole in production. The honest claim is "keys fetched from the issuer over an authenticated channel," and the authenticated part is a requirement, not a decoration.

There's more I haven't built. This follows rotation but does nothing clever about *revocation* — an issuer pulling a key it wants dead faster than a cache expires. And a verifier that fetches is a verifier that can be made to wait; anything reaching across the network wants timeouts and a failure mode that fails closed. Those are real, and they are not done.

What is done is the thing that was actually broken: the trust set no longer freezes a key it has no business freezing. You name the issuers. Their keys stay theirs, fetched live, followed through rotation, and never once sourced from the party you're auditing.

## Try it

```
git clone https://github.com/AlexlaGuardia/crumb
python -m crumb.jwks_federation_demo
```

It stands up two identity providers on real ports, each serving its own discovery and JWKS endpoints. A verifier that pinned nothing names the two issuers, fetches their keys live, and verifies a delegation chain back to the human. Then one issuer rotates its signing key, and the same verifier follows the rotation with a single refetch and keeps verifying. Last, a chain built on an issuer the verifier never named gets refused, because a live endpoint was never what earned trust.

The rest of Crumb, including the cross-issuer stapling this builds on, is at [crumb.alexlaguardia.dev](https://crumb.alexlaguardia.dev).

If you work on agent identity and you see a way the fetch path hands trust back to the wrong party, that's exactly the hole I want pointed out.
