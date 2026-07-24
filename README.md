# Crumb

**Prove which human directed an AI agent's action, across MCP and OpenAI function-calling, in a tamper-evident record an auditor can verify without trusting you.**

Every agent action drops a crumb. The trail leads back to the human who directed it.

**Live demo: [crumb.alexlaguardia.dev](https://crumb.alexlaguardia.dev).** Hit *Operator rollback* and watch the signed chain stay green while the external anchor catches the forgery.

![A key-holding operator rewrites history and re-signs the whole chain. Per-entry verification passes the forgery. The Rekor anchor catches it.](docs/rollback.gif)

## The problem

AI agents run under service accounts and shared API keys. So when an agent reads a patient record, exports customer data, or moves money, your audit log says *the agent did it*, not *which human told it to*.

That gap is about to be illegal. The EU AI Act (Article 12, in force Aug 2 2026) requires high-risk systems to log "the identification of the natural persons involved." A service-account log can't answer that.

And it isn't a model problem you can prompt your way out of. A tool call from a model is just `{"name": ..., "arguments": ...}`, with no field for *who*. Worse, anything the model emits can be prompt-injected, so identity must never come *from* the model. It has to be stamped by the runtime, outside the agent's reasoning.

Crumb is the runtime that stamps it.

## What it is (and isn't)

Crumb is a **flight recorder** for agent actions: read-only, after-the-fact, provable. It records who-did-what and proves the record wasn't altered.

It is **not** a control plane. It doesn't block, doesn't author policy, doesn't draw an identity graph. Those are the funded lane (Cerbos, Capsule, Astrix). Crumb stays in its own: forensics and accountability, and points at them for enforcement.

## How it works

```
 human (OIDC session)
        │  sub=alice, captured once, never from the model
        ▼
   ┌─────────┐   mint RFC 8693 token (sub + act, scoped)    ┌──────────────────┐
   │ GATEWAY │ ──────────────────────────────────────────▶ │ tool / MCP server │
   └─────────┘   the enforced chokepoint                    └──────────────────┘
        │  writes a signed crumb
        ▼
   hash-chained, Ed25519-signed ledger
        │  Merkle root, hourly
        ▼
   Sigstore Rekor  (public transparency log the operator doesn't control)
```

Four moves:

1. **Capture** the human once, at an OIDC session, before the agent runs. Identity never comes from the model.
2. **Bind** every tool call to an RFC 8693-shaped delegation token carrying the human (`sub`) and the agent acting for them (`act`), scoped to one resource. The tool serves data only against a valid token.
3. **Record** a hash-chained, Ed25519-signed crumb per call. Edit, delete, or reorder any entry and a different check breaks at the exact row.
4. **Anchor** the Merkle root of the whole log to Sigstore's public Rekor log. Per-entry signatures stop a forger without the key. Anchoring stops the *operator*, who could otherwise re-sign a rewritten history.

**Cross-vendor by design.** An OpenAI function-call and an MCP `tools/call` are two different wires with the same gap: neither carries the human. Both normalize to one `ToolCall`, flow through the same gateway, and land in one canonical crumb schema, distinguished only by a `transport` field. Attribution is a property of the runtime, not the wire, so it survives a change of wire.

## Quickstart

```bash
pip install -r requirements.txt

python -m crumb.demo               # the gap, then the gateway closing it
python -m crumb.cross_vendor_demo  # same action over OpenAI + a REAL MCP HTTP hop
python -m crumb.hijack_demo        # a poisoned tool hijacks the agent; the crumb pins it on the agent, not the human
python -m crumb.tamper_demo        # write crumbs, verify, edit one, watch it break
python -m crumb.anchor_demo        # the operator rollback the anchor catches
python -m crumb.actor_binding_demo # operator forges the HUMAN, the token proves the truth
python -m crumb.cross_issuer_demo  # a delegation chain across TWO issuers, provenance stapled
python -m crumb.jwks_federation_demo # verifier fetches issuer keys live over HTTP, follows rotation
python -m crumb.idp_demo           # a REAL RFC 8693 token exchange + JWKS verify
python -m crumb.verify             # re-verify the ledger on its own

uvicorn crumb.web:app --port 8730       # the timeline view + live tamper/rollback
uvicorn crumb.mcp_http:app --port 8731  # records-mcp as a standalone MCP server
uvicorn crumb.idp:app --port 8732       # the IdP: RFC 8693 token-exchange + JWKS
```

`records-mcp` is a real Resource Server — drive it with any MCP client, or curl:

```bash
curl -s localhost:8731/mcp -H "Authorization: Bearer $TOKEN" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call",
       "params":{"name":"read_record","arguments":{"record_id":42}}}'
# no token → HTTP 401 + WWW-Authenticate, like any OAuth 2.1 Resource Server
```

What each one shows:

- **demo**: a human authenticates, an agent reads a "regulated" record, and the crumb ties the action back to them.
- **cross_vendor_demo**: the same read driven once as an OpenAI function-call and once as a real MCP `tools/call` over HTTP to `records-mcp`. Both trace to the same human in one schema. Then, over that same wire, the same call with a service-account token (the human is gone) versus a delegation token (the human survives). That delta is the product.
- **hijack_demo**: the attack Crumb is built for. A poisoned tool description drives the agent into two calls the human never authorized — a same-verb read of a patient she never named, and an export to an attacker. alice scoped her session to `read_record(42)`; the read of record 43 and the export both land `unauthorized`, directive null, pinned on the agent. The read of 43 is the sharp one: same tool name, different resource, so a verb-only check clears it — the argument scope is what catches it, and it flags even though the call *succeeds* against a real record. The ledger still verifies; the point is who each call is pinned on.
- **tamper_demo**: a careless edit. Verification catches it at the exact row.
- **anchor_demo**: the one to watch. A key-holding operator rewrites a crumb *and re-signs the entire chain*, so per-entry `verify` passes the forgery. The Rekor anchor catches it, because the rewritten root is not the one already public.
- **actor_binding_demo**: anchor_demo catches a rewritten *record*; this catches a rewritten *human*. The operator edits `actor_identity` and re-signs, so integrity passes over their own log. But the crumb carries the delegation token, and `crumb verify --federation` re-walks it to the root issuer: the token still proves `alice`, the record claims `mallory`, and the human the operator can't re-sign is the one that wins. The recorded human stops being their word.
- **cross_issuer_demo**: the human logs in at one IdP (A) and the tool is governed by another (B). Vanilla token exchange would have B mint a fresh token and drop A's signature, leaving only B's word for who the human was. Crumb staples instead: B's token carries A's exact token and its hash, so a verifier re-checks A's segment against A's key and never takes B's word for the upstream. Same human, provable across the boundary.
- **jwks_federation_demo**: the trust set made trustless. Two IdPs come up on real ports serving `/.well-known/openid-configuration` + `/jwks`, and the verifier pins *nothing* — it names the issuers, discovers their JWKS, and fetches their keys live. Then A rotates its signing key: a verifier that had pinned A's PEM would break, but this one sees an unknown `kid`, refetches A's JWKS once, and keeps verifying. Keys always come from the issuer's own endpoint, never the log-holder.
- **idp_demo**: the bind made real. The gateway no longer signs its own authority — it runs a genuine RFC 8693 token exchange against an identity provider (`crumb/idp.py`), which returns an RS256 token, and the resource verifies it against the provider's published JWKS. No shared secret. Set `CRUMB_IDP_URL` and the same path points at Okta/Keycloak/Zitadel; leave it unset and the gateway falls back to a local dev mint, so every other demo runs with zero infra.

## Honest scope

- Attribution is only as good as the gateway's interposition. Bypass the proxy and attribution is void. The demo enforces the chokepoint; the tool refuses calls without a valid token.
- Reconciliation is only as tight as the directive's scope. A directive can be verb-level (authorize `read_record`, any record) or scoped to arguments (`read_record` for record 42 only). Verb-level is a deliberate choice, not an oversight — it authorizes any call to that tool, so it can't distinguish a same-verb hijack. Scope the directive to the resource and it can. The authorizer picks the granularity; Crumb records against whatever they chose and never silently widens it.
- OpenAI function-calling has zero native identity. The binding is a runtime convention, not a protocol guarantee. Crumb secures a runtime, not a wire format.
- MCP attribution is permitted by the spec but rarely implemented. `records-mcp` reads the human off the token over a real HTTP wire; most deployments send a shared service-account token instead and the human never makes it across. Crumb stamps the record, but it can't force a non-compliant upstream to *act* on the human identity.
- The MCP transport here is plain JSON-RPC over HTTP with bearer auth. Streamable-HTTP/SSE framing (session ids, event streams) is the documented upgrade and changes the envelope, not the attribution.
- The token is RFC 8693-*shaped* and minted with a dev key. Production swaps that for a real token exchange against an IdP (Keycloak/Zitadel/Auth0). It changes the issuer, not the demo.

## Built on

OAuth 2.1 + PKCE, OIDC, [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) token exchange, [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) resource indicators, the [MCP authorization spec](https://modelcontextprotocol.io), [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) Merkle trees, and [Sigstore Rekor](https://docs.sigstore.dev/logging/overview/). Ed25519 + SHA-256 via `cryptography`, JWTs via `PyJWT`. All real, all standard.

Full design in [`SPEC.md`](./SPEC.md).
