# Agent Action Tracer — Build Spec

> Flagship build (cortex focus P1). Build-in-public, aimed at the agent-governance hiring cohort.
> Name: **Crumb** (locked 2026-06-20). Every agent action drops a crumb; the trail leads back to the human. Drafted 2026-06-20 (Serberus).

## 1. Thesis (one sentence)
When an AI agent touches regulated data, prove **which individual human** directed it — across MCP *and* OpenAI function-calling — in a **tamper-evident** record an auditor can verify without trusting us.

## 2. Why this, why now
- The whole governance cohort talks **agent** identity (Astrix, Okta) or **action** integrity (Guild, Luke Hinds' `nono`). Almost nobody binds the **specific human → specific tool call → tamper-evident record**. That intersection is the wedge.
- EU AI Act Art 12 names the requirement almost verbatim: high-risk systems must log "the identification of the natural persons involved in the verification of the results." Full high-risk enforcement **Aug 2, 2026**.
- The goal is **not** to win a market against Guild ($44M) / Okta / Cisco-Astrix ($400M). It's a credibility artifact that makes an eng leader at one of them want to hire Alex. Build-in-public is the distribution.

## 3. Positioning — "flight recorder," not control plane
Read-only, after-the-fact, provable. This deliberately sidesteps the funded lane (runtime enforcement, policy authoring, discovery graphs — Capsule/Cerbos/Astrix turf) and lands on forensics/accountability, which is underbuilt and credible for a solo dev.

**The unique claim:** individual-human attribution × cross-vendor × tamper-evident. `nono` proves *what the agent did* but not *which human authorized it* — we add the on-behalf-of/attribution leg.

### Build
- A **gateway shim** that interposes on tool calls (MCP `tools/call` + OpenAI function-call), normalized to one canonical event schema.
- A **hash-chained + Ed25519-signed append-only log**, sealed into Merkle checkpoints, externally anchored.
- A **`verify` CLI** (inclusion + consistency + signature checks, offline).
- **One** web view: the audit trail as a timeline (Cerbos-style columns: time, human-principal, acting-agent, tool, args-hash, decision, inclusion-proof ✓).

### Deliberately do NOT build (each omission is a judgment signal — say so in the writeup)
- No identity-graph visualization (funded players' expensive turf, zero added proof).
- No runtime enforcement/blocking (Capsule/Cerbos lane → wannabe-competitor tell).
- No discovery/inventory of shadow agents (integration slog, not craft).
- No multi-tenant SaaS, billing, login, cost/token dashboards (Guild glitz).
- No policy-authoring UI — point at Cerbos as the enforcement layer; composability reads as maturity.
- No live KMS/HSM — local signing key, note "swap for KMS in prod."

## 4. Architecture — the interposition pattern
```
[Human] --OIDC login--> [Session/Auth]   captures verified `sub` at t=0
                              |
                              v
[Agent runtime] --tool intent--> [GATEWAY] --stamped+exchanged call--> [Tool / MCP server / API]
                              ^                       |
                       sub bound to session,          +--> signs an append-only attribution record
                       NEVER supplied by the model
```
- **Capture:** human authenticates *before* the agent runs; gateway holds session → `sub`. Single source of truth.
- **Bind:** for every outgoing tool call the gateway (1) pulls `sub` from session (not from model args), (2) mints a short-lived composite token carrying `sub` (human) + `act:{agent_id}` (RFC 8693 shape), scoped to one resource (RFC 8707), (3) forwards, (4) writes a signed attribution record.
- **MCP path:** MCP servers are OAuth 2.1 Resource Servers; a token-exchanged token carries `sub`+`act`. Spec *permits* per-human attribution; most deployments use a service-account token and don't → **that delta is the product.**
- **OpenAI path:** function-calling carries *zero* identity. The model must never be trusted as identity carrier (prompt-injection). Attribution is a property of *our runtime/gateway*, not the wire.

### Standards (real vs draft, 2026)
- **Build on:** OAuth 2.1 + PKCE, OIDC, **RFC 8693** token exchange, RFC 8707 resource indicators, MCP authz spec (2025-11-25). All real.
- **Upgrade path (draft but productized):** IETF Cross-App Access / ID-JAG (Okta/Auth0 ship it), the `oauth-ai-agents-on-behalf-of-user` draft.
- **Agent (workload) identity:** SPIFFE/SVID real; WIMSE draft. Answers "which agent," not "which human" — don't conflate; the human leg is our value-add.
- **Ignore for MVP:** agent-identity research drafts (AIMS/Agentic-JWT etc. — "TODO Security" maturity).

## 5. Tamper-evidence — signed hash-chain + Merkle checkpoint + external anchor
Three layers, each defeating a different attack (this is the RFC 9162 / Sigstore-Rekor architecture scaled to a solo dev — lineage = credibility):
1. **Per-entry hash chain** — `entry_hash = SHA-256(canonical_json(entry) || prev_hash)`. Edits/deletes detectable.
2. **Per-entry Ed25519 signature** — origin authenticity / non-repudiation.
3. **Merkle checkpoint + external anchor** — hourly, compute Merkle root, sign it (C2SP checkpoint), anchor where we don't control it (public Sigstore Rekor, or S3 Object Lock WORM, or email to auditor). This is what stops *the operator themselves* from rewriting history — without a blockchain.

### Verification (third party, no trust in operator, no full log needed)
- **Inclusion proof** — record Z is in the log (recompute Merkle path to signed checkpoint root; ~3KB even at 80M entries).
- **Consistency proof** — log was only appended, never rewritten (old externally-anchored checkpoint vs new).
- **Signature check** — Ed25519 on checkpoints; confirm Rekor anchor.

### Libs
- **Python (recommended):** `cryptography` (Ed25519/SHA-256) + `pymerkle`/`merkly` + `rfc8785` (JCS canonicalization) + optional `sigstore` (Rekor anchor) + `PyJWT` (composite tokens).
- **Node alt:** `@noble/ed25519` + `@noble/hashes` + `merkletreejs` + `canonicalize` + `@sigstore/sign` + `jose`.

## 6. Canonical audit-record schema
```jsonc
{
  // WHO (EU AI Act Art 12 "identification of natural persons"; Art 14 accountability)
  "actor_id": "u_8842",
  "actor_identity": "alejandro.moreno@org.com",   // verifiable SSO subject
  "actor_auth_method": "okta_oidc",
  "directive": "approved_export_req#1190",          // the human authority for the action

  // VIA WHAT (the agent)
  "agent_id": "tracer-agent-v2",
  "agent_version": "2.3.1",
  "model": "claude-opus-4-8",
  "on_behalf_assertion": "delegated",               // human-directed vs autonomous

  // DID WHAT (action + regulated data)
  "action": "READ_EXPORT",
  "resource_type": "patient_record",
  "resource_id": "rec_55021",
  "data_categories": ["PHI","contact"],
  "reference_database": "ehr_prod",                 // Art 12: DB checked against
  "match_result": "1 match",                        // Art 12: input that led to a match
  "outcome": "success",

  // WHEN
  "ts_start": "2026-06-20T14:03:11.412Z",
  "ts_end": "2026-06-20T14:03:11.880Z",

  // CONTEXT
  "session_id": "sess_77f1",
  "human_review": { "required": true, "reviewer_id": "u_8842", "decision": "allow" },

  // TAMPER-EVIDENCE ENVELOPE (computed, not user-supplied)
  "seq": 109432,
  "prev_hash": "b7f3…",
  "entry_hash": "9c01…",
  "signature": "ed25519:4a…",
  "checkpoint_ref": "ckpt_2026-06-20T14:00Z",
  "anchor_ref": "rekor:logIndex=88213"
}
```

## 7. Compliance mapping
| Record field / mechanism | Satisfies |
|---|---|
| `actor_identity` + `actor_auth_method` | EU AI Act Art 12 "identification of natural persons"; Art 14 named overseer |
| `directive` + `human_review` | EU Art 14 human oversight; Colorado ADMT "meaningful human review" |
| `agent_id`/`agent_version`/`model` | Traceability of the AI system (Art 12 post-market monitoring) |
| `action`+`resource_id`+`data_categories`+`reference_database`+`match_result` | Art 12 minimum log content; regulated-data scoping |
| `ts_start`/`ts_end` | Art 12 start/end of each use |
| hash chain (`seq`/`prev_hash`/`entry_hash`) | Tamper-evidence expectation (Art 12/19) |
| `signature` | Non-repudiation / origin authenticity |
| Merkle checkpoint + external anchor | Append-only proof *against the operator* (RFC 9162) |
| ≥6 mo (EU) / 3 yr (Colorado ADMT) retention | Art 19 retention; Colorado SB26-189 |

> **Compliance correction:** Colorado's June 30 2026 date is DEAD — SB 24-205 was repealed and replaced by the **Colorado ADMT Act (SB 26-189, signed May 14 2026), effective Jan 1, 2027** (3-yr retention, "meaningful human review"). **Lead the pitch with EU AI Act Aug 2, 2026** (hard deadline, prescriptive fields). Colorado = 2027 US tailwind, not a 2026 hook.

## 8. Build phases
- **P0 — Skeleton (days):** OIDC stub (signed session JWT, `sub=alice`); one function-calling agent + one tool `read_record(id)`; show on screen the model returns NO identity.
- **P1 — Gateway + record (the star):** ~150-line FastAPI proxy. Pull `sub` from session → mint composite JWT (`sub`+`act`+`aud`+`jti`+`exp`, signed local key) → call tool → write hash-chained Ed25519-signed JSONL/SQLite record. Tool verifies JWT, returns data only if valid.
- **P2 — Verifier + tamper demo:** `verify` CLI (inclusion + signature). **The killer 60s moment:** stream a few calls → `verify` → `VERIFIED`; hand-edit one historical row (flip DENY→ALLOW, or swap the human) → re-run → `MISMATCH: chain broken at event 4`.
- **P3 — Cross-vendor proof — ✅ DONE (2026-06-20):** the SAME gateway fronts an MCP `tools/call` resource server that reads `sub`+`act` from the delegation token (`crumb/mcp_server.py`); both wire formats normalize to one `ToolCall` (`ToolCall.from_openai` / `.from_mcp`) and land in one canonical crumb schema, distinguished only by a `transport` field. `python -m crumb.cross_vendor_demo` runs the same action over both protocols → both trace to `alice` → combined ledger `VERIFIED`. MCP path negative-tested (wrong-scope → `InvalidAudience`, forged → `InvalidSignature`).
- **P3b — Real RFC 8693 exchange — ✅ DONE (2026-06-22):** the dev-key mint is no longer the only path. `crumb/idp.py` is a self-contained, standards-correct token-exchange authorization server: `POST /token` (`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`) takes the human's session as `subject_token`, mints an **RS256, provider-signed** composite (`sub`+`act`, scoped to `aud`), and exposes the public keys at `GET /jwks` + issuer metadata at `/.well-known/openid-configuration`. The gateway now runs a real HTTP exchange when `CRUMB_IDP_URL` is set (`tokens.exchange_delegation`), and the resource verifies the result against the live JWKS — no shared secret. `verify_delegation` branches on the token `alg` (RS256 → JWKS, HS256 → dev fallback), so the tool is unchanged and the offline demos keep working with zero infra. `python -m crumb.idp_demo` proves the round-trip over a live ASGI wire and negative-tests it (forged → `InvalidSignature`, wrong-scope → `InvalidAudience`, tampered subject → refused at `/token`). Runs under PM2 (`crumb-idp`, 127.0.0.1:8732). The honest claim is "real RFC 8693 over HTTP, asymmetric-signed, JWKS-verified, IdP-agnostic" — point `CRUMB_IDP_URL` at Okta/Keycloak/Zitadel and the same code path holds. **Not built (judgment signal):** running a full third-party IdP as persistent infra on the prod box — the protocol and the verification are what earn trust, not which vendor's binary issues the token.
- **P4 — Web view — ✅ DONE (2026-06-20):** live at **crumb.alexlaguardia.dev**. One FastAPI app (`crumb/web.py`) serves a self-contained HTML timeline (`crumb/static/index.html`) + JSON API over the same ledger the CLI writes. Columns: human / agent / action / transport / outcome / entry-hash, with a live VERIFIED/MISMATCH banner. A visitor can seed crumbs, then TAMPER a row and watch verification break in the browser — the P2 money shot, interactive. Runs under PM2 (`crumb-web`, 127.0.0.1:8730).
- **P4b — External anchor — ✅ DONE (2026-06-20):** `crumb/merkle.py` (RFC-6962 tree, root, direction-tagged inclusion proofs, exhaustively tested 1..12) + `crumb/anchor.py` checkpoints the ledger's Merkle root and publishes it to **Sigstore's public Rekor transparency log** (hashedrekord, ECDSA-P256 + self-signed x509, REST API, no cosign dep) — returns a real logIndex + inclusion URL. `anchor.verify_anchors` recomputes the root over the anchored prefix and compares. **The payload (`crumb/anchor_demo.py`, live on the site):** a key-holding operator rewrites a crumb AND re-signs the whole chain, so the per-entry `verify` PASSES the forgery — but the rewritten root no longer matches the one already public in Rekor, so the anchor catches it. Web page surfaces anchor status + Rekor link + an "Operator rollback" button. **Deferred to P4c:** cron the checkpoint hourly (one-liner) + S3-WORM mirror of the anchor.
- **P6 — Multi-hop delegation — ✅ DONE (2026-06-23):** closes the honest-scope gap that had stood since P3 (human→agent→agent→tool). RFC 8693 §4.1 nested `act` is implemented end to end: `tokens.extend_delegation` adds a hop by nesting the prior `act` under the new actor (the human stays `sub` at the root, most-recent actor outermost); `tokens.actor_chain` walks it back to the agent that first acted. The IdP (`crumb/idp.py`) now accepts its own prior RS256 token as the `subject_token` of a re-exchange and nests its `act`, so the chain is built over a **real** token exchange, not just the dev mint. The gateway takes an optional `via=[...]` chain and records the full `actor_chain` in the crumb — **additive only for real chains**, so single-hop crumbs stay byte-for-byte identical and the deterministic web seed + Rekor anchor are untouched (verified: all six prior demos pass, seed root stable). `python -m crumb.multihop_demo`: alice→planner→researcher→read_record traces back to alice; a forged middle actor breaks the signature (the chain signs as one, no per-hop seam); a rogue hop's `export_record` lands `unauthorized` with the agent chain named and the human exonerated; and the same nesting is proven over the live IdP (RS256). **Scope flag:** single-issuer only (one provider) — cross-issuer chains are closed in P7.
- **P7 — Cross-issuer delegation — ✅ DONE (2026-06-24):** closes the last honest-scope gap (a chain that spans two IdPs: human logs in at A, an agent hands off to a sub-agent calling a tool governed by B). The hard part is that vanilla RFC 8693 exchange has B mint a fresh token and **discard A's signature**, collapsing the cross-issuer hop into "trust B that it was alice" — fatal for a verify-without-trusting-the-operator tracer. The fix is **provenance stapling** (new module `crumb/federation.py`, additive — idp.py/tokens.py/web seed/Rekor anchor all untouched, all six prior demos still pass): an `Issuer` exchanging a peer's token first verifies it against that peer's key (the peer must be in its `Federation` trust set, or `UntrustedIssuer`), then mints its own RS256 token that **staples** the predecessor — the exact inner JWS in `prv`, its SHA-256 in `psh`, the inner issuer in `pis` — while the human stays `sub` and the actor chain nests. `federation.verify_chain` walks the stapled linked list to the human-rooted root, verifying **each segment against its own issuer's key**, checking the staple hash, human continuity (`sub` identical every hop), and actor-chain continuity (an issuer may append, never rewrite). `python -m crumb.cross_issuer_demo`: alice@A→planner@A→researcher@B→read_record verifies across both issuers back to alice, then six negatives each fire a distinct, named refusal — a malicious B forging an upstream human (`InvalidSignature`, B can't sign as A), provenance swap (`StapleMismatch`), bob's token passed off as alice's (`HumanDiscontinuity`), a rewritten inherited chain (`ActorChainBroken`), and an unfederated upstream the verifier rejects even though B accepted it (`UntrustedIssuer`). **Honest boundary:** the `prv`/`psh` staple is a Crumb convention, not an RFC, and the federation trust set is a genuine assumption — we don't remove the "which issuers do I accept" decision, we make it explicit and keep everything downstream of it cryptographically checkable.

## 9. Honest-scope statements (put these IN the writeup — candor is the AI-tell antidote)
- Attribution is only as good as the gateway's interposition; bypass the proxy and attribution is void. Demo the *enforced* chokepoint.
- OpenAI function-calling has zero native identity — binding is runtime convention, not protocol. We secure a runtime, not a wire format.
- MCP attribution is *permitted but rarely implemented*; we can stamp records but can't force a non-compliant upstream to act on the human identity.
- MVP fakes the IdP authority; production needs a real RFC 8693 IdP.
- SPIFFE/WIMSE answer "which agent," not "which human."
- Multi-hop agent→agent→tool delegation works for a SINGLE issuer (P6, RFC 8693 §4.1 nested `act`) and, as of P7, ACROSS issuers via provenance stapling (`crumb/federation.py`) — but the honest boundary is that the `prv`/`psh` staple is a Crumb convention (no RFC defines it) and cross-issuer verification still rests on an explicit federation trust set. We don't claim to have removed the "which issuers do I trust" decision; we made it explicit and kept everything downstream of it cryptographically verifiable. Don't oversell it as a standards solution.
- **Args logging (current build vs hardening):** the gateway currently records the raw call `arguments` in the crumb (`resource_id: call.arguments`), which is fine for the demo's two fake records but is a PII exposure on real data — the ledger is tamper-evident and its root is publicly anchored. Production hardening is to log an `args_hash` instead, with the stated tradeoff (you prove *a* call happened, not exactly what it touched). Note this is not a free swap: changing what gets serialized moves every crumb's hash and therefore the already-anchored Merkle root, so it lands behind a version/format bump, not an in-place edit. Say "the current build logs raw args; hashing is the production path," not "we log hashes."

## 10. Name — Crumb (locked 2026-06-20)
**Crumb.** Every agent action drops a crumb; the trail leads back to the human who directed it. Collision-checked clear in the AI-agent security/observability/audit space (2026-06-20). No dedicated domain — lives as a GitHub repo under AlexlaGuardia; optional hosted timeline view (P4) would go at `crumb.alexlaguardia.dev` (free portfolio subdomain, same pattern as warden.alexlaguardia.dev). Repo dir: `/root/crumb`.

## 11. Build-in-public arc (feeds cortex focus P2)
- Post 1 — the gap: "your AI agent runs under a service account, so your audit log says the robot did it, not which human told it to. that's about to be illegal (EU AI Act Art 12, Aug 2)." Ship the thesis.
- Post 2 — the model carries no identity (show the bare function-call JSON), so attribution must live in the runtime. The two-identity (`sub`+`act`) insight.
- Post 3 — the gateway + the signed record (code).
- Post 4 — the tamper demo (the 60s before/after `VERIFIED`→`MISMATCH` clip). This is the one that travels.
- Post 5 — cross-vendor: same recorder, MCP and OpenAI, one schema.
- Each post = a warm-thread hook into the cohort below.

## 12. Target companies + warm-access angle (P2)
| Company | Angle |
|---|---|
| Guild.ai | Their audit trail is a secondary tab next to cost glitz; you made *the trail* the hero with crypto rigor. Neutral-control-plane thesis match. |
| Okta (AI Agents) | You speak their stack natively (OIDC `sub`, token exchange, Cross-App Access/ID-JAG). Already in threads with their identity-standards people. |
| Cisco / Astrix | Post-acquisition agentic governance into Splunk/Duo — you built the attribution leg their graph lacks. |
| Cerbos | You point *at* them as the enforcement layer (composability). Stole their audit-row vocabulary intentionally. |
| Capsule Security | Runtime trust layer; you cover the forensic/accountability half they don't. |
| Luke Hinds / `nono` | Closest comparable; credit it, extend it with the human-attribution leg. Warm dev-to-dev intro. |

## 13. Recommended stack (one line)
Python + FastAPI gateway, PyJWT for RFC-8693-shaped composite tokens, Ed25519 (`cryptography`) + `pymerkle` + `rfc8785` for the append-only signed Merkle log, fronting one OpenAI/Anthropic function-calling agent and (P3) one MCP server; Keycloak/Zitadel/Auth0 for real OIDC + token exchange past the stub; optional Sigstore Rekor for the external anchor.
