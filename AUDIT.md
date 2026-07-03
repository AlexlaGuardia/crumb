# Crumb — Internal Audit Ledger

Scope: verification client + crypto core (lens) and infra gap-scan (pulse).
Crypto primitives — hash-chain, RFC 6962 Merkle (domain-separated leaf/node),
Ed25519 — audited **sound**.

## Findings

| ID | Sev | Issue | Status | Where |
|----|-----|-------|--------|-------|
| C1 | critical | `crumb verify <url>` followed a server-supplied Rekor URL → forged server redirects the "independent" check to a log it controls, all 3 layers go green. | **fixed** a837783 | `anchor.verify_checkpoint_in_rekor` host-pins to `REKOR_ENTRY_PREFIX` before any network call |
| C1b | high | Host-pin held, but the pinned query used `urllib.urlopen`, which follows 3xx by default → a redirect off-host re-opens C1. | **fixed** 58f4036 | `_REKOR_OPENER` (`build_opener(_NoRedirect)`) refuses all redirects on the Rekor path |
| C2 | note | Remote CLI green could be over-read as operator-independent trust when only chain/sig self-consistency was proven. | **fixed** a837783 | CLI states anchor is the independent root of trust |
| W4 | warn | Hardcoded dev signing secrets in this public repo. | **fixed** a837783 | env (`CRUMB_SESSION_SECRET`/`CRUMB_DELEGATION_SECRET`) else ephemeral per-process |
| CI | infra | Integrity gate added in a837783 keyed on `branches:[main]`; repo default is `master` → never ran once. | **fixed** fc26e97 | trigger on `[master, main]` |
| W5 | warn | Public web demo mutates one shared on-disk ledger; `GET /` reseeds on every load and FastAPI serves sync routes on a threadpool → concurrent visitors interleave `_seed()` (append re-reads file for seq/prev_hash) = duplicate seqs / forked chain (red MISMATCH for everyone), or a read mid-rewrite 500s on a truncated line. | **fixed** 7ca7a28 | reentrant `_LEDGER_LOCK` around every ledger read/mutation in `web.py` |
| C3 | high | `verify_delegation` chose its trust root from the token's own unverified `alg`; the HS256 dev path (symmetric `CRUMB_DELEGATION_SECRET`, held by every minting process) was unconditional → in any IdP deployment, one secret leak forges delegation for any human, and an attacker can just send HS256 to bypass the provider the whole claim rests on. | **fixed** c460e97 | require RS256 whenever `CRUMB_IDP_URL` is set (overridable `require_rs256`); refuse HS256 otherwise |
| W6 | warn | RS256 path verified the signature but never checked `iss`. | **fixed** c460e97 | pin `iss` when `CRUMB_IDP_ISSUER` is set (default unset = stays IdP-agnostic) |
| W7 | low | `federation.verify_chain` walked the stapled chain with no depth bound; each staple embeds the full predecessor (size grows with depth) → a malicious/buggy federated issuer could hand over an arbitrarily deep, size-amplified chain. | **fixed** 7ce1363 | `MAX_CHAIN_DEPTH=16` + `ChainTooDeep` |

## Audited sound (auth core)
- `idp.py` token exchange: verifies the subject token (HS256 human session or prior RS256, `iss`-pinned), mints RS256 with `iss=ISSUER`, nests the actor chain (RFC 8693 §4.1) — correct.
- Per-branch `algorithms=[...]` pinning blocks the classic RS-key-as-HS-secret confusion; `alg=none` is rejected by the HS256 allowlist. The only gap was the *unconditional availability* of the dev trust root (C3).
- `gateway.py` pulls the human from the verified session, never model args; reconciles intent → flags unauthorized calls on the agent. Sound.
- `mcp_server.py` bearer path: reads the actor from the token, never from model-controlled params; `verify_delegation(resource=name)` binds the token's `aud` to the called tool, so a `read_record` token can't be replayed at `export_record`. The C3 fix flows through here — under an IdP the MCP path is RS256-only. Sound.
- `federation.py` cross-issuer verifier: each segment verified against its own issuer's key (federation set, `UntrustedIssuer` otherwise), RS256 hard-pinned (no `alg` downgrade), staple binds the exact predecessor bytes (`StapleMismatch` on swap), human continuity + append-only actor chain enforced (catches both erase and inject). Chain is strictly finite (each `prv` is a substring of its parent — no cycles). Crypto core sound; only the depth bound (W7) was missing. Now CI-gated by the 6 cross-issuer regression tests.
- `federation.py` JWKS-fetch trust source: the trust set now resolves an issuer's key from either a pinned PEM or a live JWKS endpoint, indexed by `kid`. Key selection flows the token header's `kid` into `key_for(iss, kid)`, so a rotated issuer is followed by a single refetch (unknown `kid` → reload once) rather than pinned-PEM breakage. The two failures stay distinct and named: `UntrustedIssuer` (issuer not in the set) vs `UnknownSigningKey` (in the set, no matching key even after refetch) — never a silent fallthrough. Trust boundary preserved: keys are fetched from the issuer's own endpoint (TLS-authenticated in prod), never the server under test; the verifier still names the issuers out of band (`--federation` manifest / `trust_discovery`). JWKS parse is RSA-only (unexpected `kty` refused). CI-gated by the 7 `test_jwks_federation.py` tests (fetch injected, no socket); `jwks_federation_demo` exercises the identical path over real TCP incl. live rotation.

## Regression coverage
`tests/test_integrity.py` (28 tests): C1 non-canonical-URL refusal (parametrized
host-confusion + scheme + path), canonical-prefix lock, redirect-refusal on the
pinned query, Merkle round-trip/domain-separation/tamper, end-to-end ledger
tamper detection, intent reconciliation. CI gates pytest on py3.10–3.12.

## Not a finding
- Web verifier (`web.py`) serves its own anchor data; it does not follow an
  attacker-supplied URL. The independent Rekor check is the client's job, and
  that path is the one pinned + redirect-guarded above.
- `startswith(REKOR_ENTRY_PREFIX)` is robust against `rekor.sigstore.dev.evil`
  and `@`-userinfo host confusion (next char after the host must be `/`).
