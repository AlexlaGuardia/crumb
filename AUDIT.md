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
