"""
crumb verify — client-side verifier CLI.

Prove which human directed an agent's actions WITHOUT trusting whoever holds
the log. All cryptographic checks run locally on data YOU fetched; the only
network call beyond pulling the raw data is a direct query to Sigstore's public
Rekor log — a transparency log the operator doesn't control.

Usage:
    crumb verify <target> [--federation <manifest>] [--json]

target may be:
    - A URL  (http[s]://...)  — fetches ledger, pubkey, and anchors from the
      remote server, then verifies everything client-side.
    - A local path to a ledger.jsonl file — verifies chain + signatures using
      a co-located .pub file (same stem), plus Rekor if anchors.jsonl is present.

Layers checked:
    1. chain & signatures      — per-entry hash chain + Ed25519 on every crumb
    2. merkle root             — recompute tree over entry_hash leaves, compare
                                 to the latest anchor's published root
    3. public anchor           — direct GET to rekor.sigstore.dev, confirm the
                                 anchored digest matches our recomputed checkpoint
    4. actor binding           — for crumbs carrying a delegation token, re-walk
                                 it against --federation and confirm the recorded
                                 human is the one the token proves. Without
                                 --federation this layer is a VISIBLE skip, never
                                 a silent pass.

--federation <manifest> is a JSON file naming the issuers the verifier accepts —
its own trust set, supplied out-of-band, never taken from the server under test.
Each issuer's key comes from one of two sources, mixable per issuer:
    "iss": "-----BEGIN PUBLIC KEY-----\\n..."   pinned PEM (static)
    "iss": "https://idp/jwks"                    fetch keys from that JWKS URL
    "iss": {"jwks_uri": "https://idp/jwks"}      same, explicit
    "iss": {"discovery": "https://idp"}          read /.well-known, then fetch
Fetched keys follow issuer rotation and are pulled from the ISSUER's own endpoint
(TLS-authenticated), so the human check stays operator-independent either way.

Exit 0 only when all layers pass.  Nonzero on any failure; prints the layer
name and the offending entry or mismatch.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx

from cryptography.hazmat.primitives import serialization

from . import merkle
from .anchor import verify_checkpoint_in_rekor
from .federation import Federation
from .verify import verify_actor_binding, verify_entries

# ── helpers ──────────────────────────────────────────────────────────────────

_CHECK = "✓"
_CROSS = "✗"


def _tick(ok: bool) -> str:
    return _CHECK if ok else _CROSS


def _fetch(url: str) -> bytes:
    """GET with a clear error on failure."""
    resp = httpx.get(url, timeout=20, follow_redirects=True)
    resp.raise_for_status()
    return resp.content


def _load_federation(path: str) -> Federation:
    """Build a Federation from a local trust manifest: JSON naming each issuer the
    verifier accepts and where its key comes from. A value may be:

      - a PEM string  ("-----BEGIN PUBLIC KEY-----...")  -> pinned, static.
      - a URL string  ("https://idp/jwks")               -> fetched from that JWKS.
      - {"jwks_uri": "..."}                              -> fetched, explicit.
      - {"discovery": "https://idp"}                     -> discover then fetch.

    Either way the manifest is the verifier's OWN out-of-band trust set — the
    issuers, and the endpoints their keys come from, are named by you, never taken
    from the server under test. Pinned keys are frozen; fetched keys follow the
    issuer's rotation and are pulled from the issuer's own (TLS) endpoint."""
    manifest = json.loads(Path(path).read_text())
    fed = Federation()
    for iss, source in manifest.items():
        if isinstance(source, dict):
            if source.get("discovery"):
                fed.trust_discovery(iss, discovery_url=_discovery_url(source["discovery"]))
            elif source.get("jwks_uri"):
                fed.trust_jwks_uri(iss, source["jwks_uri"])
            else:
                raise ValueError(f"issuer {iss!r}: object needs 'jwks_uri' or 'discovery'")
        elif source.lstrip().startswith("-----BEGIN"):
            fed.trust_key(iss, serialization.load_pem_public_key(source.encode()))
        elif source.startswith("http"):
            fed.trust_jwks_uri(iss, source)
        else:
            raise ValueError(f"issuer {iss!r}: value must be a PEM, a URL, or an object")
    return fed


def _discovery_url(base: str) -> str:
    """Accept either an issuer base (append the well-known path) or a full
    discovery URL (use as-is), so a manifest can give whichever it has."""
    if base.endswith("/.well-known/openid-configuration"):
        return base
    return f"{base.rstrip('/')}/.well-known/openid-configuration"


# ── core verification logic (shared by remote + local paths) ─────────────────


def _binding_layer(entries: list[dict], federation: "Federation | None") -> dict:
    """Layer 4 (conditional): cryptographically confirm the recorded human by
    re-walking each crumb's actor_token against a pinned federation trust set.

    Only meaningful for token-bearing ledgers. Three states:
      - no bound crumbs           -> {"ok": None, "note": "no bound crumbs"}
      - bound crumbs, no --federation -> {"ok": None, "note": ...}  (visible skip,
        never a silent pass: the human went unchecked and the report says so)
      - federation supplied       -> pass/fail from verify_actor_binding
    """
    has_tokens = any(e.get("actor_token") for e in entries)
    if not has_tokens:
        return {"ok": None, "note": "no bound crumbs"}
    if federation is None:
        return {"ok": None,
                "note": "bound crumbs present but no --federation set; "
                        "human NOT cryptographically checked"}
    report = verify_actor_binding(entries, federation)
    return {
        "ok": report.ok,
        "checked": report.checked,
        "issues": [(seq, reason) for seq, reason in report.issues],
    }


def _run_verification(
    entries: list[dict],
    pub_pem: bytes,
    anchors: list[dict],
    federation: "Federation | None" = None,
) -> dict:
    """Run every verification layer and return a structured result dict.

    Args:
        entries:     parsed ledger entries
        pub_pem:     Ed25519 public key bytes (PEM)
        anchors:     list of anchor records (may be empty)
        federation:  the verifier's pinned issuer trust set for the actor-binding
                     layer, or None to skip it (see _binding_layer)

    Returns:
        {
            "chain":   {"ok": bool, "checked": int, "issues": [...] or []},
            "merkle":  {"ok": bool, ...} | {"ok": None, "note": "no anchors"},
            "rekor":   {...}            | {"ok": None, "note": ...},
            "binding": {"ok": bool, ...} | {"ok": None, "note": ...},
        }
    """
    # Layer 1: chain + signatures
    report = verify_entries(entries, pub_pem)
    chain_result = {
        "ok": report.ok,
        "checked": report.checked,
        "issues": [(seq, reason) for seq, reason in report.issues],
    }
    binding_result = _binding_layer(entries, federation)

    if not anchors:
        return {
            "chain": chain_result,
            "merkle": {"ok": None, "note": "no anchors"},
            "rekor": {"ok": None, "note": "no anchors"},
            "binding": binding_result,
        }

    latest = anchors[-1]
    tree_size = latest["tree_size"]
    anchored_root = latest["root"]

    # Layer 2: recompute Merkle root over the anchored prefix
    leaves = [e["entry_hash"].encode() for e in entries[:tree_size]]
    recomputed = merkle.root(leaves)
    merkle_result = {
        "ok": recomputed == anchored_root,
        "anchored_root": anchored_root,
        "recomputed_root": recomputed,
        "tree_size": tree_size,
    }

    # Layer 3: independent Rekor query
    rekor_info = latest.get("rekor", {})
    rekor_entry_url = rekor_info.get("url")
    if not rekor_entry_url or not latest.get("anchored", False):
        rekor_result: dict = {"ok": None, "note": "anchor not submitted to Rekor"}
    else:
        rekor_result = verify_checkpoint_in_rekor(
            root=anchored_root,
            tree_size=tree_size,
            ts=latest["ts"],
            rekor_url=rekor_entry_url,
        )

    return {
        "chain": chain_result,
        "merkle": merkle_result,
        "rekor": rekor_result,
        "binding": binding_result,
    }


# ── remote path ──────────────────────────────────────────────────────────────


def _verify_remote(base_url: str, federation: "Federation | None" = None) -> dict:
    base = base_url.rstrip("/")
    try:
        entries = json.loads(_fetch(f"{base}/api/ledger"))["entries"]
    except Exception as exc:
        return {"error": f"could not fetch ledger from {base}: {exc}"}
    try:
        pub_pem = _fetch(f"{base}/api/pubkey")
    except Exception as exc:
        return {"error": f"could not fetch pubkey from {base}: {exc}"}
    try:
        anchors = json.loads(_fetch(f"{base}/api/anchors"))["anchors"]
    except Exception as exc:
        return {"error": f"could not fetch anchors from {base}: {exc}"}

    result = _run_verification(entries, pub_pem, anchors, federation)
    result["source"] = base
    return result


# ── local path ───────────────────────────────────────────────────────────────


def _verify_local(ledger_path: str, federation: "Federation | None" = None) -> dict:
    p = Path(ledger_path)
    if not p.exists():
        return {"error": f"ledger not found: {ledger_path}"}

    pub_path = p.with_suffix(".pub")
    if not pub_path.exists():
        return {"error": f"public key not found: {pub_path}"}

    entries_text = p.read_text().splitlines()
    entries = [json.loads(ln) for ln in entries_text if ln.strip()]
    pub_pem = pub_path.read_bytes()

    anchors_path = p.parent / "anchors.jsonl"
    anchors: list[dict] = []
    if anchors_path.exists():
        anchors = [
            json.loads(ln)
            for ln in anchors_path.read_text().splitlines()
            if ln.strip()
        ]

    result = _run_verification(entries, pub_pem, anchors, federation)
    result["source"] = str(p)
    return result


# ── output formatting ─────────────────────────────────────────────────────────


def _print_report(result: dict) -> int:
    """Print the layered report. Return the exit code (0 = all pass)."""
    if "error" in result:
        print(f"  error: {result['error']}", file=sys.stderr)
        return 1

    source = result.get("source", "")
    remote = source.startswith("http://") or source.startswith("https://")
    print(f"\nCrumb — verifying {source}\n")

    all_ok = True

    # Layer 1: chain & signatures
    c = result["chain"]
    ok1 = bool(c.get("ok"))
    print(f"  {_tick(ok1)} chain & signatures  ({c.get('checked', 0)} entries)")
    if not ok1:
        all_ok = False
        for seq, reason in c.get("issues", []):
            print(f"       entry {seq}: {reason}")

    # Layer 2: Merkle root
    m = result["merkle"]
    if m.get("ok") is None:
        print(f"  - merkle root          ({m.get('note', 'skipped')})")
    else:
        ok2 = bool(m.get("ok"))
        print(f"  {_tick(ok2)} merkle root        "
              f"(tree_size={m.get('tree_size')}, "
              f"anchored={m.get('anchored_root', '')[:16]}…)")
        if not ok2:
            all_ok = False
            print(f"       anchored:    {m.get('anchored_root')}")
            print(f"       recomputed:  {m.get('recomputed_root')}")

    # Layer 3: public Rekor anchor
    r = result["rekor"]
    if r.get("ok") is None:
        print(f"  - public anchor        ({r.get('note', 'skipped')})")
    else:
        ok3 = bool(r.get("ok"))
        log_index = r.get("logIndex")
        int_time = r.get("integratedTime")
        rekor_url = r.get("rekor_url", "")
        # Friendly rekor_url: just the base domain for display
        rekor_base = "/".join(rekor_url.split("/")[:3]) if rekor_url else ""
        print(f"  {_tick(ok3)} public anchor      "
              f"(Rekor logIndex={log_index}, "
              f"integratedTime={int_time}, "
              f"{rekor_base})")
        if not ok3:
            all_ok = False
            reason = r.get("reason", "digest mismatch")
            print(f"       {reason}")

    # Layer 4: actor binding (the recorded human, re-derived from the token)
    b = result.get("binding", {"ok": None, "note": "no bound crumbs"})
    if b.get("ok") is None:
        print(f"  - actor binding        ({b.get('note', 'skipped')})")
    else:
        ok4 = bool(b.get("ok"))
        print(f"  {_tick(ok4)} actor binding      "
              f"({b.get('checked', 0)} human(s) proven from token)")
        if not ok4:
            all_ok = False
            for seq, reason in b.get("issues", []):
                print(f"       entry {seq}: {reason}")

    verdict = "VERIFIED" if all_ok else "MISMATCH"
    print(f"\n  {verdict}\n")

    if remote:
        # The pubkey and ledger both came from the server under verification, so
        # "chain & signatures" only proves that server is internally consistent
        # with its own key — a forged server passes it trivially. Independence
        # comes solely from the public anchor (a log the operator can't control).
        # Be explicit so a green result isn't read as more than it is.
        print(
            "  note: pubkey fetched from the server under test — chain & signature\n"
            "        checks prove only self-consistency. Operator-independent trust\n"
            "        comes from the public anchor; pin the pubkey out-of-band for more.\n"
        )
    return 0 if all_ok else 1


# ── JSON output ───────────────────────────────────────────────────────────────


def _print_json(result: dict) -> int:
    # Make issues JSON-serialisable (they're tuples from verify_entries)
    for layer in ("chain", "binding"):
        if layer in result and "issues" in result[layer]:
            result[layer]["issues"] = [
                {"seq": seq, "reason": reason}
                for seq, reason in result[layer]["issues"]
            ]
    all_ok = (
        "error" not in result
        and bool(result.get("chain", {}).get("ok"))
        and result.get("merkle", {}).get("ok") is not False
        and result.get("rekor", {}).get("ok") is not False
        and result.get("binding", {}).get("ok") is not False
    )
    result["verified"] = all_ok
    print(json.dumps(result, indent=2))
    return 0 if all_ok else 1


# ── entry point ───────────────────────────────────────────────────────────────


def main() -> None:
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)

    if args[0] != "verify":
        print(f"unknown command: {args[0]}\nUsage: crumb verify <target> [--json]",
              file=sys.stderr)
        sys.exit(1)

    rest = args[1:]
    use_json = "--json" in rest

    # --federation <path>: the verifier's pinned issuer trust set for actor binding
    federation = None
    if "--federation" in rest:
        fi = rest.index("--federation")
        try:
            fed_path = rest[fi + 1]
        except IndexError:
            print("--federation needs a path to a JSON issuer->PEM manifest",
                  file=sys.stderr)
            sys.exit(1)
        try:
            federation = _load_federation(fed_path)
        except Exception as exc:
            print(f"could not load federation manifest {fed_path}: {exc}",
                  file=sys.stderr)
            sys.exit(1)
        rest = rest[:fi] + rest[fi + 2:]

    targets = [a for a in rest if a != "--json"]

    if not targets:
        print("Usage: crumb verify <url-or-ledger-path> [--federation <manifest>] "
              "[--json]", file=sys.stderr)
        sys.exit(1)

    target = targets[0]

    if target.startswith("http://") or target.startswith("https://"):
        result = _verify_remote(target, federation)
    else:
        result = _verify_local(target, federation)

    if use_json:
        sys.exit(_print_json(result))
    else:
        sys.exit(_print_report(result))


if __name__ == "__main__":
    main()
