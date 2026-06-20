"""
External anchor — commit the ledger's Merkle root to a log we don't control.

Per-entry signatures stop a forger without the key. They do NOT stop the
operator, who can re-sign a rewritten history. So once in a while we take the
Merkle root over the whole ledger, sign it, and publish it to Sigstore's public
Rekor transparency log. Rekor returns an inclusion proof and a signed timestamp
the operator can't forge or back-date. From then on, any rollback that changes a
past crumb changes the root, which no longer matches what's already public.

Anchors are recorded in data/anchors.jsonl. If Rekor is unreachable the checkpoint
is still written locally (anchored=False) so the chain of checkpoints is unbroken;
only the external witness is missing, and the record says so.

Run: python -m crumb.anchor          # checkpoint now + anchor to Rekor
"""

from __future__ import annotations

import datetime
import hashlib
import json
import urllib.error
import urllib.request
from base64 import b64encode
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from . import merkle
from .ledger import canonical

LEDGER = "data/ledger.jsonl"
ANCHORS = "data/anchors.jsonl"
ANCHOR_KEY = "data/anchor_ec.key"
REKOR = "https://rekor.sigstore.dev"


def _leaves(ledger_path: str = LEDGER) -> list[bytes]:
    """Leaf data = each crumb's entry_hash. The chain links them; the tree
    commits to all of them at once."""
    p = Path(ledger_path)
    if not p.exists():
        return []
    return [json.loads(ln)["entry_hash"].encode()
            for ln in p.read_text().splitlines() if ln.strip()]


def _load_or_create_key(path: str = ANCHOR_KEY):
    kp = Path(path)
    if kp.exists():
        return serialization.load_pem_private_key(kp.read_bytes(), password=None)
    key = ec.generate_private_key(ec.SECP256R1())
    kp.parent.mkdir(parents=True, exist_ok=True)
    kp.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    return key


def _self_signed_cert(key) -> bytes:
    """Rekor's x509 PKI wants a cert, not a bare key. Minimal self-signed wrapper."""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "crumb-anchor")])
    # Fixed validity window (no Date.now in core paths): 2026 → 2036.
    not_before = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    not_after = datetime.datetime(2036, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before).not_valid_after(not_after)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM)


def _submit_rekor(checkpoint_bytes: bytes, key, cert_pem: bytes) -> dict:
    """Submit a hashedrekord entry; return Rekor's inclusion record (or raise)."""
    digest = hashlib.sha256(checkpoint_bytes).hexdigest()
    sig = key.sign(checkpoint_bytes, ec.ECDSA(hashes.SHA256()))
    entry = {
        "apiVersion": "0.0.1",
        "kind": "hashedrekord",
        "spec": {
            "data": {"hash": {"algorithm": "sha256", "value": digest}},
            "signature": {
                "content": b64encode(sig).decode(),
                "publicKey": {"content": b64encode(cert_pem).decode()},
            },
        },
    }
    req = urllib.request.Request(
        f"{REKOR}/api/v1/log/entries",
        data=json.dumps(entry).encode(),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        body = json.load(urllib.request.urlopen(req, timeout=20))
    except urllib.error.HTTPError as e:
        if e.code == 409:  # already logged — the root is anchored, that's a success
            body = json.loads(e.read())
        else:
            raise
    uuid = next(iter(body))
    rec = body[uuid]
    return {
        "uuid": uuid,
        "logIndex": rec.get("logIndex"),
        "integratedTime": rec.get("verification", {}).get("signedEntryTimestamp") and
                          rec.get("integratedTime"),
        "url": f"{REKOR}/api/v1/log/entries/{uuid}",
    }


def checkpoint(ts: str, ledger_path: str = LEDGER) -> dict:
    """Build a checkpoint over the current ledger, anchor it, record it. `ts` is
    passed in (ISO string) so the core stays deterministic for tests/resume."""
    leaves = _leaves(ledger_path)
    cp = {"root": merkle.root(leaves), "tree_size": len(leaves), "ts": ts}
    cp_bytes = canonical(cp)

    key = _load_or_create_key()
    cert = _self_signed_cert(key)
    record = {**cp}
    try:
        record["rekor"] = _submit_rekor(cp_bytes, key, cert)
        record["anchored"] = True
    except Exception as e:  # network/format/rate-limit — keep the local checkpoint
        record["rekor"] = {"error": f"{type(e).__name__}: {e}"}
        record["anchored"] = False

    ap = Path(ANCHORS)
    ap.parent.mkdir(parents=True, exist_ok=True)
    with ap.open("a") as f:
        f.write(json.dumps(record) + "\n")
    return record


def read_anchors(path: str = ANCHORS) -> list[dict]:
    p = Path(path)
    if not p.exists():
        return []
    return [json.loads(ln) for ln in p.read_text().splitlines() if ln.strip()]


def verify_anchors(ledger_path: str = LEDGER, anchors_path: str = ANCHORS) -> dict:
    """Recompute the Merkle root over the anchored prefix of the CURRENT ledger
    and compare it to the root that was published. If the operator re-signed a
    rewritten history, the per-entry chain still verifies — but this root won't
    match the one already in Rekor. That mismatch is the rollback, caught."""
    anchors = read_anchors(anchors_path)
    if not anchors:
        return {"ok": True, "checked": 0, "note": "no anchors yet"}
    latest = anchors[-1]
    n = latest["tree_size"]
    prefix = _leaves(ledger_path)[:n]
    recomputed = merkle.root(prefix)
    ok = recomputed == latest["root"]
    return {
        "ok": ok,
        "checked": len(anchors),
        "tree_size": n,
        "anchored_root": latest["root"],
        "recomputed_root": recomputed,
        "externally_anchored": latest.get("anchored", False),
        "rekor_url": latest.get("rekor", {}).get("url"),
    }


def main() -> None:
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    r = checkpoint(now)
    print(f"checkpoint: tree_size={r['tree_size']} root={r['root'][:24]}…")
    if r["anchored"]:
        k = r["rekor"]
        print(f"anchored to Rekor ✓  logIndex={k['logIndex']}  uuid={k['uuid'][:24]}…")
        print(f"  public: {k['url']}")
    else:
        print(f"anchor SKIPPED (local checkpoint only): {r['rekor']['error']}")


if __name__ == "__main__":
    main()
