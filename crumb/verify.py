"""
verify — prove a Crumb ledger wasn't altered, without trusting whoever holds it.

Re-walks the log and checks three things per entry:
  1. integrity — recompute the entry hash from its fields; it must match.
  2. chain     — each entry's prev_hash must equal the previous entry's hash.
  3. signature — each entry hash must verify against the published Ed25519 key.

Any edit, deletion, or reorder of a past entry breaks at least one of these. The
verifier needs only the log and the public key — never the operator's word.

Run: python -m crumb.verify [ledger.jsonl] [ledger.pub]
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from .ledger import GENESIS, canonical

ENVELOPE = ("entry_hash", "signature")  # everything else is signed-over core


@dataclass
class Report:
    ok: bool
    checked: int
    issues: list = field(default_factory=list)  # (seq, reason)


def verify_ledger(path: str = "data/ledger.jsonl",
                  pubkey_path: str = "data/ledger.pub") -> Report:
    pub = serialization.load_pem_public_key(Path(pubkey_path).read_bytes())
    lines = Path(path).read_text().splitlines()
    issues: list = []
    prev_hash = GENESIS

    for i, line in enumerate(lines):
        rec = json.loads(line)
        seq = rec.get("seq", i)
        core = {k: v for k, v in rec.items() if k not in ENVELOPE}

        if hashlib.sha256(canonical(core)).hexdigest() != rec["entry_hash"]:
            issues.append((seq, "entry hash mismatch (a field was edited)"))
        elif rec["prev_hash"] != prev_hash:
            issues.append((seq, "broken chain link (entry inserted, removed, or reordered)"))
        else:
            sig = bytes.fromhex(rec["signature"].removeprefix("ed25519:"))
            try:
                pub.verify(sig, rec["entry_hash"].encode())
            except InvalidSignature:
                issues.append((seq, "bad signature (forged or re-signed without the key)"))

        prev_hash = rec["entry_hash"]

    return Report(ok=not issues, checked=len(lines), issues=issues)


def main() -> None:
    args = sys.argv[1:]
    path = args[0] if args else "data/ledger.jsonl"
    pub = args[1] if len(args) > 1 else "data/ledger.pub"
    report = verify_ledger(path, pub)
    if report.ok:
        print(f"  VERIFIED ✓  {report.checked} entries — chain intact, all signatures valid.")
    else:
        print(f"  MISMATCH ✗  {report.checked} entries checked, {len(report.issues)} problem(s):")
        for seq, reason in report.issues:
            print(f"    entry {seq}: {reason}")
        sys.exit(1)


if __name__ == "__main__":
    main()
