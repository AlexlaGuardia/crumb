"""
The ledger — an append-only, hash-chained, signed record of agent actions.

Each entry links to the previous one by hash, so editing or deleting any past
entry breaks every entry after it. Each entry is signed (Ed25519) so its origin
can't be forged. Together: tamper-evident. A third party can verify the chain and
the signatures without trusting us — that verifier is P2.

This is the RFC 9162 / Sigstore-Rekor structure, scaled to a single file. P2 adds
the Merkle checkpoint + external anchor that defends even against the operator.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

GENESIS = "0" * 64


def canonical(obj: dict) -> bytes:
    """Deterministic bytes for hashing/signing. Production: RFC 8785 (JCS)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


class Ledger:
    """Append-only signed log backed by a JSONL file and an Ed25519 key."""

    def __init__(self, path: str, key_path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.signing_key = self._load_or_create_key(Path(key_path))

    def _load_or_create_key(self, key_path: Path) -> Ed25519PrivateKey:
        if key_path.exists():
            return serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        key = Ed25519PrivateKey.generate()
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        # Publish the public key so verifiers don't need our private key.
        key_path.with_suffix(".pub").write_bytes(
            key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        return key

    def reset(self) -> None:
        """Clear the log (keep the key). Used to keep the demo deterministic."""
        if self.path.exists():
            self.path.unlink()

    def _last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS
        lines = self.path.read_text().splitlines()
        return json.loads(lines[-1])["entry_hash"] if lines else GENESIS

    def _count(self) -> int:
        return sum(1 for _ in self.path.open()) if self.path.exists() else 0

    def append(self, fields: dict) -> dict:
        """Append one signed, hash-chained record and return it."""
        core = {**fields, "seq": self._count(), "prev_hash": self._last_hash()}
        # prev_hash lives inside `core`, so the chain link is part of the hash.
        entry_hash = hashlib.sha256(canonical(core)).hexdigest()
        signature = self.signing_key.sign(entry_hash.encode()).hex()
        record = {**core, "entry_hash": entry_hash, "signature": "ed25519:" + signature}
        with self.path.open("a") as f:
            f.write(json.dumps(record) + "\n")
        return record
