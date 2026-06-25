"""
Tests for verify_entries (the in-memory verification core) and the verify_ledger
thin wrapper.  Also exercises the Merkle root recompute used by the CLI.

Convention: isolated temp ledger + fresh key per test; never touch data/.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from crumb import auth
from crumb.agent import ToolCall
from crumb.anchor import _leaves, checkpoint, read_anchors
from crumb.gateway import Gateway
from crumb.ledger import Ledger, canonical
from crumb.merkle import root as merkle_root
from crumb.verify import verify_entries, verify_ledger


# ── fixtures ──────────────────────────────────────────────────────────────────


def _make_ledger(tmp: Path) -> tuple[Ledger, Path, Path]:
    """Return (Ledger, ledger_path, pub_path) in a temp directory."""
    ledger_path = tmp / "test_ledger.jsonl"
    key_path = tmp / "test_ledger.key"
    ledger = Ledger(str(ledger_path), str(key_path))
    pub_path = key_path.with_suffix(".pub")
    return ledger, ledger_path, pub_path


def _seed_ledger(ledger: Ledger, n: int = 5) -> list[dict]:
    """Append n crumbs via the Gateway; return the written records."""
    gw = Gateway(ledger=ledger, agent_id="test-agent")
    records = []
    for i in range(n):
        who = ["alice", "bob", "carol"][i % 3]
        session = auth.login(who, directives=("read_record",))
        call = ToolCall(name="read_record", arguments={"record_id": i})
        d = gw.dispatch(session, call,
                        transport="openai",
                        ts=f"2026-06-25T12:0{i}:00+00:00")
        records.append(d.record)
    return records


# ── basic verify_entries tests ────────────────────────────────────────────────


def test_verify_entries_clean():
    """A freshly written ledger verifies clean."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        ledger, ledger_path, pub_path = _make_ledger(tmp)
        _seed_ledger(ledger, 5)

        entries = [json.loads(ln) for ln in ledger_path.read_text().splitlines() if ln.strip()]
        pub_pem = pub_path.read_bytes()

        report = verify_entries(entries, pub_pem)
        assert report.ok is True
        assert report.checked == 5
        assert report.issues == []


def test_verify_entries_tampered_field():
    """Editing a field inside a crumb breaks the entry hash at that row."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        ledger, ledger_path, pub_path = _make_ledger(tmp)
        _seed_ledger(ledger, 5)

        pub_pem = pub_path.read_bytes()
        lines = ledger_path.read_text().splitlines()

        # Tamper entry at seq 2: flip the actor_identity
        target_idx = 2
        rec = json.loads(lines[target_idx])
        rec["actor_identity"] = "mallory"
        lines[target_idx] = json.dumps(rec)

        entries = [json.loads(ln) for ln in lines if ln.strip()]
        report = verify_entries(entries, pub_pem)

        assert report.ok is False
        assert any(seq == 2 and "entry hash mismatch" in reason
                   for seq, reason in report.issues), \
            f"expected entry-hash mismatch at seq 2, got: {report.issues}"


def test_verify_entries_broken_chain():
    """Deleting an entry breaks the chain link at the next entry."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        ledger, ledger_path, pub_path = _make_ledger(tmp)
        _seed_ledger(ledger, 5)

        pub_pem = pub_path.read_bytes()
        lines = ledger_path.read_text().splitlines()

        # Drop entry 1 — entry 2's prev_hash now points at a non-existent hash
        del lines[1]
        entries = [json.loads(ln) for ln in lines if ln.strip()]
        report = verify_entries(entries, pub_pem)

        assert report.ok is False
        assert any("broken chain link" in reason for _, reason in report.issues)


def test_verify_entries_bad_signature():
    """A crumb re-hashed without the signing key produces a bad-signature failure."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        ledger, ledger_path, pub_path = _make_ledger(tmp)
        _seed_ledger(ledger, 3)

        pub_pem = pub_path.read_bytes()
        lines = ledger_path.read_text().splitlines()

        # Build a plausible-looking but differently-signed entry by forging the
        # signature bytes (keeps entry_hash intact so chain doesn't break first).
        target_idx = 1
        rec = json.loads(lines[target_idx])
        rec["signature"] = "ed25519:" + "ab" * 32  # 64 bytes of garbage
        lines[target_idx] = json.dumps(rec)

        entries = [json.loads(ln) for ln in lines if ln.strip()]
        report = verify_entries(entries, pub_pem)

        assert report.ok is False
        assert any("bad signature" in reason for _, reason in report.issues)


# ── verify_ledger wrapper ─────────────────────────────────────────────────────


def test_verify_ledger_wrapper_matches_verify_entries():
    """verify_ledger must return the same result as verify_entries on the same data."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        ledger, ledger_path, pub_path = _make_ledger(tmp)
        _seed_ledger(ledger, 4)

        pub_pem = pub_path.read_bytes()
        entries = [json.loads(ln) for ln in ledger_path.read_text().splitlines() if ln.strip()]

        r1 = verify_entries(entries, pub_pem)
        r2 = verify_ledger(str(ledger_path), str(pub_path))

        assert r1.ok == r2.ok
        assert r1.checked == r2.checked
        assert r1.issues == r2.issues


# ── Merkle root recompute (mirrors CLI layer 2) ───────────────────────────────


def test_merkle_root_matches_checkpoint(tmp_path):
    """After anchoring, recomputing the Merkle root over the same prefix must
    match the stored anchored root — this is what the CLI layer 2 check does."""
    ledger_path = tmp_path / "ml.jsonl"
    key_path = tmp_path / "ml.key"
    anchors_path = tmp_path / "anchors.jsonl"

    ledger = Ledger(str(ledger_path), str(key_path))
    gw = Gateway(ledger=ledger, agent_id="test-agent")

    for i in range(4):
        session = auth.login("alice", directives=("read_record",))
        gw.dispatch(session,
                    ToolCall(name="read_record", arguments={"record_id": i}),
                    ts=f"2026-06-25T13:0{i}:00+00:00")

    # Anchor (skips Rekor if unreachable — local record still written)
    rec = checkpoint("2026-06-25T13:05:00+00:00",
                     ledger_path=str(ledger_path))

    entries = [json.loads(ln) for ln in ledger_path.read_text().splitlines() if ln.strip()]
    tree_size = rec["tree_size"]
    anchored_root = rec["root"]
    leaves = [e["entry_hash"].encode() for e in entries[:tree_size]]
    recomputed = merkle_root(leaves)

    assert recomputed == anchored_root, (
        f"Merkle root mismatch: anchored={anchored_root!r} vs recomputed={recomputed!r}"
    )
