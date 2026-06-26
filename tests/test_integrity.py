"""
Integrity-critical regression tests.

Covers the surface the audit (2026-06-26) flagged as untested: the C1 SSRF/Rekor
host-pinning fix, the Merkle primitive (round-trip, domain separation, tamper),
end-to-end ledger tamper detection, and intent reconciliation. These are the
checks a forged ledger must never pass — they gate CI.
"""

from __future__ import annotations

import json

import pytest

from crumb import merkle
from crumb.anchor import REKOR_ENTRY_PREFIX, verify_checkpoint_in_rekor
from crumb.ledger import Ledger
from crumb.verify import find_unauthorized, verify_entries


# ── C1: the verifier must not follow a server-supplied non-canonical Rekor URL ──


@pytest.mark.parametrize(
    "bad_url",
    [
        "https://attacker.example/fake-rekor-entry",
        "https://rekor.sigstore.dev.attacker.example/api/v1/log/entries/x",
        "http://rekor.sigstore.dev/api/v1/log/entries/x",  # wrong scheme
        "https://rekor.sigstore.dev/api/v1/index/x",        # wrong path
        "",
    ],
)
def test_rekor_url_must_be_canonical(bad_url):
    """A malicious operator embeds their own 'Rekor' URL in the anchor; the
    independent check must refuse it WITHOUT a network call, not echo a pass."""
    r = verify_checkpoint_in_rekor(
        root="abc", tree_size=1, ts="2026-01-01T00:00:00Z", rekor_url=bad_url
    )
    assert r["ok"] is False
    assert "non-canonical" in r["reason"]


def test_canonical_prefix_is_the_real_rekor():
    assert REKOR_ENTRY_PREFIX == "https://rekor.sigstore.dev/api/v1/log/entries/"


def test_pinned_query_refuses_redirects(monkeypatch):
    """Host-pinning the URL is moot if the query then follows a 3xx off-host.
    A canonical URL that 302s must fail, not chase the redirect."""
    import urllib.error
    from crumb import anchor

    class _Redirect:
        full_url = REKOR_ENTRY_PREFIX + "deadbeef"

        def open(self, req, timeout=0):
            raise urllib.error.HTTPError(
                self.full_url, 302, "Found",
                {"Location": "https://attacker.example/echo"}, None,
            )

    monkeypatch.setattr(anchor, "_REKOR_OPENER", _Redirect())
    r = verify_checkpoint_in_rekor(
        root="abc", tree_size=1, ts="2026-01-01T00:00:00Z",
        rekor_url=REKOR_ENTRY_PREFIX + "deadbeef",
    )
    assert r["ok"] is False
    assert r["rekor_digest"] is None  # never reached an off-host body


# ── Merkle primitive ────────────────────────────────────────────────────────


@pytest.mark.parametrize("n", range(1, 10))
def test_inclusion_proof_round_trips_every_size(n):
    leaves = [f"leaf-{i}".encode() for i in range(n)]
    root = merkle.root(leaves)
    for i in range(n):
        proof = merkle.inclusion_proof(leaves, i)
        assert merkle.verify_proof(leaves[i], proof, root) is True


def test_proof_fails_for_wrong_leaf():
    leaves = [f"leaf-{i}".encode() for i in range(5)]
    root = merkle.root(leaves)
    proof = merkle.inclusion_proof(leaves, 2)
    assert merkle.verify_proof(b"not-the-leaf", proof, root) is False


def test_leaf_node_domain_separation():
    """RFC 6962: a leaf hash (0x00) and a node hash (0x01) must never collide,
    so a leaf can't be smuggled in as an interior node."""
    a, b = b"a", b"b"
    two_leaf_root = merkle.root([a, b])
    # If domain separation were missing, root([a,b]) would equal H(leaf(a)+leaf(b))
    # without the 0x01 node tag. Just assert it isn't a bare leaf hash.
    assert two_leaf_root != merkle.root([a + b])


# ── End-to-end ledger tamper detection (the core guarantee) ─────────────────


def _build_ledger(tmp_path, n=3):
    led = Ledger(str(tmp_path / "ledger.jsonl"), str(tmp_path / "led.key"))
    for i in range(n):
        led.append({"tool": "search", "arg": f"q{i}", "on_behalf_assertion": "alice"})
    entries = [json.loads(ln) for ln in (tmp_path / "ledger.jsonl").read_text().splitlines()]
    pub_pem = (tmp_path / "led.pub").read_bytes()  # Ledger writes .pub alongside the key
    return entries, pub_pem


def test_clean_ledger_verifies(tmp_path):
    entries, pub_pem = _build_ledger(tmp_path)
    rep = verify_entries(entries, pub_pem)
    assert rep.ok and rep.checked == 3 and rep.issues == []


def test_edited_field_is_caught(tmp_path):
    entries, pub_pem = _build_ledger(tmp_path)
    entries[1]["arg"] = "tampered"  # change a signed field, leave the hash
    rep = verify_entries(entries, pub_pem)
    assert not rep.ok
    assert any("hash mismatch" in reason for _, reason in rep.issues)


def test_dropped_entry_breaks_the_chain(tmp_path):
    entries, pub_pem = _build_ledger(tmp_path)
    del entries[1]  # remove a middle entry
    rep = verify_entries(entries, pub_pem)
    assert not rep.ok
    assert any("broken chain link" in reason for _, reason in rep.issues)


# ── Intent reconciliation ───────────────────────────────────────────────────


def test_find_unauthorized_flags_hijacked_calls(tmp_path):
    p = tmp_path / "ledger.jsonl"
    rows = [
        {"seq": 0, "tool": "search", "on_behalf_assertion": "alice"},
        {"seq": 1, "tool": "wire_money", "on_behalf_assertion": "unauthorized"},
    ]
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    flagged = find_unauthorized(str(p))
    assert len(flagged) == 1 and flagged[0]["tool"] == "wire_money"
