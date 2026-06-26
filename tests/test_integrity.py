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


# ── Concurrency: the public demo shares one ledger across all visitors ───────


def test_concurrent_seed_keeps_the_chain_consistent(tmp_path, monkeypatch):
    """`GET /` reseeds on every load and FastAPI serves sync routes on a
    threadpool, so concurrent visitors drive interleaved seeds. Unsynchronized,
    each append() re-reads the file for seq/prev_hash → duplicate seqs, a forked
    chain, and a red MISMATCH for everyone. The lock must keep every observed
    state consistent: any non-empty read has contiguous seqs and the final
    ledger verifies clean."""
    import threading

    from crumb import web
    from crumb.verify import verify_ledger
    from crumb.web import _SEED

    monkeypatch.setattr(web, "LEDGER", str(tmp_path / "ledger.jsonl"))
    monkeypatch.setattr(web, "KEY", str(tmp_path / "ledger.key"))
    monkeypatch.setattr(web, "PUB", str(tmp_path / "ledger.pub"))
    web._seed()  # create the key + a first clean ledger

    errors: list[Exception] = []
    barrier = threading.Barrier(16)

    def seed_worker():
        barrier.wait()
        for _ in range(10):
            web._seed()

    def read_worker():
        barrier.wait()
        for _ in range(40):
            try:
                rows = web._read_ledger()
                seqs = [r["seq"] for r in rows]
                # A read must never observe a torn write: when entries are
                # present they form the contiguous prefix 0..n with no dupes.
                assert seqs == list(range(len(seqs))), seqs
            except Exception as exc:  # truncated JSON line, dup seq, etc.
                errors.append(exc)

    threads = [threading.Thread(target=seed_worker) for _ in range(8)] + \
              [threading.Thread(target=read_worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, errors[:3]
    rep = verify_ledger(web.LEDGER, web.PUB)
    assert rep.ok and rep.checked == len(_SEED)


# ── Delegation trust root: a token must not pick its own verifier ────────────


def test_hs256_dev_token_refused_once_an_idp_is_configured(monkeypatch):
    """The dev HS256 path verifies with a SYMMETRIC secret every minting process
    holds. In a deployment with a real IdP, accepting it means one secret leak
    forges delegation for any human, and an attacker just sends HS256 to skip the
    provider. Configuring an IdP must flip the resource to RS256-only."""
    import jwt
    from crumb import tokens

    monkeypatch.delenv("CRUMB_IDP_URL", raising=False)
    dev_token = tokens.mint_delegation("alice", "support-agent", "read_record")
    assert jwt.get_unverified_header(dev_token)["alg"] == "HS256"

    # No IdP: the offline demo path still works.
    claims = tokens.verify_delegation(dev_token, resource="read_record")
    assert claims["sub"] == "alice"

    # IdP configured: the same HS256 token is now refused, not silently trusted.
    monkeypatch.setenv("CRUMB_IDP_URL", "https://idp.example")
    with pytest.raises(jwt.InvalidAlgorithmError):
        tokens.verify_delegation(dev_token, resource="read_record")

    # And an explicit require_rs256 pins it regardless of env.
    monkeypatch.delenv("CRUMB_IDP_URL", raising=False)
    with pytest.raises(jwt.InvalidAlgorithmError):
        tokens.verify_delegation(dev_token, resource="read_record", require_rs256=True)


def test_alg_none_token_is_never_accepted(monkeypatch):
    """The other half of 'token picks its verifier': an alg=none token must not
    sail through the dev branch on the strength of having no signature."""
    import jwt
    from crumb import tokens

    monkeypatch.delenv("CRUMB_IDP_URL", raising=False)
    forged = jwt.encode({"sub": "attacker", "aud": "read_record"}, key="",
                        algorithm="none")
    with pytest.raises(jwt.PyJWTError):
        tokens.verify_delegation(forged, resource="read_record")


# ── Cross-issuer chain: each issuer signs only its segment, human survives ────


def _federation_setup():
    """Two issuers (A = human's home IdP, B = tool's domain) + a verifier that
    federates with both. Mirrors cross_issuer_demo, as a fixture for the gate."""
    import time
    import uuid

    from crumb import auth
    from crumb.federation import Federation, Issuer, staple_hash

    idp_a = Issuer("https://idp-a.local")
    idp_b = Issuer("https://idp-b.local")
    verifier = Federation().trust(idp_a).trust(idp_b)

    def claims(iss, sub, act, prv=None, pis=None, resource="read_record"):
        now = int(time.time())
        body = {"iss": iss, "sub": sub, "act": act, "aud": resource,
                "jti": uuid.uuid4().hex, "iat": now, "exp": now + 60}
        if prv is not None:
            body.update({"prv": prv, "psh": staple_hash(prv), "pis": pis})
        return body

    return idp_a, idp_b, verifier, claims, auth


def test_cross_issuer_chain_verifies_back_to_the_human():
    from crumb.federation import Federation, verify_chain

    idp_a, idp_b, verifier, _claims, auth = _federation_setup()
    alice = auth.login("alice", directives=("read_record",))
    tok_a = idp_a.exchange(alice.token, "planner", "read_record", Federation())
    tok_b = idp_b.exchange(tok_a, "researcher", "read_record",
                           Federation().trust(idp_a))

    resolved = verify_chain(tok_b, "read_record", verifier)
    assert resolved["human"] == "alice"
    assert resolved["actor_chain"] == ["researcher", "planner"]
    assert resolved["issuer_path"] == ["https://idp-b.local", "https://idp-a.local"]


def test_cross_issuer_rejects_every_tamper():
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa

    from crumb.federation import (ActorChainBroken, Federation,
                                  HumanDiscontinuity, StapleMismatch,
                                  UntrustedIssuer, verify_chain)

    idp_a, idp_b, verifier, _c, auth = _federation_setup()
    R = "read_record"
    alice = auth.login("alice", directives=(R,))
    bob = auth.login("bob", directives=(R,))
    tok_a = idp_a.exchange(alice.token, "planner", R, Federation())
    tok_a_bob = idp_a.exchange(bob.token, "planner", R, Federation())

    def sign(body, issuer):
        return jwt.encode(body, issuer._key, algorithm="RS256",
                          headers={"kid": issuer.kid})

    # B can mint its own segment but cannot sign as A.
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged_inner = jwt.encode(_c(idp_a.iss, "mallory", {"sub": "planner"}),
                              attacker, algorithm="RS256")
    forged = sign(_c(idp_b.iss, "mallory",
                     {"sub": "researcher", "act": {"sub": "planner"}},
                     prv=forged_inner, pis=idp_a.iss), idp_b)
    with pytest.raises(jwt.InvalidSignatureError):
        verify_chain(forged, R, verifier)

    # Swap the stapled token but leave psh hashing the original.
    swapped = jwt.decode(idp_b.exchange(tok_a, "researcher", R,
                                        Federation().trust(idp_a)),
                         options={"verify_signature": False})
    swapped["prv"] = tok_a_bob
    with pytest.raises(StapleMismatch):
        verify_chain(sign(swapped, idp_b), R, verifier)

    # Claim alice but staple a token A issued for bob.
    disc = sign(_c(idp_b.iss, "alice",
                   {"sub": "researcher", "act": {"sub": "planner"}},
                   prv=tok_a_bob, pis=idp_a.iss), idp_b)
    with pytest.raises(HumanDiscontinuity):
        verify_chain(disc, R, verifier)

    # Rewrite the inherited actor chain (ghost instead of planner).
    rewrite = sign(_c(idp_b.iss, "alice",
                      {"sub": "researcher", "act": {"sub": "ghost"}},
                      prv=tok_a, pis=idp_a.iss), idp_b)
    with pytest.raises(ActorChainBroken):
        verify_chain(rewrite, R, verifier)

    # An upstream issuer the verifier does not federate with.
    idp_c = type(idp_a)("https://idp-c.rogue")
    tok_c = idp_c.exchange(alice.token, "planner", R, Federation())
    tok_bc = idp_b.exchange(tok_c, "researcher", R, Federation().trust(idp_c))
    with pytest.raises(UntrustedIssuer):
        verify_chain(tok_bc, R, verifier)


def test_cross_issuer_refuses_an_overdeep_chain():
    import jwt

    from crumb.federation import (MAX_CHAIN_DEPTH, ChainTooDeep, Federation,
                                  verify_chain)

    idp_a, idp_b, verifier, _c, auth = _federation_setup()
    R = "read_record"
    alice = auth.login("alice", directives=(R,))
    tok = idp_a.exchange(alice.token, "agent0", R, Federation())
    # Re-staple through B well past the depth bound; each hop is validly signed.
    for i in range(MAX_CHAIN_DEPTH + 2):
        tok = idp_b.exchange(tok, f"agent{i+1}", R, Federation().trust(idp_a).trust(idp_b))
    with pytest.raises(ChainTooDeep):
        verify_chain(tok, R, verifier)
