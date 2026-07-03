"""
Trustless key distribution — the JWKS-fetch leg of federation.

The cross-issuer verifier already refused to take an operator's word for the
upstream human; it checked each segment against the issuer's key. Those tests pin
the keys in-process. These prove the same verification holds when the verifier
holds NO key up front and fetches each issuer's current JWKS from its own
endpoint — the real OIDC steady state, with rotation and the two distinct failure
modes (issuer not federated vs. key not found) exercised explicitly.

Fetches are injected (no socket): `_JWKSHost` serves an issuer's discovery + JWKS
documents from memory and can rotate its signing key the way a real IdP does.
`jwks_federation_demo` drives the identical path over real TCP.
"""

from __future__ import annotations

import jwt
import pytest

from crumb import auth
from crumb.federation import (
    Federation,
    Issuer,
    UnknownSigningKey,
    UntrustedIssuer,
    verify_chain,
)

RESOURCE = "read_record"


class _JWKSHost:
    """An issuer's public face over an in-memory fetch: its discovery document and
    its JWKS, both reachable by URL, with a `rotate()` that swaps the signing key
    to a fresh `kid` — exactly what a verifier that only pinned a static PEM would
    fail to follow."""

    def __init__(self, iss: str):
        self.iss = iss
        self._gen = 1
        self.issuer = Issuer(iss, kid=f"{iss}-rs256-{self._gen}")
        self.disco_url = f"{iss}/.well-known/openid-configuration"
        self.jwks_url = f"{iss}/jwks"
        self.hits: dict = {"disco": 0, "jwks": 0}

    def fetch(self, url: str) -> dict:
        if url == self.disco_url:
            self.hits["disco"] += 1
            return {"issuer": self.iss, "jwks_uri": self.jwks_url}
        if url == self.jwks_url:
            self.hits["jwks"] += 1
            return self.issuer.jwks()
        raise AssertionError(f"unexpected fetch: {url!r}")

    def rotate(self) -> None:
        self._gen += 1  # new key AND new kid — as a real IdP rotates
        self.issuer = Issuer(self.iss, kid=f"{self.iss}-rs256-{self._gen}")


def _human(sub="alice"):
    return auth.login(sub, directives=(RESOURCE,))


def test_single_issuer_verifies_via_fetched_jwks():
    host = _JWKSHost("https://idp-a.local")
    alice = _human()
    token = host.issuer.exchange(alice.token, "planner", RESOURCE, Federation())

    # The verifier pins NOTHING: it names the issuer and fetches its keys.
    fed = Federation().trust_jwks_uri(host.iss, host.jwks_url, fetch=host.fetch)
    resolved = verify_chain(token, RESOURCE, fed)

    assert resolved["human"] == "alice"
    assert resolved["actor_chain"] == ["planner"]
    assert host.hits["jwks"] == 1  # fetched once, then cached


def test_discovery_reads_jwks_uri_from_well_known():
    host = _JWKSHost("https://idp-a.local")
    alice = _human()
    token = host.issuer.exchange(alice.token, "planner", RESOURCE, Federation())

    # trust_discovery only names the issuer; the issuer's own metadata says where
    # its keys live.
    fed = Federation().trust_discovery(host.iss, fetch=host.fetch)
    resolved = verify_chain(token, RESOURCE, fed)

    assert resolved["human"] == "alice"
    assert host.hits["disco"] == 1
    assert host.hits["jwks"] == 1


def test_cross_issuer_chain_verifies_with_both_jwks_fetched():
    host_a = _JWKSHost("https://idp-a.local")
    host_b = _JWKSHost("https://idp-b.local")
    alice = _human()

    tok_a = host_a.issuer.exchange(alice.token, "planner", RESOURCE, Federation())
    # B federates with A to *exchange* (in-process trust is fine at mint time);
    # the point under test is the VERIFIER's trust, established by fetch.
    tok_b = host_b.issuer.exchange(
        tok_a, "researcher", RESOURCE, Federation().trust(host_a.issuer))

    fed = (Federation()
           .trust_discovery(host_a.iss, fetch=host_a.fetch)
           .trust_discovery(host_b.iss, fetch=host_b.fetch))
    resolved = verify_chain(tok_b, RESOURCE, fed)

    assert resolved["human"] == "alice"
    assert resolved["actor_chain"] == ["researcher", "planner"]
    assert resolved["issuer_path"] == [host_b.iss, host_a.iss]


def test_rotation_is_followed_by_a_single_refetch():
    host = _JWKSHost("https://idp-a.local")
    fed = Federation().trust_jwks_uri(host.iss, host.jwks_url, fetch=host.fetch)

    tok1 = host.issuer.exchange(_human().token, "planner", RESOURCE, Federation())
    assert verify_chain(tok1, RESOURCE, fed)["human"] == "alice"
    assert host.hits["jwks"] == 1

    # The issuer rotates its signing key. A pinned PEM would now be stale; the
    # fetched source sees a kid it hasn't cached and refetches exactly once.
    host.rotate()
    tok2 = host.issuer.exchange(_human().token, "planner", RESOURCE, Federation())
    assert verify_chain(tok2, RESOURCE, fed)["human"] == "alice"
    assert host.hits["jwks"] == 2  # one refetch, not one-per-token


def test_unfederated_issuer_is_still_refused():
    host = _JWKSHost("https://idp-a.local")
    token = host.issuer.exchange(_human().token, "planner", RESOURCE, Federation())

    empty = Federation()  # names no issuers at all
    with pytest.raises(UntrustedIssuer):
        verify_chain(token, RESOURCE, empty)


def test_unknown_kid_is_refused_not_guessed():
    host = _JWKSHost("https://idp-a.local")
    fed = Federation().trust_jwks_uri(host.iss, host.jwks_url, fetch=host.fetch)

    # A token claiming a kid the issuer never published: signed by the real key but
    # headered with a ghost kid. The issuer is trusted, the key is not found — even
    # after a refetch — so it dies as UnknownSigningKey, distinct from Untrusted.
    good = host.issuer.exchange(_human().token, "planner", RESOURCE, Federation())
    claims = jwt.decode(good, options={"verify_signature": False})
    forged = jwt.encode(claims, host.issuer._key, algorithm="RS256",
                        headers={"kid": "ghost-kid"})
    with pytest.raises(UnknownSigningKey):
        verify_chain(forged, RESOURCE, fed)


def test_cli_manifest_parses_pem_and_url_sources(tmp_path):
    """The `--federation` manifest accepts a pinned PEM, a bare JWKS URL, and an
    explicit {jwks_uri} object — all naming issuers the verifier chose. URL forms
    register a fetched source lazily (no network at load time)."""
    import json as _json

    from cryptography.hazmat.primitives import serialization

    from crumb.cli import _load_federation
    from crumb.federation import _JWKSKeys, _PinnedKeys

    pem = Issuer("https://pinned.local").public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    manifest = tmp_path / "fed.json"
    manifest.write_text(_json.dumps({
        "https://pinned.local": pem,
        "https://fetched.local": "https://fetched.local/jwks",
        "https://explicit.local": {"jwks_uri": "https://explicit.local/keys"},
    }))

    fed = _load_federation(str(manifest))
    assert fed.issuers == [
        "https://explicit.local", "https://fetched.local", "https://pinned.local"]
    assert isinstance(fed._sources["https://pinned.local"], _PinnedKeys)
    assert isinstance(fed._sources["https://fetched.local"], _JWKSKeys)
    assert fed._sources["https://explicit.local"].jwks_uri == "https://explicit.local/keys"


def test_pinned_and_fetched_sources_mix_in_one_trust_set():
    host_a = _JWKSHost("https://idp-a.local")   # fetched
    idp_b = Issuer("https://idp-b.local")       # pinned
    alice = _human()

    tok_a = host_a.issuer.exchange(alice.token, "planner", RESOURCE, Federation())
    tok_b = idp_b.exchange(
        tok_a, "researcher", RESOURCE, Federation().trust(host_a.issuer))

    fed = (Federation()
           .trust_discovery(host_a.iss, fetch=host_a.fetch)  # A: live JWKS
           .trust(idp_b))                                    # B: pinned key
    resolved = verify_chain(tok_b, RESOURCE, fed)

    assert resolved["human"] == "alice"
    assert resolved["actor_chain"] == ["researcher", "planner"]
