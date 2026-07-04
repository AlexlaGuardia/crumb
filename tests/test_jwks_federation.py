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

import contextlib
import json
import threading

import jwt
import pytest

from crumb import auth
from crumb.federation import (
    Federation,
    IssuerUnreachable,
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


def test_revoked_key_is_trusted_within_ttl_then_dropped():
    """A key the issuer removes from its JWKS keeps verifying from cache until the
    TTL lapses (the bounded, honest staleness window), then stops once the cache is
    reconfirmed against the live JWKS and the key is gone. Deterministic via an
    injected clock; the fetch count proves the cache isn't re-hit prematurely."""
    host = _JWKSHost("https://idp-a.local")
    now = [0.0]
    fed = Federation().trust_jwks_uri(
        host.iss, host.jwks_url, fetch=host.fetch, ttl=10, clock=lambda: now[0])

    token = host.issuer.exchange(_human().token, "planner", RESOURCE, Federation())
    assert verify_chain(token, RESOURCE, fed)["human"] == "alice"
    assert host.hits["jwks"] == 1

    # The issuer rotates its key, which REVOKES the old kid from the served JWKS.
    host.rotate()

    # Still inside the TTL: the old key sits in cache and keeps verifying. No
    # refetch yet, so revocation hasn't propagated. This window is the honest cost.
    now[0] = 9.0
    assert verify_chain(token, RESOURCE, fed)["human"] == "alice"
    assert host.hits["jwks"] == 1  # served from cache, not reconfirmed

    # Past the TTL: the cache is reconfirmed, the revoked kid is gone, and a token
    # signed by it no longer verifies.
    now[0] = 11.0
    with pytest.raises(UnknownSigningKey):
        verify_chain(token, RESOURCE, fed)
    assert host.hits["jwks"] == 2  # exactly one reconfirm fetch


def test_stale_cache_fails_closed_when_issuer_unreachable():
    """When the TTL lapses and the reconfirm fetch fails, the source refuses rather
    than serve the stale cache — fail-closed, so a stalled JWKS endpoint can't keep
    a revoked key alive."""
    host = _JWKSHost("https://idp-a.local")
    now = [0.0]
    down = {"flag": False}

    def flaky_fetch(url):
        if down["flag"]:
            raise ConnectionError("issuer JWKS unreachable")
        return host.fetch(url)

    fed = Federation().trust_jwks_uri(
        host.iss, host.jwks_url, fetch=flaky_fetch, ttl=10, clock=lambda: now[0])

    token = host.issuer.exchange(_human().token, "planner", RESOURCE, Federation())
    assert verify_chain(token, RESOURCE, fed)["human"] == "alice"

    # Issuer goes dark, TTL lapses: the reconfirm can't run, so we refuse to keep
    # vouching for the cached key rather than serve it unconfirmed.
    down["flag"] = True
    now[0] = 11.0
    with pytest.raises(IssuerUnreachable):
        verify_chain(token, RESOURCE, fed)


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


@contextlib.contextmanager
def _served_issuer(kid_gen: int = 1):
    """Serve one issuer's discovery + JWKS over a REAL loopback socket, with `iss`
    set to the port it actually listens on so the default discovery path derives
    cleanly. Every test above injects `fetch`; this one drives the shipped
    `_http_get_json` (httpx) end to end so the real network round-trip — the one
    line the injected tests can't reach — is guarded in CI, not just runnable by
    hand in `jwks_federation_demo`."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    box = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            iss = box["iss"]
            if self.path == "/.well-known/openid-configuration":
                body = {"issuer": iss, "jwks_uri": f"{iss}/jwks"}
            elif self.path == "/jwks":
                body = box["issuer"].jwks()
            else:
                self.send_error(404)
                return
            payload = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_):  # keep the test output quiet
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    iss = f"http://127.0.0.1:{srv.server_address[1]}"
    box["iss"] = iss
    box["issuer"] = Issuer(iss, kid=f"{iss}-rs256-{kid_gen}")
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield box["issuer"], iss
    finally:
        srv.shutdown()
        thread.join(timeout=5)


def test_real_socket_round_trip_via_default_httpx_fetch():
    """The one path every other test stubs: keys fetched over an actual TCP socket
    through the default httpx-backed `_http_get_json`, with nothing injected. Proves
    the shipped fetch code — discovery read, jwks_uri followed, kid selected —
    actually works against a live endpoint, backing the public writeups' claim with
    a network round-trip the CI gate holds."""
    with _served_issuer() as (issuer, iss):
        token = issuer.exchange(_human().token, "planner", RESOURCE, Federation())

        # No fetch= override: this exercises _http_get_json / httpx for real.
        fed = Federation().trust_discovery(iss)
        resolved = verify_chain(token, RESOURCE, fed)

    assert resolved["human"] == "alice"
    assert resolved["actor_chain"] == ["planner"]
    assert resolved["issuer_path"] == [iss]
