"""
Trustless key distribution — the JWKS-fetch leg, over real HTTP.

`cross_issuer_demo` proves the chain verifies when the verifier holds each
issuer's key in-process. That's the shape, not the steady state: real verifiers
don't ship PEMs around, they fetch each issuer's CURRENT keys from its JWKS
endpoint and follow rotation. This demo makes that real. Two identity providers
come up on actual TCP ports, each serving `/.well-known/openid-configuration` and
`/jwks` — the same endpoints Okta/Keycloak expose. The verifier pins NOTHING: it
names the two issuers, discovers their JWKS URIs, and fetches their keys live.

  1. alice@A -> planner@A -> researcher@B -> read_record, B staples A's segment.
  2. A verifier that fetched both issuers' JWKS over HTTP verifies the whole chain
     back to alice — each segment against the key it just pulled from that issuer.
  3. A rotates its signing key (new kid), the way a real IdP does. A verifier that
     had PINNED A's old PEM would now break. The fetching verifier sees an unknown
     kid, refetches A's JWKS exactly once, and keeps verifying.
  4. An issuer the verifier never named is refused — the fetch endpoint doesn't
     buy trust; the verifier's own list does.

The trust boundary: keys come from the ISSUER's endpoint (here plain HTTP on
localhost; HTTPS/TLS authenticates it in prod), never from whoever holds the log.

Run: python -m crumb.jwks_federation_demo
"""

from __future__ import annotations

import threading
import time

import httpx
import jwt
import uvicorn
from fastapi import FastAPI

from . import auth
from .federation import (
    Federation,
    Issuer,
    RevokedSigningKey,
    UnknownSigningKey,
    UntrustedIssuer,
    verify_chain,
)

RESOURCE = "read_record"


class _LiveIdP:
    """An issuer served on a real port. Its current signing key sits behind the
    JWKS route so a rotation is reflected on the next fetch — exactly the moving
    target a pinned PEM can't track."""

    def __init__(self, iss: str, port: int):
        self.iss = iss
        self.port = port
        self.base = f"http://127.0.0.1:{port}"
        self._gen = 1
        self.issuer = Issuer(iss, kid=f"{iss}-rs256-{self._gen}")
        self.app = self._build_app()

    def _build_app(self) -> FastAPI:
        app = FastAPI()

        @app.get("/.well-known/openid-configuration")
        def discovery() -> dict:
            return {"issuer": self.iss, "jwks_uri": f"{self.base}/jwks"}

        @app.get("/jwks")
        def jwks() -> dict:
            return self.issuer.jwks()   # reads the CURRENT key — rotation-aware

        return app

    def serve(self) -> uvicorn.Server:
        server = uvicorn.Server(
            uvicorn.Config(self.app, host="127.0.0.1", port=self.port, log_level="error"))
        threading.Thread(target=server.run, daemon=True).start()
        return server

    def rotate(self) -> None:
        self._gen += 1
        self.issuer = Issuer(self.iss, kid=f"{self.iss}-rs256-{self._gen}")


def _wait_ready(idp: _LiveIdP, tries: int = 50) -> None:
    for _ in range(tries):
        try:
            httpx.get(f"{idp.base}/.well-known/openid-configuration", timeout=1).raise_for_status()
            return
        except Exception:
            time.sleep(0.05)
    raise RuntimeError(f"{idp.iss} never came up on {idp.base}")


def main() -> None:
    print("JWKS-fetch federation — trustless keys over real HTTP\n" + "=" * 52)

    idp_a = _LiveIdP("https://idp-a.local", 8741)
    idp_b = _LiveIdP("https://idp-b.local", 8742)
    srv_a, srv_b = idp_a.serve(), idp_b.serve()
    try:
        _wait_ready(idp_a)
        _wait_ready(idp_b)

        # The chain, minted the same way as the in-process demo.
        alice = auth.login("alice", directives=(RESOURCE,))
        tok_a = idp_a.issuer.exchange(alice.token, "planner", RESOURCE, Federation())
        tok_b = idp_b.issuer.exchange(
            tok_a, "researcher", RESOURCE, Federation().trust(idp_a.issuer))
        print("\n1. alice@A -> planner@A -> researcher@B -> read_record")
        print(f"   outer kid  {jwt.get_unverified_header(tok_b).get('kid')!r}")

        # The verifier pins nothing. It names two issuers and discovers their keys
        # over HTTP — real GETs to the well-known + JWKS endpoints above.
        # The trusted identity is the logical `iss`; discovery is pointed at the
        # real port it's served on (in prod the two coincide — `iss` IS the URL).
        verifier = (Federation()
                    .trust_discovery(idp_a.iss, discovery_url=f"{idp_a.base}/.well-known/openid-configuration")
                    .trust_discovery(idp_b.iss, discovery_url=f"{idp_b.base}/.well-known/openid-configuration"))
        resolved = verify_chain(tok_b, RESOURCE, verifier)
        print("\n2. verify with keys fetched live (no PEM pinned)")
        print(f"   human        {resolved['human']!r}")
        print(f"   actor_chain  {resolved['actor_chain']!r}")
        print(f"   issuer_path  {resolved['issuer_path']!r}")
        assert resolved["human"] == "alice"
        print("   => VERIFIED — keys came from each issuer's own endpoint")

        # A rotates. A pinned-PEM verifier would now fail closed; this one refetches.
        print("\n3. A rotates its signing key (new kid)")
        idp_a.rotate()
        tok_a2 = idp_a.issuer.exchange(
            auth.login("alice", directives=(RESOURCE,)).token, "planner", RESOURCE, Federation())
        tok_b2 = idp_b.issuer.exchange(
            tok_a2, "researcher", RESOURCE, Federation().trust(idp_a.issuer))
        print(f"   new A kid    {jwt.get_unverified_header(tok_a2).get('kid')!r}")
        resolved2 = verify_chain(tok_b2, RESOURCE, verifier)
        assert resolved2["human"] == "alice"
        print("   => STILL VERIFIED — unknown kid triggered one refetch of A's JWKS")

        # An issuer the verifier never named. It has a live JWKS too; that isn't
        # what earns trust.
        print("\n4. upstream from an issuer the verifier never named")
        idp_c = _LiveIdP("https://idp-c.rogue", 8743)
        srv_c = idp_c.serve()
        try:
            _wait_ready(idp_c)
            tok_c = idp_c.issuer.exchange(alice.token, "planner", RESOURCE, Federation())
            tok_bc = idp_b.issuer.exchange(
                tok_c, "researcher", RESOURCE, Federation().trust(idp_c.issuer))
            try:
                verify_chain(tok_bc, RESOURCE, verifier)
                print("   unfederated issuer  UNEXPECTEDLY ACCEPTED  <-- bug")
            except UntrustedIssuer:
                print("   unfederated issuer  rejected (UntrustedIssuer) — endpoint != trust")
        finally:
            srv_c.should_exit = True

        # Rotation picks up a key that APPEARS. Revocation is the opposite: a key
        # that DISAPPEARS must stop verifying. A short-TTL verifier reconfirms A's
        # JWKS once the cache lapses, so a revoked key drops out.
        print("\n5. A revokes a signing key (short-TTL verifier)")
        v_short = Federation().trust_discovery(
            idp_a.iss, ttl=1.0,
            discovery_url=f"{idp_a.base}/.well-known/openid-configuration")
        tok_rev = idp_a.issuer.exchange(
            auth.login("alice", directives=(RESOURCE,)).token, "planner", RESOURCE, Federation())
        assert verify_chain(tok_rev, RESOURCE, v_short)["human"] == "alice"
        idp_a.rotate()  # the kid tok_rev was signed with is now gone from A's JWKS
        # Inside the TTL the cached key still verifies — the bounded staleness window.
        assert verify_chain(tok_rev, RESOURCE, v_short)["human"] == "alice"
        print("   inside TTL   still verifies (cached) — revocation not yet propagated")
        time.sleep(1.2)  # let the TTL lapse
        try:
            verify_chain(tok_rev, RESOURCE, v_short)
            print("   after TTL    UNEXPECTEDLY ACCEPTED  <-- bug")
        except UnknownSigningKey:
            print("   after TTL    rejected (UnknownSigningKey) — reconfirmed, key is gone")

        # The TTL is the backstop — eventual, bounded by how long you're willing to
        # honor a stale cache. When you already KNOW a key is compromised, waiting a
        # window is a window too long. Push-invalidation refuses it now, on a normal
        # verifier, no short TTL required.
        print("\n6. A operator push-invalidates a compromised key (instant, normal TTL)")
        tok_now = idp_b.issuer.exchange(
            idp_a.issuer.exchange(
                auth.login("alice", directives=(RESOURCE,)).token, "planner", RESOURCE, Federation()),
            "researcher", RESOURCE, Federation().trust(idp_a.issuer))
        assert verify_chain(tok_now, RESOURCE, verifier)["human"] == "alice"
        print("   before       verifies — key is live and current")
        verifier.revoke(idp_a.iss, idp_a.issuer.kid)   # the instant path
        try:
            verify_chain(tok_now, RESOURCE, verifier)
            print("   after revoke UNEXPECTEDLY ACCEPTED  <-- bug")
        except RevokedSigningKey:
            print("   after revoke rejected (RevokedSigningKey) — now, not in a TTL window")
        # Subtract-only: revoking A's key cannot make a DIFFERENT issuer's token
        # verify. A revocation only ever removes trust.
        tok_b_only = idp_b.issuer.exchange(
            auth.login("bob", directives=(RESOURCE,)).token, "planner", RESOURCE, Federation())
        assert verify_chain(tok_b_only, RESOURCE, verifier)["human"] == "bob"
        print("   B's own key  still verifies — revocation subtracts, never adds")

        print("\nThe verifier fetched every key from the issuer that owns it, followed a")
        print("rotation with no redeploy, dropped a revoked key within its TTL, killed a")
        print("known-compromised key instantly, and still trusted only the issuers it named.")
        print("Pinning was never required; trusting the log-holder never happened.")
    finally:
        srv_a.should_exit = True
        srv_b.should_exit = True


if __name__ == "__main__":
    main()
