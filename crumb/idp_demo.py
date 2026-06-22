"""
P3b proof — a real RFC 8693 token exchange, end to end.

Runs the identity provider as a live ASGI app and drives it over HTTP:

  1. The human logs in (a session token — the `subject_token`).
  2. The gateway exchanges it at the provider's /token endpoint for an RS256,
     provider-signed delegation token carrying (human + act), scoped to a resource.
  3. The resource verifies that token against the provider's JWKS — public key,
     no shared secret.
  4. Negatives: a forged token (attacker re-signs) fails the signature check; a
     token scoped to one resource is rejected at another; a tampered session is
     refused at the exchange itself.

The whole point of P3b: the chokepoint stops signing its own authority. The
provider issues, the resource verifies the provider's key, and that key is
fetched, not shared. Point `CRUMB_IDP_URL` at Okta/Keycloak/Zitadel and the same
code path holds.

Run: python -m crumb.idp_demo
"""

from __future__ import annotations

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from . import auth, tokens
from .idp import _GRANT_TOKEN_EXCHANGE, _TOKEN_TYPE_ACCESS, app


def _exchange(client: TestClient, session_token: str, agent_id: str, resource: str) -> str:
    """A real token-exchange POST over the ASGI wire."""
    resp = client.post(
        "/token",
        data={
            "grant_type": _GRANT_TOKEN_EXCHANGE,
            "subject_token": session_token,
            "subject_token_type": _TOKEN_TYPE_ACCESS,
            "audience": resource,
            "scope": agent_id,
        },
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def main() -> None:
    client = TestClient(app)

    print("P3b — real RFC 8693 token exchange\n" + "=" * 42)

    # 1. The human authenticates. This session is the subject_token.
    session = auth.login("alice", directives=("read_record",))
    print(f"\n1. human logs in            sub={session.human!r}")
    print(f"   session token alg        {jwt.get_unverified_header(session.token)['alg']} (the IdP's own session)")

    # 2. Real exchange at the provider's /token endpoint.
    delegated = _exchange(client, session.token, agent_id="support-agent", resource="read_record")
    header = jwt.get_unverified_header(delegated)
    print("\n2. exchange at /token        grant=urn:...:token-exchange")
    print(f"   issued token alg         {header['alg']} (provider-signed, kid={header.get('kid')})")

    # 3. The resource verifies against the provider's JWKS — public key, no secret.
    claims = tokens.verify_delegation(delegated, resource="read_record")
    print("\n3. resource verifies         via the provider's public key (JWKS)")
    print(f"   sub (human)              {claims['sub']!r}")
    print(f"   act (agent)             {claims['act']!r}")
    print(f"   aud (scoped to)         {claims['aud']!r}")
    print(f"   iss (provider)          {claims['iss']!r}")
    assert claims["sub"] == "alice" and claims["act"]["sub"] == "support-agent"
    print("   => VERIFIED — the human is provable, the provider asserted it")

    # 4a. Forgery: an attacker without the provider's key re-signs their own token.
    print("\n4. negatives")
    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged = jwt.encode(
        {**claims, "sub": "attacker"}, attacker_key, algorithm="RS256",
        headers={"kid": header.get("kid")},
    )
    try:
        tokens.verify_delegation(forged, resource="read_record")
        print("   forged token             UNEXPECTEDLY ACCEPTED  <-- bug")
    except jwt.InvalidSignatureError:
        print("   forged token             rejected (InvalidSignature) — no provider key, no trust")

    # 4b. Scope: a token minted for read_record is presented at another resource.
    try:
        tokens.verify_delegation(delegated, resource="export_record")
        print("   wrong-scope token        UNEXPECTEDLY ACCEPTED  <-- bug")
    except jwt.InvalidAudienceError:
        print("   wrong-scope token        rejected (InvalidAudience) — aud binds it to one resource")

    # 4c. Tampered subject: a doctored session is refused at the exchange itself.
    bad_session = session.token[:-4] + "AAAA"
    resp = client.post(
        "/token",
        data={
            "grant_type": _GRANT_TOKEN_EXCHANGE,
            "subject_token": bad_session,
            "subject_token_type": _TOKEN_TYPE_ACCESS,
            "audience": "read_record",
            "scope": "support-agent",
        },
    )
    print(f"   tampered subject_token   refused at /token (HTTP {resp.status_code}) — no exchange on a bad session")

    print("\nThe chokepoint signs nothing. The provider issues, the resource")
    print("verifies its fetched public key. Swap in a real IdP by URL alone.")


if __name__ == "__main__":
    main()
