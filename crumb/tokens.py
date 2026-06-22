"""
Delegation tokens — the bind point (RFC 8693).

When the gateway forwards a tool call it obtains a short-lived token carrying BOTH
identities: the human (`sub`) and the agent acting on their behalf (`act`),
scoped to one resource (`aud`). The composite "agent acting for human alice"
credential.

There are two ways that token comes to exist, and this module supports both:

  - Real (P3b): when `CRUMB_IDP_URL` is set and the gateway has the human's
    session token, it runs a genuine RFC 8693 token exchange against the identity
    provider (`crumb/idp.py`, or any real one — Okta/Keycloak/Zitadel). The result
    is RS256-signed by the provider; the resource verifies it against the
    provider's published JWKS, trusting no shared secret. See `exchange_delegation`.
  - Dev fallback: with no IdP configured, the gateway mints the same-shaped token
    locally with a dev HS256 key. Keeps the deterministic web seed and offline
    demos working with zero infra.

`verify_delegation` branches on the token's `alg`, so the resource (a tool) reads
identity the same way regardless of which path produced the token — RS256 means
"verify against the IdP's public key," HS256 means "the dev path." The point
stands either way: identity is carried in a signed token, never in model output.
"""

from __future__ import annotations

import os
import time
import uuid

import jwt

_DEV_SECRET = "crumb-delegation-dev-key-not-for-production"
_ALGO = "HS256"
_TTL = 60  # short-lived: one token per call

# RFC 8693 token-exchange constants.
_GRANT_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
_TOKEN_TYPE_ACCESS = "urn:ietf:params:oauth:token-type:access_token"

# PyJWKClient is cached per JWKS URL so verification doesn't refetch keys per call.
_jwks_clients: dict = {}


def _idp_url() -> str | None:
    url = os.environ.get("CRUMB_IDP_URL")
    return url.rstrip("/") if url else None


def exchange_delegation(session_token: str, agent_id: str, resource: str,
                        idp_url: str | None = None, ttl: int = _TTL) -> str:
    """Run a real RFC 8693 token exchange: hand the IdP the human's session
    (`subject_token`) plus the agent, get back a provider-signed composite token
    scoped to `resource`. This is the production path — the chokepoint no longer
    signs its own authority; the IdP does, and the resource verifies its key.

    Pointing at Okta/Keycloak/Zitadel instead is just a different `idp_url`."""
    import httpx

    base = idp_url or _idp_url()
    if not base:
        raise RuntimeError("no IdP configured (set CRUMB_IDP_URL)")
    resp = httpx.post(
        f"{base}/token",
        data={
            "grant_type": _GRANT_TOKEN_EXCHANGE,
            "subject_token": session_token,
            "subject_token_type": _TOKEN_TYPE_ACCESS,
            "audience": resource,
            "scope": agent_id,
        },
        timeout=10.0,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def mint_delegation(human_sub: str, agent_id: str, resource: str, ttl: int = _TTL,
                    *, session_token: str | None = None) -> str:
    """Obtain a composite (human + agent) token scoped to one resource.

    With an IdP configured AND the human's session token in hand, this is a real
    token exchange (RS256, provider-signed). Otherwise it falls back to the dev
    HS256 mint — same claims, same shape, no infra. The caller (the gateway)
    doesn't branch; it passes `session_token` and lets the path resolve here."""
    if session_token is not None and _idp_url():
        return exchange_delegation(session_token, agent_id, resource, ttl=ttl)

    now = int(time.time())
    claims = {
        "sub": human_sub,          # the human — RFC 8693 subject
        "act": {"sub": agent_id},  # the agent acting on their behalf
        "aud": resource,           # scoped to one resource — RFC 8707 spirit
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": now + ttl,
    }
    return jwt.encode(claims, _DEV_SECRET, algorithm=_ALGO)


def mint_service_account(service_id: str, resource: str, ttl: int = _TTL) -> str:
    """Mint the token MOST MCP deployments actually send: a shared service
    account, scoped to the resource, carrying NO `act` — so no human rides it.

    This is the "wrong way" Crumb exists to expose. The resource server can prove
    *a bot* called it, never *which person* was behind the bot. Same wire as a
    delegation token; the missing `act` claim is the whole difference.
    """
    now = int(time.time())
    claims = {
        "sub": service_id,   # the bot itself — there is no human in this token
        "aud": resource,
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": now + ttl,
    }
    return jwt.encode(claims, _DEV_SECRET, algorithm=_ALGO)


def _rs256_public_key(token: str):
    """The public key to verify a provider-signed token against. When an IdP URL
    is set, fetch it from the live JWKS over HTTP (cached) — the real, no-shared-
    secret path. With no URL set (in-process tests/demo), read the local provider
    module's public key directly. Either way the key is the provider's, never a
    secret the resource and minter share."""
    url = _idp_url()
    if url:
        jwks_uri = f"{url}/jwks"
        client = _jwks_clients.get(jwks_uri)
        if client is None:
            client = jwt.PyJWKClient(jwks_uri)
            _jwks_clients[jwks_uri] = client
        return client.get_signing_key_from_jwt(token).key

    from .idp import _PRIVATE_KEY  # local provider; in-process verification

    return _PRIVATE_KEY.public_key()


def verify_delegation(token: str, resource: str) -> dict:
    """Verify a token for a given resource; return its claims. Transport- and
    path-agnostic: it reads the token's `alg` and verifies accordingly.

      - RS256 -> a provider-issued token; verify against the IdP's public key
        (JWKS). No shared secret — the resource trusts the provider, not the minter.
      - HS256 -> the dev path; verify with the local dev key.

    Works for both delegation tokens (with `act`) and service-account tokens
    (without), under either signing path."""
    alg = jwt.get_unverified_header(token).get("alg")
    if alg == "RS256":
        return jwt.decode(
            token,
            _rs256_public_key(token),
            algorithms=["RS256"],
            audience=resource,
        )
    return jwt.decode(token, _DEV_SECRET, algorithms=[_ALGO], audience=resource)
