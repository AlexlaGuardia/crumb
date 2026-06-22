"""
The identity provider — a real RFC 8693 token-exchange authorization server.

Through P3 the gateway minted the delegation token itself, with a shared dev key.
That proved the *shape* of an RFC 8693 result (`sub` + `act`, scoped) but not the
handshake: a real deployment doesn't let the chokepoint sign its own authority.
An identity provider does, and the resource trusts it because it verifies the
provider's public key — never a shared secret.

This is that provider, self-contained and standards-correct:

  POST /token   grant_type=urn:ietf:params:oauth:grant-type:token-exchange
                subject_token = the human's session, actor_token info = the agent
                -> a short-lived RS256 JWT carrying (human + act), scoped to aud
  GET  /jwks    the public keys the resource verifies against — no shared secret
  GET  /.well-known/openid-configuration   issuer metadata, so it reads like one

Crumb stays IdP-agnostic: this implements the same exchange and JWKS verification
Okta/Keycloak/Zitadel expose, so pointing the gateway at one of them is a URL
change, not a code change (see `tokens.exchange_delegation`). The honest claim is
"real RFC 8693 over HTTP, asymmetric-signed, JWKS-verified" — not "real Keycloak."

Run: uvicorn crumb.idp:app  (PM2 service `crumb-idp`, 127.0.0.1:8731)
"""

from __future__ import annotations

import time
import uuid
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import JSONResponse

from . import auth

ISSUER = "https://crumb-idp.local"
_ALGO = "RS256"
_KID = "crumb-idp-rs256-1"
_TTL = 60  # short-lived: one exchanged token per call
_KEY_PATH = Path(__file__).resolve().parent.parent / "data" / "idp_rsa.key"

# RFC 8693 token-type URIs.
_GRANT_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
_TOKEN_TYPE_ACCESS = "urn:ietf:params:oauth:token-type:access_token"
_TOKEN_TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt"


def _load_or_create_key() -> rsa.RSAPrivateKey:
    """The provider's signing key. Persisted under data/ (gitignored) so the JWKS
    is stable across restarts — a resource that cached the public key keeps
    verifying. Generated on first boot; never committed."""
    if _KEY_PATH.exists():
        return serialization.load_pem_private_key(_KEY_PATH.read_bytes(), password=None)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    _KEY_PATH.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return key


_PRIVATE_KEY = _load_or_create_key()
_PUBLIC_PEM = _PRIVATE_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)


def public_jwks() -> dict:
    """The provider's public keys, JWKS format — what a resource fetches to verify
    a token without trusting the operator who issued it."""
    from jwt.algorithms import RSAAlgorithm
    import json

    jwk = json.loads(RSAAlgorithm.to_jwk(_PRIVATE_KEY.public_key()))
    jwk.update({"kid": _KID, "use": "sig", "alg": _ALGO})
    return {"keys": [jwk]}


def _mint(claims: dict) -> str:
    return jwt.encode(claims, _PRIVATE_KEY, algorithm=_ALGO, headers={"kid": _KID})


app = FastAPI(title="Crumb IdP", description="RFC 8693 token-exchange authorization server")


@app.get("/jwks")
def jwks() -> dict:
    return public_jwks()


@app.get("/.well-known/openid-configuration")
def discovery() -> dict:
    """Minimal issuer metadata, so the provider is discoverable the way a real one
    is — token endpoint, JWKS, and the exchange grant it advertises support for."""
    return {
        "issuer": ISSUER,
        "token_endpoint": f"{ISSUER}/token",
        "jwks_uri": f"{ISSUER}/jwks",
        "grant_types_supported": [_GRANT_TOKEN_EXCHANGE],
        "token_endpoint_auth_methods_supported": ["none"],
        "id_token_signing_alg_values_supported": [_ALGO],
    }


@app.post("/token")
def token(
    grant_type: str = Form(...),
    subject_token: str = Form(...),
    subject_token_type: str = Form(_TOKEN_TYPE_ACCESS),
    audience: str = Form(...),
    actor_token: str | None = Form(None),
    actor_token_type: str | None = Form(None),
    requested_token_type: str | None = Form(None),
    scope: str | None = Form(None),
):
    """RFC 8693 token exchange.

    The human's session rides in as `subject_token` — the provider validates it
    (this is where, in prod, it would be the IdP's own session) and reads the
    verified `sub`. The agent acting on the human's behalf rides in as
    `actor_token` (or, lacking one, the scope-derived agent id). The provider
    mints a composite, RS256-signed, short-lived token: the human in `sub`, the
    agent in `act.sub`, scoped to `audience`. Identity is asserted by the provider
    and verifiable by anyone holding its public key — the property the dev-key
    mint could only imitate.
    """
    if grant_type != _GRANT_TOKEN_EXCHANGE:
        raise HTTPException(400, detail="unsupported_grant_type")

    # Validate the subject — the human's session. Invalid/expired => no exchange.
    try:
        subject_claims = auth.verify_session(subject_token)
    except jwt.PyJWTError as exc:
        raise HTTPException(400, detail=f"invalid_subject_token: {type(exc).__name__}")

    human = subject_claims["sub"]

    # The actor (agent). Prefer an explicit actor_token; fall back to the scope.
    agent_id = None
    if actor_token:
        try:
            agent_id = auth.verify_session(actor_token).get("sub")
        except jwt.PyJWTError:
            agent_id = None
    if not agent_id:
        agent_id = (scope or "agent").strip()

    now = int(time.time())
    access = _mint(
        {
            "iss": ISSUER,
            "sub": human,                 # the human — RFC 8693 subject
            "act": {"sub": agent_id},     # the agent acting on their behalf
            "aud": audience,              # scoped to one resource — RFC 8707 spirit
            "jti": uuid.uuid4().hex,
            "iat": now,
            "exp": now + _TTL,
        }
    )

    # RFC 8693 §2.2.1 token-exchange response.
    return JSONResponse(
        {
            "access_token": access,
            "issued_token_type": requested_token_type or _TOKEN_TYPE_ACCESS,
            "token_type": "N_A",
            "expires_in": _TTL,
        }
    )
