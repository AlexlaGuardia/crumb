"""
An issuer signs with the algorithm IT chose, not the one we expected.

Crumb minted RS256 and, for a long time, verified only RS256 — reasonable while
every issuer in the system was its own. It stops being reasonable the moment a
real authorization server shows up: AuthPlane signs ES256 off an EC P-256 key
and publishes it in its JWKS, so an RSA-only reader cannot verify a single valid
token it issues. Not a subtle mismatch, a total one, and no test caught it
because every test issuer was ours.

These pin the EC path so it can't regress: an EC JWKS entry becomes a usable
key, an ES256 token verifies, and the refusals that make the trust set
meaningful still refuse.
"""

from __future__ import annotations

import json

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm

from crumb.federation import Federation, UnknownSigningKey, UntrustedIssuer, _jwk_to_key

ISS = "https://as.example.test"
RESOURCE = "https://mcp.example.test/mcp"
KID = "ec-test-key-1"


@pytest.fixture
def ec_issuer():
    """An issuer shaped like a real AS: EC P-256, ES256, kid-tagged JWKS."""
    private = ec.generate_private_key(ec.SECP256R1())
    jwk = json.loads(ECAlgorithm.to_jwk(private.public_key()))
    jwk.update({"kid": KID, "alg": "ES256", "use": "sig"})
    return private, {"keys": [jwk]}


def _federation(jwks: dict) -> Federation:
    return Federation().trust_jwks_uri(ISS, f"{ISS}/.well-known/jwks.json",
                                       fetch=lambda url: jwks)


def test_an_ec_jwks_entry_becomes_a_usable_key(ec_issuer):
    _, jwks = ec_issuer
    assert _jwk_to_key(jwks["keys"][0]) is not None


def test_an_es256_token_verifies_against_a_live_jwks(ec_issuer):
    private, jwks = ec_issuer
    token = jwt.encode({"iss": ISS, "sub": "alice", "aud": RESOURCE,
                        "act": {"sub": "planner"}},
                       private, algorithm="ES256", headers={"kid": KID})

    key = _federation(jwks).key_for(ISS, KID)
    claims = jwt.decode(token, key, algorithms=["RS256", "ES256"],
                        audience=RESOURCE, issuer=ISS)

    assert claims["sub"] == "alice"
    assert claims["act"]["sub"] == "planner"


def test_an_unsupported_key_type_is_still_refused():
    """Widening to EC must not turn the key reader into an accept-anything.
    A type we don't understand stays a refusal, never a silent skip that would
    quietly shrink the trusted key set."""
    with pytest.raises(UnknownSigningKey):
        _jwk_to_key({"kty": "OKP", "crv": "Ed25519", "x": "irrelevant"})


def test_fail_closed_still_holds_for_ec_issuers(ec_issuer):
    _, jwks = ec_issuer
    fed = _federation(jwks)

    with pytest.raises(UnknownSigningKey):
        fed.key_for(ISS, "a-kid-this-issuer-never-published")
    with pytest.raises(UntrustedIssuer):
        fed.key_for("https://evil.example.test", KID)
