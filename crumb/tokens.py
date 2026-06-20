"""
Delegation tokens — the bind point (RFC 8693 shape).

When the gateway forwards a tool call it mints a short-lived token carrying BOTH
identities: the human (`sub`) and the agent acting on their behalf (`act`),
scoped to one resource (`aud`). This is the shape of an RFC 8693 token-exchange
result — the composite "agent acting for human alice" credential.

In production an identity provider's token-exchange endpoint mints this. Here the
gateway mints it with a dev key; the resource (the tool) verifies it. The point
stands either way: identity is carried in a signed token, never in model output.
"""

from __future__ import annotations

import time
import uuid

import jwt

_DEV_SECRET = "crumb-delegation-dev-key-not-for-production"
_ALGO = "HS256"
_TTL = 60  # short-lived: one token per call


def mint_delegation(human_sub: str, agent_id: str, resource: str, ttl: int = _TTL) -> str:
    """Mint a composite (human + agent) token scoped to one resource."""
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


def verify_delegation(token: str, resource: str) -> dict:
    """Verify a delegation token for a given resource; return its claims."""
    return jwt.decode(token, _DEV_SECRET, algorithms=[_ALGO], audience=resource)
