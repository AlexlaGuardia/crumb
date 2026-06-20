"""
Session auth — the capture point.

In production this is a real OIDC login against an identity provider (Okta,
Auth0, Keycloak), and we'd hold the user's verified `sub` claim. For P0 we stub
the IdP: `login()` stands in for "the human authenticated" and hands back a
signed session token carrying their identity.

The one thing that matters: the human's identity is captured ONCE, here, at the
start — before the agent runs. Everything downstream derives from this. The
model never gets a say in who the human is.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import jwt

# Dev-only signing secret. In prod the IdP holds the keys; we'd verify its
# tokens, not mint our own. Never ship a hardcoded secret — see SPEC §9.
_DEV_SECRET = "crumb-dev-secret-not-for-production"
_ALGO = "HS256"
_SESSION_TTL = 3600  # seconds


@dataclass
class Session:
    """An authenticated human session. `sub` is the source of truth for 'who';
    `directives` is the source of truth for 'what the human authorized'.

    Both are captured here, at t=0, and ride inside the signed session token — so
    the gateway reads the human's INTENT from verified claims, never from the
    model. An action the human never authorized has no directive to point to, and
    that absence is exactly what exposes a hijacked tool call downstream.
    """

    sub: str
    token: str
    directives: tuple[str, ...] = ()

    @property
    def human(self) -> str:
        return self.sub


def login(user_id: str, directives: tuple[str, ...] = ()) -> Session:
    """Stand-in for an OIDC login. Returns a session bound to the human's id and
    the set of actions they authorized this session (by tool name). The model
    cannot widen this set — it's signed into the session token at login."""
    now = int(time.time())
    claims = {
        "sub": user_id,
        "directives": list(directives),
        "iat": now,
        "exp": now + _SESSION_TTL,
    }
    token = jwt.encode(claims, _DEV_SECRET, algorithm=_ALGO)
    return Session(sub=user_id, token=token, directives=tuple(directives))


def verify_session(token: str) -> dict:
    """Verify a session token and return its claims. Raises on tamper/expiry."""
    return jwt.decode(token, _DEV_SECRET, algorithms=[_ALGO])
