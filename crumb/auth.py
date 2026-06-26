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

import os
import secrets
import sys
import time
from dataclasses import dataclass

import jwt

# Signing secret. In prod the IdP holds the keys; we'd verify its tokens, not
# mint our own (see SPEC §9). For the demo, take it from CRUMB_SESSION_SECRET; if
# unset, generate an ephemeral per-process secret so the public repo ships NO
# usable signing key — tokens just don't survive a restart, fine for a demo. A
# deployment that needs stable sessions sets the env var.
_DEV_SECRET = os.environ.get("CRUMB_SESSION_SECRET")
if not _DEV_SECRET:
    _DEV_SECRET = secrets.token_hex(32)
    print(
        "crumb.auth: CRUMB_SESSION_SECRET unset — using an ephemeral per-process "
        "secret (tokens won't survive restart). Set it for stable sessions.",
        file=sys.stderr,
    )
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
