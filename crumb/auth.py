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

    Each directive is a normalized `{"action": str, "args": dict}`: the tool name,
    plus an optional argument scope. An empty `args` is verb-level (any arguments
    to that tool are authorized). A non-empty `args` binds the directive to a
    resource — `read_record` scoped to `{"record_id": 42}` authorizes reading
    record 42 and nothing else. The scope is what lets reconciliation tell apart
    two calls to the SAME tool: the one the human named, and a same-verb call a
    hijack slipped in against a different resource.
    """

    sub: str
    token: str
    directives: tuple[dict, ...] = ()

    @property
    def human(self) -> str:
        return self.sub


def normalize_directive(d) -> dict:
    """Coerce a directive into canonical `{"action": str, "args": dict}` form.

    Accepts three shapes so every existing caller keeps working:
      - `"read_record"`                      → verb-level (args = {})
      - `("read_record", {"record_id": 42})` → scoped to that resource
      - `{"action": ..., "args": {...}}`     → already canonical
    """
    if isinstance(d, str):
        return {"action": d, "args": {}}
    if isinstance(d, (tuple, list)):
        action = d[0]
        args = d[1] if len(d) > 1 and d[1] else {}
        return {"action": action, "args": dict(args)}
    if isinstance(d, dict) and "action" in d:
        return {"action": d["action"], "args": dict(d.get("args") or {})}
    raise TypeError(f"unrecognized directive: {d!r}")


def authorizes(directives, name: str, arguments: dict | None = None) -> tuple[bool, str | None]:
    """Reconcile a tool call against the human's directives.

    A call is authorized iff some directive matches the tool `name` AND every
    argument the directive constrains equals the call's argument. A verb-level
    directive (empty `args`) constrains nothing, so it authorizes any call to that
    tool — the original behavior. A scoped directive additionally requires the
    named resource to match, which is what stops a same-verb hijack (an authorized
    `read_record(42)` does not authorize `read_record(43)`).

    Returns `(True, name)` when authorized so the caller can point the crumb at the
    authorizing directive, or `(False, None)` when nothing authorized it — the
    absence that flags a call as unauthorized and pins it on the agent.
    """
    args = arguments or {}
    for d in directives:
        nd = d if (isinstance(d, dict) and "action" in d) else normalize_directive(d)
        if nd["action"] != name:
            continue
        if all(args.get(k) == v for k, v in nd["args"].items()):
            return True, name
    return False, None


def login(user_id: str, directives: tuple = ()) -> Session:
    """Stand-in for an OIDC login. Returns a session bound to the human's id and
    the set of actions they authorized this session. Each directive is a tool name,
    optionally scoped to specific arguments (see `normalize_directive`). The model
    cannot widen this set — it's signed into the session token at login."""
    now = int(time.time())
    normalized = [normalize_directive(d) for d in directives]
    claims = {
        "sub": user_id,
        "directives": normalized,
        "iat": now,
        "exp": now + _SESSION_TTL,
    }
    token = jwt.encode(claims, _DEV_SECRET, algorithm=_ALGO)
    return Session(sub=user_id, token=token, directives=tuple(normalized))


def verify_session(token: str) -> dict:
    """Verify a session token and return its claims. Raises on tamper/expiry."""
    return jwt.decode(token, _DEV_SECRET, algorithms=[_ALGO])
