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
import secrets
import sys
import time
import uuid

import jwt

# Delegation signing key. Demo-only: from CRUMB_DELEGATION_SECRET, else an
# ephemeral per-process secret so the public repo ships no usable key. Mint and
# verify happen in one process, so a per-process secret is sufficient.
_ENV_SECRET = os.environ.get("CRUMB_DELEGATION_SECRET")
_EPHEMERAL_SECRET: str | None = None
_WARNED = False


def _secret() -> str:
    """Resolve the delegation signing key, minting an ephemeral one on first use.

    Lazy for the same reason as `crumb.auth._secret`: importing the package must
    stay silent so `crumb --help` doesn't greet a new user with a warning. Fires
    once per process, at the point a token is actually minted or verified.
    """
    global _EPHEMERAL_SECRET, _WARNED
    if _ENV_SECRET:
        return _ENV_SECRET
    if _EPHEMERAL_SECRET is None:
        _EPHEMERAL_SECRET = secrets.token_hex(32)
    if not _WARNED:
        _WARNED = True
        print(
            "crumb.tokens: CRUMB_DELEGATION_SECRET unset — using an ephemeral "
            "per-process secret. Set it for stable cross-process delegation.",
            file=sys.stderr,
        )
    return _EPHEMERAL_SECRET


_ALGO = "HS256"
# Provider-signed algorithms this resource will accept. Which one shows up is the
# authorization server's choice: AuthPlane signs ES256 off a P-256 key, so an
# RS256-only check rejects a valid token from a conformant AS. Both are
# asymmetric and PyJWT pairs each against its matching key type, so this is not
# the HS256-confusion door — the dev symmetric path stays a separate branch that
# a configured IdP refuses outright.
_ASYMMETRIC_ALGOS = ("RS256", "ES256")
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
    return jwt.encode(claims, _secret(), algorithm=_ALGO)


def extend_delegation(prior_token: str, new_agent_id: str, resource: str,
                      ttl: int = _TTL) -> str:
    """Add one hop to an existing delegation chain (RFC 8693 §4.1 nested `act`).

    Multi-hop: a human directs agent A, A delegates to agent B, B calls the tool.
    The human stays the `sub` the whole way down; each new actor nests the prior
    `act` under its own, so the issued token carries the full chain with the most
    recent actor outermost. `actor_chain` walks it back to the agent that first
    acted; `sub` is the human at the root.

    Real path (IdP configured): re-exchange the PRIOR delegation token as the
    `subject_token` and the provider nests its `act` (see crumb/idp.py). Dev path:
    decode the prior token and re-mint with the prior `act` nested under the new
    agent. Either way the chain is signed end to end, so tampering a middle actor
    breaks the signature — there is no per-hop seam to forge at."""
    if _idp_url():
        return exchange_delegation(prior_token, new_agent_id, resource, ttl=ttl)

    prior = jwt.decode(prior_token, _secret(), algorithms=[_ALGO],
                       options={"verify_aud": False})
    act = {"sub": new_agent_id}
    if prior.get("act"):
        act["act"] = prior["act"]          # nest the prior actor chain beneath us
    now = int(time.time())
    claims = {
        "sub": prior["sub"],               # the human stays the subject, every hop
        "act": act,
        "aud": resource,
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": now + ttl,
    }
    return jwt.encode(claims, _secret(), algorithm=_ALGO)


def actor_chain(claims: dict) -> list:
    """The delegation chain carried in a token's nested `act`, most-recent actor
    first, ending with the agent that first acted for the human. The human is the
    root `sub`, not part of this list. Single-hop returns one agent; an empty list
    means a token with no actor at all (a service account — no human rode it)."""
    chain: list = []
    act = claims.get("act")
    while isinstance(act, dict):
        if "sub" in act:
            chain.append(act["sub"])
        act = act.get("act")
    return chain


# An authorization server may stamp FLAT mirrors of the delegation chain beside
# the nested RFC 8693 `act` — AuthPlane does, and says so explicitly: they exist
# so a resource server reading identity on every call doesn't walk the nested
# tree per request. Names confirmed against docs.authplane.ai/sdks/python.
_FLAT_AGENT = "agent_id"
_FLAT_CHAIN = "agent_chain"


def _actor_id(value: object) -> str | None:
    """An actor identifier, or None if it isn't one.

    Whatever lands here is going into a signed, permanent record that a third
    party will read as "this agent made this call". A dict, an int or an empty
    string is not an agent id, and writing one into the ledger would be
    fabricating an actor out of malformed input. Refuse instead.
    """
    return value if isinstance(value, str) and value.strip() else None


def _flat_chain(claims: dict, outermost: str | None) -> tuple[list, str | None]:
    """Read a flat `agent_chain` and normalize it to most-recent-actor-first.

    The flat claim's ORDER is not something we get to assume. Crumb's convention
    is most-recent-first (`actor_chain`); an AS may well emit oldest-first. So we
    orient it against the one actor we already know is authoritative — the token's
    `agent_id` / outermost `act.sub` — rather than guessing: whichever end of the
    chain that actor sits on tells us which way the list runs. A single-element
    chain is orientation-free. If it sits on NEITHER end the two representations
    genuinely disagree, and we say so instead of silently picking one.

    Two cases that look decidable and are not. A chain whose members don't all
    parse as ids is unusable — we won't guess which entry was meant. And when the
    authoritative actor sits at BOTH ends (an agent that delegated onward and was
    handed control back), either reading puts it outermost while the hops between
    run opposite ways; that's audit-only ordering, but a flight recorder says
    "ambiguous" rather than picking the pleasant one.

    Returns (chain-most-recent-first, discrepancy-or-None).
    """
    raw = claims.get(_FLAT_CHAIN)
    if raw is None:
        return [], None
    if not isinstance(raw, list) or not raw:
        return [], f"{_FLAT_CHAIN} is not a non-empty list: {raw!r}"
    chain = [_actor_id(v) for v in raw]
    if any(c is None for c in chain):
        return [], f"{_FLAT_CHAIN} contains entries that are not actor ids: {raw!r}"
    if outermost is None or len(chain) == 1:
        return chain, None
    head, tail = chain[0] == outermost, chain[-1] == outermost
    if head and tail and chain != list(reversed(chain)):
        return chain, (
            f"{_FLAT_CHAIN} {chain!r} starts and ends with the authoritative actor "
            f"{outermost!r} — hop order between them is ambiguous"
        )
    if head:
        return chain, None
    if tail:
        return list(reversed(chain)), None   # AS emitted oldest-first
    return chain, (
        f"{_FLAT_CHAIN} {chain!r} contains no end matching the authoritative "
        f"actor {outermost!r} — orientation undecidable"
    )


def resolve_actor(claims: dict) -> dict:
    """Resolve WHO is behind one call, from already-verified token claims.

    This is the consume side of delegation: whatever the authorization server
    minted, a resource server has to turn it into "which human, via which agent"
    at the moment a tool runs. Crumb records that per call; the token only
    asserted it once, at mint time, before any of these calls existed.

    The rules, which are the AS's rules and not ours:

      - `sub` stays the human for the life of the chain. It is never rewritten
        by a hop, so it is the attribution anchor.
      - The OUTERMOST actor — flat `agent_id`, else the first nested `act.sub` —
        is whoever actually holds the token at call time. That one is
        authoritative. Inner hops are audit-only: they say how the token got
        here, not who is allowed to use it.
      - Flat claims win when present, because that is what they are for. The
        nested walk stays as the fallback for a plain RFC 8693 issuer that
        stamps no mirrors.
      - No actor at all means a service-account token: an agent is known, no
        human ever rode it. That absence, on a byte-identical wire, is the gap
        Crumb exists to make visible — so it is reported, not treated as an error.

    Returns {human, agent, chain, actor_type, source, discrepancy}. `source` names
    which representation answered ("flat" | "act" | "none") and `discrepancy`
    carries a human-readable note when a token's two representations of the same
    chain don't agree. Neither changes the answer; both exist because a flight
    recorder that quietly normalizes away a contradiction has destroyed the one
    detail worth recording.
    """
    nested = [_actor_id(a) for a in actor_chain(claims)]   # most-recent-first
    if any(a is None for a in nested):
        nested = []                                       # unusable, not authoritative
    flat_agent = _actor_id(claims.get(_FLAT_AGENT))
    outermost = flat_agent or (nested[0] if nested else None)
    flat, discrepancy = _flat_chain(claims, outermost)
    if flat_agent is None and flat:
        outermost = flat[0]                               # chain without an agent_id

    # actor_type describes the actor holding the token. Her spelling is
    # `act.actor_type`; the SDK reference also lists it top-level. Read both.
    act = claims.get("act")
    actor_type = None
    if isinstance(act, dict):
        actor_type = act.get("actor_type")
    if actor_type is None:
        actor_type = claims.get("actor_type")

    if flat_agent is not None or flat:
        source, chain = "flat", (flat or [flat_agent])
        # Both representations present: they describe the same chain, so a
        # mismatch is a real signal about the issuer, not noise to smooth over.
        if nested and discrepancy is None and chain != nested:
            discrepancy = (
                f"flat chain {chain!r} disagrees with nested `act` chain "
                f"{nested!r} in the same token"
            )
    elif nested:
        source, chain = "act", nested
    elif any(claims.get(k) is not None for k in ("act", _FLAT_AGENT, _FLAT_CHAIN)):
        # An actor claim IS present and we could not read an actor out of it.
        # This is NOT a service account, and the distinction is the whole product:
        # `sub` here is the HUMAN who delegated, so naming them as the agent would
        # record a person as the bot that acted — the exact inversion Crumb exists
        # to prevent. Keep the human, refuse to invent an agent, and say why.
        return {"human": claims.get("sub"), "agent": None, "chain": [],
                "actor_type": actor_type, "source": "unresolved",
                "discrepancy": discrepancy or (
                    "token carries actor claims but no readable actor id "
                    f"(act={claims.get('act')!r}, {_FLAT_AGENT}="
                    f"{claims.get(_FLAT_AGENT)!r}, {_FLAT_CHAIN}="
                    f"{claims.get(_FLAT_CHAIN)!r})"
                )}
    else:
        # No actor claim at all. The subject IS the caller — a bot, not a person.
        return {"human": None, "agent": claims.get("sub"), "chain": [],
                "actor_type": actor_type or "service", "source": "none",
                "discrepancy": discrepancy}

    return {"human": claims.get("sub"), "agent": chain[0], "chain": chain,
            "actor_type": actor_type, "source": source, "discrepancy": discrepancy}


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
    return jwt.encode(claims, _secret(), algorithm=_ALGO)


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


def _issuer_opt() -> dict:
    """Pin the expected issuer when the operator declares one (CRUMB_IDP_ISSUER).
    Left unset by default so Crumb stays IdP-agnostic (Okta/Keycloak/Zitadel each
    have their own `iss`); when set, the RS256 path additionally rejects a token
    whose `iss` doesn't match, not just one signed by the wrong key."""
    iss = os.environ.get("CRUMB_IDP_ISSUER")
    return {"issuer": iss} if iss else {}


def verify_delegation(token: str, resource: str, *,
                      require_rs256: bool | None = None) -> dict:
    """Verify a token for a given resource; return its claims.

      - RS256 -> a provider-issued token; verify against the IdP's public key
        (JWKS). No shared secret — the resource trusts the provider, not the minter.
      - HS256 -> the dev path; verify with the local dev key.

    The trust root must NOT be chosen by the token. The dev HS256 path verifies
    with `CRUMB_DELEGATION_SECRET`, a SYMMETRIC secret every minting process
    holds — acceptable for an offline demo, fatal in production: one leak forges
    delegation for any human, and an attacker simply sends an HS256 token to
    sidestep the provider entirely. So whenever an IdP is configured (the
    deployment opted into provider-signed identity) we require RS256 and refuse
    HS256 outright. `require_rs256` overrides the default for callers that want to
    pin it explicitly either way.

    Works for both delegation tokens (with `act`) and service-account tokens
    (without), under either signing path."""
    require = bool(_idp_url()) if require_rs256 is None else require_rs256
    alg = jwt.get_unverified_header(token).get("alg")
    if alg in _ASYMMETRIC_ALGOS:
        return jwt.decode(
            token,
            _rs256_public_key(token),
            algorithms=[alg],
            audience=resource,
            **_issuer_opt(),
        )
    if require:
        raise jwt.InvalidAlgorithmError(
            f"provider-signed token required (IdP configured) — refusing {alg!r} "
            f"dev token at resource {resource!r}; the shared-secret path is not a "
            "trust root in production"
        )
    return jwt.decode(token, _secret(), algorithms=[_ALGO], audience=resource)
