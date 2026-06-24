"""
Cross-issuer delegation — preserving provenance across a trust boundary (P7).

Through P6 a delegation chain (human -> agent -> agent -> tool) lived under ONE
issuer: one IdP signed the whole nested-`act` token, and the resource verified it
against that one provider's key. Real deployments aren't so tidy. The human logs
in at their employer's IdP (call it A); an agent they direct hands off to a
sub-agent that calls a tool in a partner's domain, governed by a different IdP
(B). The chain now spans two issuers — and that is the case Crumb has flagged as
unsolved since P3.

Why it's hard, honestly: vanilla RFC 8693 token exchange, when B is handed a
token A issued, *mints a fresh token signed only by B and throws A's signature
away*. Downstream you no longer hold the cryptographic proof that A authenticated
the human — only B's word that "A told me it was alice." For a tracer whose whole
thesis is "verify without trusting the operator," that collapses the cross-issuer
hop into exactly the trust-me point we exist to remove.

The fix here is provenance stapling. When B exchanges a token issued by A:

  1. B verifies A's token against A's public key — A must be in B's federation
     trust set (`Federation`), an explicit, inspectable list of issuers it accepts.
     Federation is a real relationship, not a hand-wave; we just make it the only
     trust assumption and refuse to hide any others.
  2. B does NOT discard A's token. B's minted token STAPLES it: the exact inner
     JWS rides in `prv`, its hash in `psh`, the inner issuer in `pis`. The human
     stays `sub`; the actor chain nests as before.

A federation-aware verifier (`verify_chain`) then walks the stapled linked list
of tokens back to the root, verifying EACH segment against ITS OWN issuer's key,
checking that each staple hash matches the token it points at, that the human is
the same identity at every hop, and that no issuer rewrote the actor chain it
inherited. Each issuer signs only its own segment; the verifier trusts the
federation set, never a single operator's say-so. The original provenance
survives the crossing instead of being collapsed into B's assertion.

What stays unsolved-by-standards (say it in the writeup): there is no RFC that
defines the `prv`/`psh` staple claims — that is a Crumb convention. And the
federation trust set is a genuine assumption: a verifier still has to decide which
issuers it will accept. We don't remove that decision; we make it explicit and
keep everything downstream of it cryptographically checkable.
"""

from __future__ import annotations

import hashlib
import time
import uuid

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from . import auth

_ALGO = "RS256"
_TTL = 60  # short-lived: one token per call, same as the single-issuer path


class CrossIssuerError(Exception):
    """Base for every way a cross-issuer chain can fail to verify. Each subclass
    names a distinct, demonstrable failure mode — the negative tests fire them by
    name so a reader can see exactly what the verifier refuses and why."""


class UntrustedIssuer(CrossIssuerError):
    """A token in the chain was signed by an issuer the verifier (or the
    exchanging IdP) does not federate with. No key to check it against, so it is
    refused outright — not verified-then-ignored, refused."""


class StapleMismatch(CrossIssuerError):
    """A token's `psh` does not hash the `prv` it carries. Someone swapped the
    embedded provenance for a different inner token; the staple is what makes that
    swap detectable without re-contacting the upstream issuer."""


class HumanDiscontinuity(CrossIssuerError):
    """The human (`sub`) changed somewhere down the chain — an outer token claims
    to act for one person while the token it stapled was issued for another. The
    crossing must carry the SAME human end to end or it proves nothing."""


class ActorChainBroken(CrossIssuerError):
    """An issuer rewrote the actor chain it inherited instead of only appending to
    it. The nested `act` an outer token carries beneath its own actor must equal
    the inner token's `act` verbatim; anything else is a forged hop."""


def staple_hash(token: str) -> str:
    """The provenance staple: a prefixed SHA-256 over the inner token's exact
    compact bytes. Embedding this in the outer token binds it to one specific
    predecessor, so the `prv` payload can't be silently substituted."""
    digest = hashlib.sha256(token.encode("ascii")).hexdigest()
    return f"sha256:{digest}"


class Issuer:
    """One identity provider in a federation — its own key, its own `iss`, its own
    JWKS. Mirrors `crumb.idp` but is instantiable, so a demo can stand up two
    distinct providers (A and B) with different keys and prove a chain crosses
    between them. Each issuer signs only the segment it mints."""

    def __init__(self, iss: str, kid: str | None = None,
                 key: rsa.RSAPrivateKey | None = None):
        self.iss = iss
        self.kid = kid or f"{iss}-rs256-1"
        self._key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def public_key(self):
        return self._key.public_key()

    def jwks(self) -> dict:
        """The public keys a resource (or a peer issuer) verifies this provider's
        tokens against — no shared secret, same shape Okta/Keycloak expose."""
        import json

        from jwt.algorithms import RSAAlgorithm

        jwk = json.loads(RSAAlgorithm.to_jwk(self.public_key()))
        jwk.update({"kid": self.kid, "use": "sig", "alg": _ALGO})
        return {"keys": [jwk]}

    def _verify_incoming(self, subject_token: str, federation: "Federation") -> tuple[dict, bool]:
        """Recover the verified claims of an exchange's subject. Returns
        `(claims, is_delegation)`.

          - The human's session (HS256) is the root of a chain — verified against
            the session key, `is_delegation=False`, nothing to staple.
          - A delegation token (RS256) is verified against ITS issuer's key: our
            own if it is ours, otherwise the federation set's entry for that `iss`
            (raising `UntrustedIssuer` if we don't federate with it). This is the
            boundary check — an IdP refuses to extend a chain it can't anchor."""
        try:
            return auth.verify_session(subject_token), False
        except jwt.PyJWTError:
            pass

        iss = jwt.decode(subject_token, options={"verify_signature": False}).get("iss")
        if iss == self.iss:
            key = self.public_key()
        else:
            key = federation.key_for(iss)   # raises UntrustedIssuer if unknown
        claims = jwt.decode(subject_token, key, algorithms=[_ALGO], issuer=iss,
                            options={"verify_aud": False})
        return claims, True

    def exchange(self, subject_token: str, actor: str, audience: str,
                 federation: "Federation", ttl: int = _TTL) -> str:
        """RFC 8693 token exchange, federation-aware. Verify the subject (human
        session or a peer/own delegation token), append `actor` to the nested
        chain, and mint our own RS256 token scoped to `audience`. If the subject
        was itself a delegation token, STAPLE it (`prv`/`psh`/`pis`) so the segment
        it represents stays independently verifiable after the crossing."""
        claims, is_delegation = self._verify_incoming(subject_token, federation)

        human = claims["sub"]
        act: dict = {"sub": actor}
        if claims.get("act"):
            act["act"] = claims["act"]      # nest the inherited chain, never rewrite it

        now = int(time.time())
        out = {
            "iss": self.iss,
            "sub": human,                   # the human stays the subject, every hop
            "act": act,                     # most-recent actor outermost
            "aud": audience,
            "jti": uuid.uuid4().hex,
            "iat": now,
            "exp": now + ttl,
        }
        if is_delegation:
            # Bind the predecessor into this token so its provenance survives the
            # boundary and can be re-verified against the issuer that signed it.
            out["prv"] = subject_token
            out["psh"] = staple_hash(subject_token)
            out["pis"] = claims["iss"]
        return jwt.encode(out, self._key, algorithm=_ALGO, headers={"kid": self.kid})


class Federation:
    """The trust set: the issuers a verifier (or an exchanging IdP) will accept,
    keyed by `iss` -> public key. This is the ONE assumption cross-issuer
    verification rests on, so it is an explicit object you can read, not an
    ambient default. Model it as 'the JWKS each peer has already fetched and
    cached' — exactly the steady state OIDC federation establishes."""

    def __init__(self):
        self._keys: dict = {}

    def trust(self, issuer: Issuer) -> "Federation":
        self._keys[issuer.iss] = issuer.public_key()
        return self

    def key_for(self, iss: str | None):
        key = self._keys.get(iss)
        if key is None:
            raise UntrustedIssuer(f"issuer not in federation trust set: {iss!r}")
        return key

    @property
    def issuers(self) -> list:
        return sorted(self._keys)


def actor_chain(claims: dict) -> list:
    """The delegation chain in a token's nested `act`, most-recent actor first,
    ending with the agent that first acted for the human. Same walk as the
    single-issuer path — the chain is continuous across issuers because each
    exchange nests, never flattens."""
    chain: list = []
    act = claims.get("act")
    while isinstance(act, dict):
        if "sub" in act:
            chain.append(act["sub"])
        act = act.get("act")
    return chain


def verify_chain(token: str, resource: str, federation: "Federation") -> dict:
    """Verify a (possibly cross-issuer) delegation token end to end and return a
    resolved view: `{human, actor_chain, issuer_path}`.

    Walk the stapled linked list from the outermost token to the root, and at
    every link enforce four things:

      1. SIGNATURE per segment — each token is verified against ITS issuer's key,
         taken from the federation set (`UntrustedIssuer` if we don't federate
         with it). Only the outermost token is checked against `resource`; inner
         tokens were scoped to their own earlier audiences.
      2. STAPLE — a token carrying `prv` must have `psh == staple_hash(prv)`, or
         the embedded provenance was swapped (`StapleMismatch`).
      3. HUMAN CONTINUITY — `sub` is the same identity at every hop
         (`HumanDiscontinuity`).
      4. ACTOR CONTINUITY — the chain an outer token carries beneath its own actor
         equals the inner token's chain verbatim; no issuer rewrote what it
         inherited (`ActorChainBroken`).

    The root is the token with no `prv` (its subject was the human's session). If
    every link holds, the human at the root is provably the one the outermost
    actor is acting for — across the issuer boundary, with no single issuer
    trusted to assert it alone."""
    human = None
    issuer_path: list = []
    outer_chain = None
    current = token
    is_outer = True

    while True:
        iss = jwt.decode(current, options={"verify_signature": False}).get("iss")
        key = federation.key_for(iss)      # raises UntrustedIssuer if unknown
        claims = jwt.decode(
            current, key, algorithms=[_ALGO], issuer=iss,
            audience=resource if is_outer else None,
            options={"verify_aud": is_outer},
        )
        issuer_path.append(iss)

        if human is None:
            human = claims["sub"]
            outer_chain = actor_chain(claims)
        elif claims["sub"] != human:
            raise HumanDiscontinuity(
                f"human changed across the boundary: {human!r} then {claims['sub']!r}")

        prv = claims.get("prv")
        if prv is None:
            break                          # reached the root: human-session-rooted token

        if staple_hash(prv) != claims.get("psh"):
            raise StapleMismatch(f"psh does not hash the stapled token at issuer {iss!r}")

        # The chain beneath our own actor must be exactly what the predecessor held.
        inherited = claims.get("act", {}).get("act")
        parent = jwt.decode(prv, options={"verify_signature": False})
        if inherited != parent.get("act"):
            raise ActorChainBroken(f"actor chain rewritten at issuer {iss!r}")

        current = prv
        is_outer = False

    return {"human": human, "actor_chain": outer_chain, "issuer_path": issuer_path}
