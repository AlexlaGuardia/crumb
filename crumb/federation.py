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

Trustless key distribution (the JWKS leg). Through the first cut, the trust set
was a map of `iss -> pinned public key` — the verifier held each issuer's key as a
static PEM, supplied out of band. That is the right *shape* but the wrong
steady state: real IdPs rotate signing keys, and a pinned PEM goes stale the day
they do. So a verifier can instead name the issuers it federates with by URL and
fetch their CURRENT keys from each issuer's own JWKS endpoint
(`/.well-known/openid-configuration` -> `jwks_uri`), selecting the key by the
token header's `kid`. Two properties are load-bearing and worth stating plainly:

  - It stays trustless. The keys are fetched from the ISSUER's endpoint (over TLS,
    which authenticates it), NEVER from whoever holds the log under test. The
    verifier still decides which issuer URLs it accepts — that decision just names
    an issuer identity instead of pinning one frozen key.
  - It follows rotation. Keys are cached and indexed by `kid`; when a token
    arrives signed by a `kid` we haven't seen, the source refetches once before
    giving up. A rotated issuer keeps verifying with no redeploy; a genuinely
    unknown key is refused (`UnknownSigningKey`), not guessed at.
  - It follows revocation, two ways. The BACKSTOP is polling: a cached key is
    trusted for a bounded `ttl`; past that the cache is reconfirmed against the live
    JWKS before it is served again, so a dropped key stops verifying within one TTL
    window even if nobody flagged it. The reconfirm fails closed — an unreachable
    issuer is refused, never served stale, so stalling the fetch can't extend a
    revoked key. The INSTANT path is push-invalidation (`Federation.revoke`): a key
    you already know is compromised is tombstoned and refused NOW, ahead of the TTL.
    Push-invalidation is sound because it is subtract-only — a revocation can make
    verification stricter, never looser — so it never reintroduces trust in whoever
    delivers the signal (`RevokedSigningKey`).

A pinned PEM and a JWKS URL are two sources of the SAME trust set — mix them per
issuer. Pin the key you already hold out of band; fetch the ones that rotate.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from . import auth

_ALGO = "RS256"
_TTL = 60  # short-lived: one token per call, same as the single-issuer path

# A real human->agent->...->tool chain is a handful of hops. Each staple embeds
# the FULL predecessor token, so token size grows with depth and a verifier walks
# one decode per hop. Bound it: a malicious or buggy federated issuer must not be
# able to hand a verifier an arbitrarily deep chain to chew through. Generous
# enough that no honest delegation comes near it.
MAX_CHAIN_DEPTH = 16


class CrossIssuerError(Exception):
    """Base for every way a cross-issuer chain can fail to verify. Each subclass
    names a distinct, demonstrable failure mode — the negative tests fire them by
    name so a reader can see exactly what the verifier refuses and why."""


class UntrustedIssuer(CrossIssuerError):
    """A token in the chain was signed by an issuer the verifier (or the
    exchanging IdP) does not federate with. No key to check it against, so it is
    refused outright — not verified-then-ignored, refused."""


class UnknownSigningKey(CrossIssuerError):
    """The issuer IS in the federation trust set, but none of its published keys
    match the token's `kid` — even after a fresh JWKS fetch. Distinct from
    `UntrustedIssuer`: we federate with the issuer, we just can't find the key it
    claims to have signed with. Refused, never guessed (a token whose `kid` we
    can't resolve is unverifiable, not merely inconvenient)."""


class RevokedSigningKey(CrossIssuerError):
    """A key was explicitly revoked (push-invalidation) and is refused NOW,
    independent of any cache TTL. Distinct from `UnknownSigningKey`: the key was
    known and is being actively killed, not merely absent — so a reader can tell
    "compromised, pulled" from "never heard of it." A revocation only ever
    SUBTRACTS from the trusted set: marking a `kid` revoked can make verification
    stricter, never looser, so a token signed by it stops verifying the instant the
    revocation lands rather than waiting out the TTL reconfirm."""


class IssuerUnreachable(CrossIssuerError):
    """A trusted issuer's JWKS endpoint could not be reached to (re)confirm its
    keys. The cache is stale or empty, so we refuse rather than serve keys we can't
    currently substantiate — fail-closed. This is deliberate: serving a stale cache
    when the fetch fails would let an attacker who can stall the endpoint keep a
    revoked key alive past its TTL."""


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


class ChainTooDeep(CrossIssuerError):
    """The stapled chain exceeds `MAX_CHAIN_DEPTH`. No honest delegation is this
    deep; refusing it stops a malicious issuer from handing the verifier an
    arbitrarily long (and size-amplified) chain to walk."""


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
            kid = jwt.get_unverified_header(subject_token).get("kid")
            key = federation.key_for(iss, kid)   # raises Untrusted/UnknownSigningKey
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


def _jwk_to_key(jwk: dict):
    """One JWKS entry -> a usable public key. RS256 only, matching what every
    issuer in this system signs with; an unexpected key type is a refusal, not a
    silent skip, so a malformed JWKS can't quietly shrink the trusted key set."""
    kty = jwk.get("kty")
    if kty != "RSA":
        raise UnknownSigningKey(f"unsupported JWKS key type {kty!r} (RSA only)")
    return RSAAlgorithm.from_jwk(json.dumps(jwk))


class _PinnedKeys:
    """A trust source backed by keys the verifier already holds — an in-process
    `Issuer` or a PEM pinned out of band. Indexed by `kid` when we know it, with a
    keyless default so a bare `trust_key(iss, pem)` (no kid to hand) still resolves
    for any token from that issuer. Static: what you pinned is what you get."""

    def __init__(self):
        self._by_kid: dict = {}
        self._default = None

    def add(self, public_key, kid: str | None = None) -> None:
        if kid is not None:
            self._by_kid[kid] = public_key
        if self._default is None:
            self._default = public_key

    def get(self, kid: str | None):
        if kid is not None and kid in self._by_kid:
            return self._by_kid[kid]
        # A token whose kid we didn't pin still verifies against the pinned key if
        # that's all we hold — the single-key case, unchanged from before kids.
        return self._default


class _JWKSKeys:
    """A trust source that fetches an issuer's CURRENT keys from its JWKS endpoint
    and caches them by `kid`. The verifier commits to the issuer's URL, not to one
    frozen key, so two moving-target problems are handled:

      - ROTATION (a key APPEARS): an unseen `kid` triggers exactly one refetch
        before we give up, so a freshly-rotated key is picked up immediately.
      - REVOCATION (a key DISAPPEARS): a cached key is only trusted for `ttl`
        seconds. Past that, the cache is stale and must be reconfirmed against the
        live JWKS before we keep vouching for it. When the issuer has dropped a
        compromised key, the reconfirm removes it from cache, and tokens signed by
        it stop verifying — within one TTL window, not forever.

    The refetch fails CLOSED: if the reconfirm can't reach the issuer we raise
    rather than serve the stale cache. Serving stale would hand an attacker who can
    stall the JWKS endpoint an indefinite extension on a revoked key — exactly the
    revocation the TTL exists to enforce. Availability of the issuer's JWKS is the
    cost; it is the honest cost of verifying against the live issuer.

    `fetch` is injectable so tests and in-process demos can serve a JWKS without a
    socket; `clock` likewise so TTL behaviour is testable without real time. In
    production `fetch` is an HTTPS GET (TLS authenticates the issuer). The
    stdlib-equivalent is `jwt.PyJWKClient`; we keep an explicit cache here so the
    trust boundary — issuer URL in, key out — stays legible in one place."""

    def __init__(self, jwks_uri: str, fetch=None, ttl: float = 300, clock=None,
                 *, retries: int = 2, backoff: float = 0.5, sleep=None,
                 breaker_threshold: int = 3, breaker_cooldown: float = 30.0):
        self.jwks_uri = jwks_uri
        self._fetch = fetch or _http_get_json
        self._ttl = ttl
        self._clock = clock or time.monotonic
        # Availability defences around the fetch (see `_fetch_jwks`). Both preserve
        # fail-closed; they only trade retry latency for a faster refusal.
        self._retries = retries
        self._backoff = backoff
        self._sleep = sleep or time.sleep
        self._breaker_threshold = breaker_threshold
        self._breaker_cooldown = breaker_cooldown
        self._by_kid: dict = {}
        self._fetched_at: float | None = None
        self._consec_failures = 0
        self._circuit_open_until: float | None = None

    def _fetch_jwks(self) -> dict:
        """Fetch the JWKS with bounded retries and a per-issuer circuit breaker.

        Both are availability defences that PRESERVE fail-closed. A transient blip
        (one dropped connection, a brief 5xx) shouldn't collapse verification, so
        the fetch is retried a few times with exponential backoff. Once an issuer
        fails persistently the breaker OPENS and every subsequent call fails fast:
        it still raises `IssuerUnreachable` and never serves a stale key, it just
        skips the retry latency until a cooldown lets one trial fetch through
        (half-open). The breaker trades retry latency for a quick refusal; it never
        trades security for availability.

        Semantic refusals (`UntrustedIssuer` / `UnknownSigningKey`) are not
        availability failures, so they propagate immediately and never retry or
        trip the breaker. Note the worst-case latency of the first failing load is
        `(retries + 1)` fetch timeouts plus backoff; tune `retries`/`backoff` and
        the underlying fetch timeout together for a slow (as opposed to refused)
        issuer."""
        now = self._clock()
        if self._circuit_open_until is not None and now < self._circuit_open_until:
            raise IssuerUnreachable(
                f"JWKS circuit open for {self.jwks_uri}: issuer failed "
                f"{self._consec_failures}x, cooling down before the next attempt")

        last_exc: Exception | None = None
        for attempt in range(self._retries + 1):
            try:
                doc = self._fetch(self.jwks_uri)
            except CrossIssuerError as e:
                if not isinstance(e, IssuerUnreachable):
                    raise                       # semantic refusal: never retried
                last_exc = e                    # availability failure: retryable
            except Exception as e:              # network/transport failure
                last_exc = e
            else:
                self._consec_failures = 0       # a good fetch closes the breaker
                self._circuit_open_until = None
                return doc
            if attempt < self._retries:
                self._sleep(self._backoff * (2 ** attempt))

        self._consec_failures += 1
        if self._consec_failures >= self._breaker_threshold:
            self._circuit_open_until = self._clock() + self._breaker_cooldown
        raise IssuerUnreachable(
            f"could not fetch JWKS at {self.jwks_uri} after "
            f"{self._retries + 1} attempt(s): {last_exc!r}") from last_exc

    def _load(self) -> None:
        doc = self._fetch_jwks()
        by_kid = {}
        for jwk in doc.get("keys", []):
            kid = jwk.get("kid")
            if kid is not None:
                by_kid[kid] = _jwk_to_key(jwk)
        self._by_kid = by_kid
        self._fetched_at = self._clock()

    def _is_stale(self) -> bool:
        return (self._fetched_at is None
                or (self._clock() - self._fetched_at) >= self._ttl)

    def get(self, kid: str | None):
        # A cache older than ttl can no longer be trusted to reflect revocations,
        # so reconfirm before serving. This raises (fail-closed) if the issuer is
        # unreachable — never serve a key past its confirmed lifetime.
        reloaded = False
        if self._is_stale():
            self._load()
            reloaded = True
        if kid is None:
            # No kid to match: only unambiguous if the issuer publishes exactly one.
            if len(self._by_kid) == 1:
                return next(iter(self._by_kid.values()))
            return None
        if kid not in self._by_kid and not reloaded:
            self._load()                    # rotation: a new kid mid-ttl, refetch once
        return self._by_kid.get(kid)

    def evict(self, kid: str) -> None:
        """Drop a `kid` from the live cache immediately. Called on push-revocation
        so a compromised key does not linger in the served set until the next TTL
        reconfirm. `key_for` already refuses a revoked kid regardless; this just
        keeps the cache from vouching for a key we've killed. Idempotent — a kid we
        don't currently hold is a no-op."""
        self._by_kid.pop(kid, None)


def _http_get_json(url: str) -> dict:
    """Default JWKS/discovery fetch: an HTTPS GET returning parsed JSON. Imported
    lazily so pure in-process federation (tests, deterministic demos) never pulls
    in httpx or touches the network."""
    import httpx

    resp = httpx.get(url, timeout=20, follow_redirects=True)
    resp.raise_for_status()
    return resp.json()


class Federation:
    """The trust set: the issuers a verifier (or an exchanging IdP) will accept,
    keyed by `iss`. This is the ONE assumption cross-issuer verification rests on,
    so it is an explicit object you can read, not an ambient default.

    An issuer's keys come from one of two sources, mixable per issuer:
      - PINNED (`trust`, `trust_key`) — a key the verifier already holds.
      - FETCHED (`trust_jwks_uri`, `trust_discovery`) — the issuer's live JWKS,
        cached and rotation-aware.
    Either way the verifier, not the log-holder, decides which issuers count."""

    def __init__(self):
        self._sources: dict = {}
        # Push-invalidation tombstones: (iss, kid) pairs refused NOW, ahead of any
        # TTL reconfirm. Subtract-only — see `revoke`.
        self._revoked: set = set()

    def _pinned(self, iss: str) -> "_PinnedKeys":
        src = self._sources.get(iss)
        if not isinstance(src, _PinnedKeys):
            src = _PinnedKeys()
            self._sources[iss] = src
        return src

    def trust(self, issuer: Issuer) -> "Federation":
        self._pinned(issuer.iss).add(issuer.public_key(), issuer.kid)
        return self

    def trust_key(self, iss: str, public_key, kid: str | None = None) -> "Federation":
        """Trust an issuer by a raw public key, not a live `Issuer` object. This is
        how a verifier pins the keys it accepts out of band (e.g. a
        `crumb verify --federation` manifest) — the same explicit trust set,
        sourced from disk instead of an in-process issuer. Pass `kid` when you know
        it so it survives an issuer publishing multiple keys."""
        self._pinned(iss).add(public_key, kid)
        return self

    def trust_jwks_uri(self, iss: str, jwks_uri: str, fetch=None,
                       ttl: float = 300, clock=None,
                       resilience: dict | None = None) -> "Federation":
        """Trust an issuer by its JWKS endpoint: fetch its current keys on demand
        instead of pinning one. This is the trustless steady state — the verifier
        commits to the issuer's URL, and rotation is handled downstream. `ttl`
        bounds how long a cached key is trusted before it must be reconfirmed
        against the live JWKS (this is what lets a revoked key drop out); tighten it
        to propagate revocations faster, at the cost of more fetches. `fetch`/`clock`
        override the default HTTPS GET / monotonic clock (tests/in-process demos).
        `resilience` tunes the availability defences on the fetch — any of
        `retries`, `backoff`, `sleep`, `breaker_threshold`, `breaker_cooldown`
        (see `_JWKSKeys`); it never relaxes fail-closed."""
        self._sources[iss] = _JWKSKeys(jwks_uri, fetch=fetch, ttl=ttl, clock=clock,
                                       **(resilience or {}))
        return self

    def trust_discovery(self, iss: str, fetch=None,
                        discovery_url: str | None = None,
                        ttl: float = 300, clock=None,
                        resilience: dict | None = None) -> "Federation":
        """Trust an issuer the way OIDC intends: read its
        `/.well-known/openid-configuration`, take the advertised `jwks_uri`, and
        fetch keys from there. The verifier names only the issuer; the issuer's own
        metadata says where its keys live. `discovery_url` overrides the derived
        well-known path for issuers that host metadata off-origin; `ttl`/`clock`
        flow through to the JWKS cache (see `trust_jwks_uri`)."""
        get = fetch or _http_get_json
        url = discovery_url or f"{iss.rstrip('/')}/.well-known/openid-configuration"
        meta = get(url)
        jwks_uri = meta.get("jwks_uri")
        if not jwks_uri:
            raise UntrustedIssuer(
                f"issuer {iss!r} discovery document has no jwks_uri")
        return self.trust_jwks_uri(iss, jwks_uri, fetch=fetch, ttl=ttl, clock=clock,
                                   resilience=resilience)

    def revoke(self, iss: str, kid: str) -> "Federation":
        """Push-invalidate a signing key: refuse it NOW, without waiting for the TTL
        reconfirm to notice the issuer dropped it. This is the instant path for a
        key you already know is compromised; the TTL reconfirm stays as the backstop
        for revocations nobody pushed.

        The property that keeps this sound is asymmetry: a revocation can only
        SUBTRACT from the trusted set, never add to it. Marking a `kid` revoked can
        at most make the verifier refuse tokens (fail-closed); it can never make a
        forged token verify. So the signal moves only in the safe direction and does
        not reintroduce trust in whoever delivers it — the worst a bogus revocation
        does is a self-inflicted denial, not an acceptance. That asymmetry is what
        lets the transport (a webhook, an admin call, a shared feed) carry a low
        authorization bar without reopening the operator-trust hole Crumb exists to
        close.

        Permanent by design: a `kid` names one key, and a revoked key's id is not
        reused, so the tombstone never lifts. A rotated issuer signs under a NEW
        kid, which this does not touch."""
        if kid is None:
            raise ValueError("revoke requires a kid: revocation targets one specific key")
        self._revoked.add((iss, kid))
        # Best-effort cache hygiene: drop the dead key from a live JWKS source so it
        # doesn't linger in the served set. `key_for` refuses it regardless.
        src = self._sources.get(iss)
        if isinstance(src, _JWKSKeys):
            src.evict(kid)
        return self

    def is_revoked(self, iss: str | None, kid: str | None) -> bool:
        """Whether `(iss, kid)` has been push-invalidated. Exposed so a caller can
        distinguish a revoked key from an unknown one without catching the raise."""
        return (iss, kid) in self._revoked

    def key_for(self, iss: str | None, kid: str | None = None):
        """Resolve the verifying key for a token, by issuer and (when present) key
        id. `RevokedSigningKey` if the key was push-invalidated (checked first, so
        a revoked key is refused ahead of any cache/TTL logic); `UntrustedIssuer` if
        the issuer isn't in the trust set at all; `UnknownSigningKey` if it is but
        none of its keys match the `kid` — the failures a verifier must keep
        distinct."""
        if (iss, kid) in self._revoked:
            raise RevokedSigningKey(
                f"issuer {iss!r} key {kid!r} was revoked (push-invalidated)")
        src = self._sources.get(iss)
        if src is None:
            raise UntrustedIssuer(f"issuer not in federation trust set: {iss!r}")
        key = src.get(kid)
        if key is None:
            raise UnknownSigningKey(
                f"issuer {iss!r} has no key matching kid {kid!r}")
        return key

    @property
    def issuers(self) -> list:
        return sorted(self._sources)


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
    depth = 0

    while True:
        depth += 1
        if depth > MAX_CHAIN_DEPTH:
            raise ChainTooDeep(
                f"stapled chain exceeds MAX_CHAIN_DEPTH={MAX_CHAIN_DEPTH}")
        iss = jwt.decode(current, options={"verify_signature": False}).get("iss")
        kid = jwt.get_unverified_header(current).get("kid")
        key = federation.key_for(iss, kid)  # raises Untrusted/UnknownSigningKey
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
