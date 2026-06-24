"""
P7 proof — cross-issuer delegation with preserved provenance.

The chain Crumb has refused to fake since P3: a human authenticates at one IdP
(A), an agent they direct hands off to a sub-agent that calls a tool governed by
a DIFFERENT IdP (B). Two issuers, one accountable human. Vanilla token exchange
would have B mint a fresh token and drop A's signature, leaving only B's word
that the human was alice. Crumb staples instead — B's token carries A's exact
token (`prv`) and its hash (`psh`), so a verifier re-checks A's segment against
A's key and never takes B's word for the upstream.

  1. alice logs in at A. A issues planner's token. B exchanges it for researcher,
     stapling A's token. researcher calls read_record in B's domain.
  2. A federation-aware verifier walks the chain back to alice — verifying B's
     segment against B's key and A's segment against A's key. VERIFIED.
  3. A malicious B forges an upstream "mallory authorized this at A": it can stamp
     its own segment, but it cannot sign as A. Inner signature fails.
  4. Swap the stapled provenance for a different token: the psh no longer hashes
     it. StapleMismatch.
  5. B claims to act for alice but staples a token A issued for bob.
     HumanDiscontinuity — the human must be the same at every hop.
  6. B rewrites the actor chain it inherited (claims the hop went through a ghost
     agent). ActorChainBroken — an issuer may append, never rewrite.
  7. The upstream token is from an issuer the verifier does not federate with.
     UntrustedIssuer — even if B vouches for it, the verifier decides for itself.

The one assumption is the federation trust set, and it is explicit
(`Federation`). Everything downstream of it is cryptographically checked.

Run: python -m crumb.cross_issuer_demo
"""

from __future__ import annotations

import time
import uuid

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from . import auth
from .federation import (
    ActorChainBroken,
    Federation,
    HumanDiscontinuity,
    Issuer,
    StapleMismatch,
    UntrustedIssuer,
    actor_chain,
    staple_hash,
    verify_chain,
)

RESOURCE = "read_record"


def _claims(iss: str, sub: str, act: dict, prv: str | None = None,
            pis: str | None = None) -> dict:
    """A delegation token's claim set, optionally stapling a predecessor. Used by
    the negative tests to hand-craft what a malicious issuer would try to mint."""
    now = int(time.time())
    body = {"iss": iss, "sub": sub, "act": act, "aud": RESOURCE,
            "jti": uuid.uuid4().hex, "iat": now, "exp": now + 60}
    if prv is not None:
        body["prv"] = prv
        body["psh"] = staple_hash(prv)
        body["pis"] = pis
    return body


def main() -> None:
    print("P7 — cross-issuer delegation\n" + "=" * 42)

    # Two distinct providers, two distinct keys. A is the human's home IdP; B
    # governs the tool's domain. B federates with A (it will accept A's tokens);
    # the verifier federates with both.
    idp_a = Issuer("https://idp-a.local")
    idp_b = Issuer("https://idp-b.local")
    b_trusts_a = Federation().trust(idp_a)
    verifier = Federation().trust(idp_a).trust(idp_b)

    # 1. The chain crosses the boundary. alice -> planner (at A) -> researcher (at
    #    B) -> read_record. B staples A's token as it exchanges.
    alice = auth.login("alice", directives=("read_record",))
    tok_a = idp_a.exchange(alice.token, "planner", RESOURCE, Federation())   # human-rooted, no staple
    tok_b = idp_b.exchange(tok_a, "researcher", RESOURCE, b_trusts_a)        # crosses A->B, staples
    print("\n1. alice@A -> planner@A -> researcher@B -> read_record")
    hdr = jwt.get_unverified_header(tok_b)
    body = jwt.decode(tok_b, options={"verify_signature": False})
    print(f"   outer token issuer       {body['iss']!r} (alg {hdr['alg']}, kid {hdr.get('kid')})")
    print(f"   stapled provenance iss   {body.get('pis')!r}  (the segment A signed)")
    print(f"   psh binds prv            {body['psh'][:23]}...")

    # 2. Verify the whole chain — each issuer's segment against its own key.
    resolved = verify_chain(tok_b, RESOURCE, verifier)
    print("\n2. federation-aware verify")
    print(f"   human (root sub)         {resolved['human']!r}")
    print(f"   actor_chain              {resolved['actor_chain']!r}  (most-recent first)")
    print(f"   issuer_path              {resolved['issuer_path']!r}  (outer -> root)")
    assert resolved["human"] == "alice"
    assert resolved["actor_chain"] == ["researcher", "planner"]
    assert resolved["issuer_path"] == ["https://idp-b.local", "https://idp-a.local"]
    print("   => VERIFIED across two issuers; the trail leads back to alice")

    # 3. A malicious B fabricates an upstream human. It controls its OWN segment,
    #    so it can mint a token that says it acts for mallory and staple a forged
    #    "A token" naming mallory — but it cannot SIGN as A. The inner segment is
    #    verified against A's real key and the forgery fails there.
    print("\n3. malicious B forges an upstream human (mallory)")
    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged_inner = jwt.encode(_claims(idp_a.iss, "mallory", {"sub": "planner"}),
                              attacker_key, algorithm="RS256")           # iss=A, NOT A's key
    tok_forge = jwt.encode(
        _claims(idp_b.iss, "mallory", {"sub": "researcher", "act": {"sub": "planner"}},
                prv=forged_inner, pis=idp_a.iss),
        idp_b._key, algorithm="RS256", headers={"kid": idp_b.kid})       # genuinely B-signed
    try:
        verify_chain(tok_forge, RESOURCE, verifier)
        print("   forged upstream          UNEXPECTEDLY ACCEPTED  <-- bug")
    except jwt.InvalidSignatureError:
        print("   forged upstream          rejected (InvalidSignature) — B can't sign as A")

    # 4. Swap the stapled provenance for a real-but-different token without fixing
    #    the hash. The staple is what makes the substitution visible.
    print("\n4. swap the stapled provenance (psh left stale)")
    bob = auth.login("bob", directives=("read_record",))
    tok_a_bob = idp_a.exchange(bob.token, "planner", RESOURCE, Federation())
    swapped = jwt.decode(tok_b, options={"verify_signature": False})
    swapped["prv"] = tok_a_bob                                            # different token...
    # ...but psh still hashes the original tok_a, so the bind no longer holds
    tok_swap = jwt.encode(swapped, idp_b._key, algorithm="RS256", headers={"kid": idp_b.kid})
    try:
        verify_chain(tok_swap, RESOURCE, verifier)
        print("   swapped provenance       UNEXPECTEDLY ACCEPTED  <-- bug")
    except StapleMismatch:
        print("   swapped provenance       rejected (StapleMismatch) — psh pins one predecessor")

    # 5. B claims to act for alice but staples a token A issued for bob. Each
    #    segment is validly signed; the human just doesn't line up across the hop.
    print("\n5. B claims alice but staples bob's token")
    tok_disc = jwt.encode(
        _claims(idp_b.iss, "alice", {"sub": "researcher", "act": {"sub": "planner"}},
                prv=tok_a_bob, pis=idp_a.iss),
        idp_b._key, algorithm="RS256", headers={"kid": idp_b.kid})
    try:
        verify_chain(tok_disc, RESOURCE, verifier)
        print("   human discontinuity      UNEXPECTEDLY ACCEPTED  <-- bug")
    except HumanDiscontinuity:
        print("   human discontinuity      rejected (HumanDiscontinuity) — same human or nothing")

    # 6. B rewrites the actor chain it inherited — claims the hop ran through a
    #    'ghost' agent instead of planner. An issuer may append, never rewrite.
    print("\n6. B rewrites the inherited actor chain")
    tok_rewrite = jwt.encode(
        _claims(idp_b.iss, "alice", {"sub": "researcher", "act": {"sub": "ghost"}},
                prv=tok_a, pis=idp_a.iss),                               # real tok_a (act=planner)
        idp_b._key, algorithm="RS256", headers={"kid": idp_b.kid})
    try:
        verify_chain(tok_rewrite, RESOURCE, verifier)
        print("   rewritten chain          UNEXPECTEDLY ACCEPTED  <-- bug")
    except ActorChainBroken:
        print("   rewritten chain          rejected (ActorChainBroken) — append-only, no rewrite")

    # 7. The upstream issuer isn't one the verifier federates with. Even though B
    #    chose to accept it, the verifier makes its own trust decision.
    print("\n7. upstream from an unfederated issuer")
    idp_c = Issuer("https://idp-c.rogue")
    b_trusts_c = Federation().trust(idp_c)
    tok_c = idp_c.exchange(alice.token, "planner", RESOURCE, Federation())
    tok_bc = idp_b.exchange(tok_c, "researcher", RESOURCE, b_trusts_c)    # B accepted C...
    try:
        verify_chain(tok_bc, RESOURCE, verifier)                         # ...verifier did not
        print("   unfederated issuer       UNEXPECTEDLY ACCEPTED  <-- bug")
    except UntrustedIssuer:
        print("   unfederated issuer       rejected (UntrustedIssuer) — verifier trusts its own set")

    print("\nCross-issuer attribution: the chain spans two providers, each signs only")
    print("its own segment, and the human stays provable at the root — no single")
    print("issuer is trusted to assert it alone. The federation set is the one")
    print("assumption, and it is explicit.")


if __name__ == "__main__":
    main()
