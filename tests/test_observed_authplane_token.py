"""
Pinned against a token a real AuthPlane server actually issued.

Everything else in the suite tests claim shapes we reasoned our way to. This one
is a transcript: alice logged in, consented, and two agents each ran an RFC 8693
exchange against a live AuthPlane 0.x instance. The claims below are copied
verbatim off the resulting token (identifiers shortened, timestamps dropped).

Two things it records that the reasoning did NOT predict:

  - `agent_id` and `agent_chain` are ABSENT. Both names appear in AuthPlane's
    SDK reference, and its server binary contains both, but neither is emitted
    for clients registered through dynamic client registration — not at one hop,
    not at two. So the nested `act` walk is not the fallback path here, it is the
    only path. A consumer that reads the docs and builds only the flat fast path
    gets nothing.
  - `actor_type` is `"service"` for both hops, even though both actors are
    agents acting for a human. The binary carries a `typeagent`/`typeservice`
    client distinction and a CIMD subsystem, so agent typing evidently exists;
    plain DCR just doesn't reach it. Whatever the cause, `actor_type` cannot be
    read as "is a human behind this" — `sub` plus the presence of an actor is
    what answers that.

The point of pinning a real transcript is that reality gets a vote. If our model
of the claims drifts from what an issuer sends, this test fails and the model is
what's wrong.
"""

from __future__ import annotations

from crumb.tokens import resolve_actor

ALICE = "eGNrNFdD-alice"
PLANNER = "Hxsg1GsL-planner"        # first actor
RESEARCHER = "UUSr8HD5-researcher"  # most recent actor, outermost

# Verbatim shape from the live two-hop exchange.
OBSERVED = {
    "act": {
        "act": {"actor_type": "service", "sub": PLANNER},
        "actor_type": "service",
        "sub": RESEARCHER,
    },
    "aud": ["https://mcp.example.com/mcp"],
    "client_id": RESEARCHER,
    "iss": "http://localhost:9000",
    "sub": ALICE,
}


def test_the_human_survives_two_real_delegation_hops():
    actor = resolve_actor(OBSERVED)

    assert actor["human"] == ALICE


def test_the_outermost_actor_is_the_most_recent_one():
    """AuthPlane nests most-recent-outermost, per RFC 8693 4.1. The agent
    authoritative for the call is the one holding the token now."""
    actor = resolve_actor(OBSERVED)

    assert actor["agent"] == RESEARCHER
    assert actor["chain"] == [RESEARCHER, PLANNER]


def test_it_resolves_from_the_nested_walk_because_no_flat_claims_arrive():
    actor = resolve_actor(OBSERVED)

    assert actor["source"] == "act"
    assert "agent_id" not in OBSERVED and "agent_chain" not in OBSERVED
    assert actor["discrepancy"] is None


def test_actor_type_service_does_not_erase_the_human():
    """The regression that matters most here. Both hops are tagged "service",
    and a consumer that treated that tag as "no human involved" would drop
    alice from a token that names her as the subject."""
    actor = resolve_actor(OBSERVED)

    assert actor["actor_type"] == "service"
    assert actor["human"] == ALICE
    assert actor["agent"] != ALICE


def test_a_single_hop_from_the_same_server_resolves_too():
    single = {**OBSERVED, "act": {"actor_type": "service", "sub": PLANNER},
              "client_id": PLANNER}
    actor = resolve_actor(single)

    assert actor["human"] == ALICE
    assert actor["agent"] == PLANNER
    assert actor["chain"] == [PLANNER]
