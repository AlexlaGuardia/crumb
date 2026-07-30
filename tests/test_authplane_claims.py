"""
Consuming an authorization server's delegation claims at call time.

Crumb's own minter emits plain RFC 8693: the human as `sub`, the actor nested
under `act`. A production AS may stamp more. AuthPlane, for one, mirrors the
chain into flat `agent_id` / `agent_chain` claims specifically so a resource
server reading identity on EVERY call doesn't walk the nested tree per request,
and tags the holder with `actor_type`.

These tests pin the consume side against those shapes. The properties that
matter, and that must hold whichever representation a token carries:

  - `sub` is the human, always, however many hops the token made.
  - The outermost actor is the one authoritative for the call.
  - A token with no actor at all is a service account and loses the human — that
    is the gap, and it must be reported rather than papered over.
  - When a token's two representations of its own chain disagree, the resolver
    says so. A flight recorder that normalizes away a contradiction has thrown
    out the only detail worth recording.
"""

from __future__ import annotations

from crumb.tokens import resolve_actor


def _authplane(sub="alice", agent_id=None, agent_chain=None, act=None,
               actor_type=None, **extra):
    """An AuthPlane-shaped claim set, as a resource server sees it post-verify."""
    claims = {"sub": sub, "aud": "read_record", "iss": "https://as.authplane.ai"}
    if agent_id is not None:
        claims["agent_id"] = agent_id
    if agent_chain is not None:
        claims["agent_chain"] = agent_chain
    if act is not None:
        claims["act"] = act
    if actor_type is not None:
        claims["actor_type"] = actor_type
    claims.update(extra)
    return claims


# --- the flat fast path -----------------------------------------------------

def test_flat_agent_id_is_the_anchor_without_walking_the_tree():
    """The whole point of the flat claim: one lookup, no nested descent."""
    actor = resolve_actor(_authplane(agent_id="support-agent"))

    assert actor["human"] == "alice"        # sub stays the person
    assert actor["agent"] == "support-agent"
    assert actor["source"] == "flat"
    assert actor["discrepancy"] is None


def test_flat_chain_most_recent_first_is_taken_as_is():
    actor = resolve_actor(_authplane(
        agent_id="planner", agent_chain=["planner", "researcher"],
    ))

    assert actor["agent"] == "planner"      # outermost = authoritative
    assert actor["chain"] == ["planner", "researcher"]
    assert actor["discrepancy"] is None


def test_flat_chain_emitted_oldest_first_is_normalized_not_guessed():
    """We don't get to assume the AS's ordering. `agent_id` is the known-
    authoritative actor, so whichever end it sits on decides the direction."""
    actor = resolve_actor(_authplane(
        agent_id="planner", agent_chain=["researcher", "planner"],
    ))

    assert actor["chain"] == ["planner", "researcher"]   # flipped to our convention
    assert actor["agent"] == "planner"
    assert actor["discrepancy"] is None


def test_single_hop_flat_chain_is_orientation_free():
    actor = resolve_actor(_authplane(agent_id="solo", agent_chain=["solo"]))

    assert actor["chain"] == ["solo"]
    assert actor["discrepancy"] is None


# --- the nested fallback ----------------------------------------------------

def test_plain_rfc8693_issuer_still_resolves_via_the_nested_walk():
    """No flat mirrors — a stock RFC 8693 AS, or Crumb's own dev minter."""
    actor = resolve_actor(_authplane(
        act={"sub": "planner", "act": {"sub": "researcher"}},
    ))

    assert actor["human"] == "alice"
    assert actor["agent"] == "planner"
    assert actor["chain"] == ["planner", "researcher"]
    assert actor["source"] == "act"


def test_flat_and_nested_agreeing_reports_no_discrepancy():
    actor = resolve_actor(_authplane(
        agent_id="planner",
        agent_chain=["planner", "researcher"],
        act={"sub": "planner", "act": {"sub": "researcher"}},
    ))

    assert actor["source"] == "flat"        # flat answers; it's what it's for
    assert actor["chain"] == ["planner", "researcher"]
    assert actor["discrepancy"] is None


# --- the contradictions, which are the point --------------------------------

def test_flat_disagreeing_with_nested_is_reported_not_smoothed():
    """Same token, same AS, two representations of one chain that don't match.
    Whatever caused it, the resolver must surface it — this is precisely the
    class of thing a per-call record exists to catch."""
    actor = resolve_actor(_authplane(
        agent_id="planner",
        agent_chain=["planner", "researcher"],
        act={"sub": "planner", "act": {"sub": "ghost"}},   # inner hop differs
    ))

    assert actor["agent"] == "planner"      # still answerable
    assert actor["discrepancy"] is not None
    assert "researcher" in actor["discrepancy"] and "ghost" in actor["discrepancy"]


def test_chain_that_matches_neither_end_is_flagged_undecidable():
    actor = resolve_actor(_authplane(
        agent_id="planner", agent_chain=["researcher", "auditor"],
    ))

    assert actor["discrepancy"] is not None
    assert "orientation undecidable" in actor["discrepancy"]


# --- the service-account gap ------------------------------------------------

def test_no_actor_at_all_loses_the_human_and_says_so():
    """The token most MCP deployments actually send. Byte-identical wire, and
    the server can prove a bot called it but never which person."""
    actor = resolve_actor(_authplane(sub="svc-records-bot"))

    assert actor["human"] is None
    assert actor["agent"] == "svc-records-bot"
    assert actor["chain"] == []
    assert actor["actor_type"] == "service"
    assert actor["source"] == "none"


def test_actor_type_agent_does_not_displace_the_human():
    """`actor_type` describes the holder, not whether a person is behind it."""
    actor = resolve_actor(_authplane(agent_id="support-agent", actor_type="agent"))

    assert actor["human"] == "alice"
    assert actor["actor_type"] == "agent"


def test_actor_type_reads_from_inside_act_as_well_as_top_level():
    """Prose spelled it `act.actor_type`; the SDK reference lists it flat.
    A resource server doesn't get to pick which one the AS meant."""
    nested = resolve_actor(_authplane(act={"sub": "a1", "actor_type": "service"}))
    flat = resolve_actor(_authplane(agent_id="a1", actor_type="service"))

    assert nested["actor_type"] == "service"
    assert flat["actor_type"] == "service"
    # A service HOLDING a delegated token still carries the human that delegated.
    assert nested["human"] == "alice" and flat["human"] == "alice"


# --- refusing to invent an actor -------------------------------------------
#
# These are regressions. The first cut of the resolver returned `agent = sub`
# whenever no actor resolved, which is right only when `sub` really is the bot.
# On a token that carried actor claims we couldn't read, it recorded the HUMAN as
# the agent and reported the call as a service account — a person named as the
# bot that acted, signed into an append-only ledger. That is the precise
# inversion this project exists to prevent, so each door into it gets a test.

def test_flat_chain_without_an_agent_id_still_names_the_agent():
    """Regression: an AS that stamps `agent_chain` but no `agent_id` used to
    resolve as a service account with alice recorded as the bot."""
    actor = resolve_actor(_authplane(agent_chain=["planner", "researcher"]))

    assert actor["human"] == "alice"
    assert actor["agent"] == "planner"
    assert actor["chain"] == ["planner", "researcher"]


def test_act_without_a_sub_is_unresolved_not_a_service_account():
    """RFC 8693 permits an actor identified by claims other than `sub`. We can't
    name that actor — but the token plainly carries one, so `sub` is still the
    human and must not be relabelled as the agent."""
    actor = resolve_actor(_authplane(act={"actor_type": "agent"}))

    assert actor["human"] == "alice"     # the human survives
    assert actor["agent"] is None        # and we refuse to invent an agent
    assert actor["source"] == "unresolved"
    assert actor["discrepancy"] is not None


def test_malformed_actor_claims_never_name_the_human_as_the_agent():
    for claims in (
        _authplane(act=[{"sub": "x"}]),          # act as a list
        _authplane(agent_id=7),                  # non-string id
        _authplane(agent_id="   "),              # blank id
    ):
        actor = resolve_actor(claims)
        assert actor["agent"] != "alice", claims
        assert actor["human"] == "alice", claims
        assert actor["source"] == "unresolved", claims


def test_non_string_chain_entries_are_refused_not_recorded():
    """A dict is not an agent id. Writing one into a signed record would be
    fabricating an actor out of malformed input."""
    actor = resolve_actor(_authplane(agent_id="planner",
                                     agent_chain=[{"a": 1}, None]))

    assert actor["agent"] == "planner"       # the readable claim still answers
    assert actor["chain"] == ["planner"]     # the garbage chain is dropped
    assert actor["discrepancy"] is not None


def test_actor_at_both_ends_of_the_chain_is_flagged_ambiguous():
    """An agent that delegated onward and was handed control back sits at both
    ends. Either reading puts it outermost while the hops between run opposite
    ways, so the order is genuinely undecidable."""
    actor = resolve_actor(_authplane(agent_id="A",
                                     agent_chain=["A", "B", "C", "A"]))

    assert actor["agent"] == "A"
    assert "ambiguous" in actor["discrepancy"]


def test_a_symmetric_round_trip_chain_is_not_flagged():
    """A -> B -> A reads the same both ways; there is nothing to be unsure of."""
    actor = resolve_actor(_authplane(agent_id="A", agent_chain=["A", "B", "A"]))

    assert actor["discrepancy"] is None


# --- end to end, over the resource server ----------------------------------

def test_resource_server_resolves_an_authplane_shaped_token(monkeypatch):
    """The full consume path: a verified bearer in, attribution out, at the
    point the tool actually runs."""
    import jwt

    from crumb import mcp_server, tokens

    secret = "0" * 64   # >=32 bytes; HS256 warns below that
    monkeypatch.setattr(tokens, "_ENV_SECRET", secret)

    token = jwt.encode(
        _authplane(agent_id="planner", agent_chain=["researcher", "planner"],
                   act={"sub": "planner", "act": {"sub": "researcher"}}),
        secret, algorithm="HS256",
    )
    resp = mcp_server.handle(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
         "params": {"name": "read_record", "arguments": {"record_id": 42}}},
        bearer=token,
    )

    actor = resp["result"]["_actor"]
    assert actor["human"] == "alice"
    assert actor["agent"] == "planner"
    assert actor["chain"] == ["planner", "researcher"]
    assert actor["discrepancy"] is None
