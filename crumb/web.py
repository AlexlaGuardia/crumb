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
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

from . import anchor, auth
from .agent import ToolCall
from .gateway import Gateway
from .ledger import Ledger, canonical
from .verify import verify_ledger

LEDGER = "data/ledger.jsonl"
KEY = "data/ledger.key"
PUB = "data/ledger.pub"
ANCHORS = "data/anchors.jsonl"
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
        session = auth.login(who)
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
    return (HERE / "static" / "index.html").read_text()


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
