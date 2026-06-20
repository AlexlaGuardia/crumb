"""
Crumb web — the timeline view (P4).

One small FastAPI app, no build step. It serves a self-contained HTML timeline
and a thin JSON API over the same ledger the CLI writes. The page lets a visitor
seed a few crumbs, then TAMPER one and watch verification flip from VERIFIED to
MISMATCH live — the P2 money shot, in a browser.

Run: uvicorn crumb.web:app --host 127.0.0.1 --port 8730
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

from . import auth
from .agent import ToolCall
from .gateway import Gateway
from .ledger import Ledger
from .verify import verify_ledger

LEDGER = "data/ledger.jsonl"
KEY = "data/ledger.key"
PUB = "data/ledger.pub"
HERE = Path(__file__).parent
AGENT_ID = "crumb-agent-1"

# A realistic mix: two humans, both transports, one denied call.
_SEED = [
    ("alice", "openai", 42),
    ("bob", "mcp", 43),
    ("carol", "openai", 42),
    ("alice", "mcp", 99),   # record 99 doesn't exist → denied
    ("bob", "openai", 43),
]

app = FastAPI(title="Crumb", docs_url=None, redoc_url=None)


def _gateway() -> Gateway:
    return Gateway(ledger=Ledger(path=LEDGER, key_path=KEY), agent_id=AGENT_ID)


def _seed() -> None:
    gw = _gateway()
    gw.ledger.reset()
    for who, transport, record_id in _SEED:
        session = auth.login(who)
        call = ToolCall(name="read_record", arguments={"record_id": record_id})
        gw.dispatch(session, call, transport=transport)


def _read_ledger() -> list[dict]:
    p = Path(LEDGER)
    if not p.exists():
        return []
    return [json.loads(ln) for ln in p.read_text().splitlines() if ln.strip()]


@app.on_event("startup")
def _startup() -> None:
    _seed()  # every (re)start comes up on a clean, deterministic demo ledger


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
