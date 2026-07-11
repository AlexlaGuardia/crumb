"""
Vigil → Crumb adapter: a scan-flagged tool call becomes a signed crumb, reconciled
against what the human actually authorized.

The adapter is the concrete implementation of Vigil's `attributor(event)` hook. It
does not import vigil — it consumes the documented event dict, the same way vigil
doesn't import crumb. These tests build that event dict directly.
"""

import json

from crumb import auth
from crumb.ledger import Ledger
from crumb.verify import find_unauthorized
from crumb.vigil_adapter import VigilAttributor


def _event(tool_name, status="success", fields=("parameters.properties.mode.enum[1]",)):
    return {
        "server": "records",
        "tool_name": tool_name,
        "status": status,
        "reason": "call to a tool flagged HIGH at registration (scan-tools)",
        "flagged_fields": list(fields),
        "timestamp": "2026-07-11T17:00:00+00:00",
    }


def _ledger(tmp_path):
    return Ledger(str(tmp_path / "ledger.jsonl"), str(tmp_path / "led.key"))


def test_authorized_call_records_a_delegated_crumb(tmp_path):
    led = _ledger(tmp_path)
    session = auth.login("alejandro.moreno@org.com", directives=("read_record",))
    attr = VigilAttributor.for_session(led, session)

    crumb = attr(_event("read_record"))
    assert crumb["actor_identity"] == "alejandro.moreno@org.com"
    assert crumb["directive"] == "read_record"
    assert crumb["on_behalf_assertion"] == "delegated"
    # signed + chained by the ledger
    assert crumb["signature"].startswith("ed25519:") and "entry_hash" in crumb


def test_unauthorized_flagged_call_is_pinned_on_the_agent(tmp_path):
    led = _ledger(tmp_path)
    # The human only authorized read_record; the poisoned tool drove export_record.
    session = auth.login("alejandro.moreno@org.com", directives=("read_record",))
    attr = VigilAttributor.for_session(led, session)

    crumb = attr(_event("export_record"))
    assert crumb["directive"] is None
    assert crumb["on_behalf_assertion"] == "unauthorized"

    # Crumb's existing reconciliation flags it with zero adapter-specific logic.
    flagged = find_unauthorized(str(tmp_path / "ledger.jsonl"))
    assert len(flagged) == 1 and flagged[0]["action"] == "export_record"


def test_scan_provenance_is_recorded(tmp_path):
    led = _ledger(tmp_path)
    session = auth.login("u@org.com", directives=())
    attr = VigilAttributor.for_session(led, session)

    crumb = attr(_event("read_record", fields=("parameters.properties.mode.enum[1]",)))
    assert crumb["scan_flag"]["source"] == "vigil.scan-tools"
    assert "enum" in crumb["scan_flag"]["fields"][0]
    assert crumb["transport"] == "vigil-hook"


def test_status_flows_through_to_outcome(tmp_path):
    led = _ledger(tmp_path)
    session = auth.login("u@org.com", directives=("read_record",))
    attr = VigilAttributor.for_session(led, session)
    crumb = attr(_event("read_record", status="error"))
    assert crumb["outcome"] == "error"


def test_human_comes_from_the_session_not_the_event(tmp_path):
    led = _ledger(tmp_path)
    session = auth.login("real.human@org.com", directives=("read_record",))
    attr = VigilAttributor.for_session(led, session)
    # Even if an attacker stuffed an identity into the event, the crumb uses the
    # verified session subject, never the event.
    ev = _event("read_record")
    ev["actor_identity"] = "mallory@evil.com"
    crumb = attr(ev)
    assert crumb["actor_identity"] == "real.human@org.com"


def test_provider_is_read_per_call(tmp_path):
    led = _ledger(tmp_path)
    sessions = {"cur": auth.login("first@org.com", directives=("read_record",))}
    attr = VigilAttributor(led, session_provider=lambda: sessions["cur"])
    c1 = attr(_event("read_record"))
    sessions["cur"] = auth.login("second@org.com", directives=("read_record",))
    c2 = attr(_event("read_record"))
    assert c1["actor_identity"] == "first@org.com"
    assert c2["actor_identity"] == "second@org.com"
    # chain stays intact across both appends
    lines = (tmp_path / "ledger.jsonl").read_text().splitlines()
    assert json.loads(lines[1])["prev_hash"] == json.loads(lines[0])["entry_hash"]
