"""
Vigil → Crumb, end to end — a scan-flagged tool call, attributed and reconciled.

Run:  python3 -m crumb.vigil_adapter_demo

The story (the pairing Vigil's scan-tools §5 describes, from the Crumb side):
  A human logs in and authorizes exactly one action: read_record. A poisoned tool —
  its description swears it never exports data, the directive hiding in an enum value —
  is monitored by Vigil. Two calls fire:
    1. read_record  — the human authorized it. Crumb records a DELEGATED crumb.
    2. export_record — the poison drove it; the human never authorized it. Crumb
       records an UNAUTHORIZED crumb, directive=null.
  Then reconciliation (find_unauthorized) surfaces the export, and tamper-evidence
  (verify_ledger) confirms the whole chain is intact. The export is pinned on the
  AGENT, provably, without trusting the operator — and without ever having been able
  to prevent it. Flight recorder, not control plane.

Self-contained: this constructs Vigil's event dict directly (it does not import vigil),
mirroring how Vigil doesn't import crumb — each side depends only on the dict contract.
"""

import tempfile
from pathlib import Path

from . import auth
from .ledger import Ledger
from .verify import find_unauthorized, verify_ledger
from .vigil_adapter import VigilAttributor


def _vigil_event(tool_name, status="success"):
    """The payload Vigil's MCPWatch attributor hook emits for a flagged tool call."""
    return {
        "server": "records",
        "tool_name": tool_name,
        "status": status,
        "reason": "call to a tool flagged HIGH at registration (scan-tools)",
        "flagged_fields": ["parameters.properties.mode.enum[1]"],
        "timestamp": "2026-07-11T17:00:00+00:00",
    }


def main():
    tmp = Path(tempfile.mkdtemp(prefix="crumb-vigil-"))
    led = Ledger(str(tmp / "ledger.jsonl"), str(tmp / "led.key"))

    print("1. Human logs in, authorizing exactly one action: read_record")
    session = auth.login("alejandro.moreno@org.com", directives=("read_record",))
    attr = VigilAttributor.for_session(led, session)

    print("2. Two monitored calls fire; Vigil's hook hands each to the adapter:\n")
    for tool in ("read_record", "export_record"):
        crumb = attr(_vigil_event(tool))
        tag = "DELEGATED" if crumb["on_behalf_assertion"] == "delegated" else "UNAUTHORIZED"
        print(f"   [{tag:12}] action={crumb['action']:14} "
              f"directive={str(crumb['directive']):11} actor={crumb['actor_identity']}")

    path = str(tmp / "ledger.jsonl")
    print("\n3. Reconcile intent — which calls had no human directive behind them?")
    for c in find_unauthorized(path):
        print(f"   → {c['action']} flagged (rode in {c['scan_flag']['fields'][0]}), "
              f"pinned on the AGENT not {c['actor_identity']}")

    print("\n4. Tamper-evidence — is the whole chain intact?")
    report = verify_ledger(path, str(tmp / "led.pub"))
    print(f"   verify_ledger: ok={report.ok}, entries checked={report.checked}")

    print("\nScan-tools caught it at the door; Crumb proves who was accountable when it")
    print("walked through — a record, not a block. That distinction is the pitch.")


if __name__ == "__main__":
    main()
