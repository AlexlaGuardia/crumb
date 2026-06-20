"""
The tool the agent calls — and the 'regulated' data behind it.

`read_record` stands in for any action that touches sensitive data (a patient
record, a customer export, a payment). The OpenAI-style schema in TOOLS is what
the model is told it can call. Note what the schema does NOT contain: any notion
of who the acting human is. The protocol has no slot for it.
"""

from __future__ import annotations

from . import tokens

# A tiny stand-in for a regulated datastore (PHI, in this case).
_RECORDS = {
    42: {"id": 42, "name": "Dana Okafor", "dob": "1979-03-02", "dx": "Type 2 diabetes"},
    43: {"id": 43, "name": "Sam Reyes", "dob": "1991-11-20", "dx": "Hypertension"},
}

# The function-calling schema handed to the model. Pure capability description —
# no identity, by design of the protocol.
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "read_record",
            "description": "Read a patient record by id.",
            "parameters": {
                "type": "object",
                "properties": {
                    "record_id": {"type": "integer", "description": "The record id."}
                },
                "required": ["record_id"],
            },
        },
    }
]


def read_record(record_id: int, token: str) -> dict:
    """Return a patient record — but only to a caller with a valid delegation token.

    The token arrives out-of-band from the gateway, never from the model. The
    resource server verifies it before serving data, which is what proves a real
    human (`claims["sub"]`) is behind the call. No token, no data.
    """
    tokens.verify_delegation(token, resource="read_record")
    return _RECORDS[record_id]
