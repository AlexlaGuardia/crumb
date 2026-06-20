"""
The tool the agent calls — and the 'regulated' data behind it.

`read_record` stands in for any action that touches sensitive data (a patient
record, a customer export, a payment). The OpenAI-style schema in TOOLS is what
the model is told it can call. Note what the schema does NOT contain: any notion
of who the acting human is. The protocol has no slot for it.
"""

from __future__ import annotations

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


def read_record(record_id: int) -> dict:
    """Return a patient record. Raises KeyError if it doesn't exist."""
    return _RECORDS[record_id]
