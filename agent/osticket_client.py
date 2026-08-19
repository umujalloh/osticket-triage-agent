import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timezone

import requests

from writes import writes_enabled

# Base of the endpoint family the triage plugin registers. Operations hang off
# it, so adding one does not add another value to configure.
OSTICKET_WRITE_URL = os.getenv("OSTICKET_WRITE_URL")
TRIAGE_WRITE_SECRET = os.getenv("TRIAGE_WRITE_SECRET")
if not OSTICKET_WRITE_URL or not TRIAGE_WRITE_SECRET:
    raise RuntimeError("OSTICKET_WRITE_URL and TRIAGE_WRITE_SECRET must both be set")

DONE = "done"
# The endpoint found a note from the agent already on the ticket and did not
# write a second one. Reached by a retry after a timeout, where the reply was
# lost rather than the write failing.
ALREADY_WRITTEN = "already_written"
SKIPPED = "skipped_writes_disabled"

class OsTicketWriteError(Exception):
    def __init__(self, failure_type: str, message: str):
        self.failure_type = failure_type
        super().__init__(message)

def _sign(body: bytes) -> str:
    return "sha256=" + hmac.new(
        TRIAGE_WRITE_SECRET.encode(), body, hashlib.sha256
    ).hexdigest()

def _post(operation: str, payload: dict) -> dict:
    """Signs and sends one write, retrying only what a retry can fix.

    Returns the endpoint's parsed response. Raises OsTicketWriteError on
    failure and never reports a write that did not happen.
    """
    payload = dict(payload, created_at=datetime.now(timezone.utc).isoformat())
    body = json.dumps(payload).encode()
    url = OSTICKET_WRITE_URL.rstrip("/") + operation
    headers = {"Content-Type": "application/json", "X-Triage-Signature": _sign(body)}

    last_error = None
    for attempt in range(3):
        try:
            response = requests.post(url, data=body, headers=headers, timeout=10)
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            last_error = ("server_down", f"Could not reach osTicket: {e}")
            time.sleep([2, 5, 10][attempt])
            continue
        except requests.exceptions.RequestException as e:
            raise OsTicketWriteError("unknown", f"{type(e).__name__}: {e}")

        if response.status_code == 200:
            try:
                return response.json()
            except ValueError as e:
                raise OsTicketWriteError("bad_output", f"Could not parse the response: {e}")
        if response.status_code == 401:
            raise OsTicketWriteError("auth_failure", "osTicket rejected the write signature")
        if response.status_code in (400, 404):
            raise OsTicketWriteError(
                "bad_request",
                f"osTicket refused the write: HTTP {response.status_code} {response.text[:200]}",
            )
        if response.status_code in (429, 503):
            last_error = ("rate_limited", f"osTicket is unavailable (HTTP {response.status_code})")
            time.sleep([5, 15, 30][attempt])
            continue
        raise OsTicketWriteError(
            "unknown", f"Unexpected osTicket response: HTTP {response.status_code}"
        )

    failure_type, message = last_error
    raise OsTicketWriteError(failure_type, message)

# The kill switch is checked in this module rather than left to callers, so no
# future write path can forget it.
def write_note(ticket_id: int, note: str, title: str = "AI Triage") -> str:
    """Writes an internal note.

    Returns DONE, ALREADY_WRITTEN when the ticket already carried one, or
    SKIPPED when writes are off. The middle case is not a failure, and the
    caller records the note as done either way, but the two are distinguished
    so a retry that landed on an existing note is visible rather than looking
    like a fresh write.
    """
    if not writes_enabled():
        return SKIPPED
    result = _post("/note", {"ticket_id": ticket_id, "title": title, "note": note})
    return ALREADY_WRITTEN if result.get("status") == "note_exists" else DONE

def set_priority(ticket_id: int, priority: str) -> dict:
    """Sets the ticket priority.

    Returns the outcome with the value it replaced, so the audit trail records
    what the agent overwrote rather than only what it chose.
    """
    if not writes_enabled():
        return {"outcome": SKIPPED, "from": None, "to": priority}
    result = _post("/priority", {"ticket_id": ticket_id, "priority": priority})
    return {"outcome": DONE, "from": result.get("from"), "to": result.get("to")}
