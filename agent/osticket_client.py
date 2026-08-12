import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timezone

import requests

from writes import writes_enabled

OSTICKET_WRITE_URL = os.getenv("OSTICKET_WRITE_URL")
TRIAGE_WRITE_SECRET = os.getenv("TRIAGE_WRITE_SECRET")
if not OSTICKET_WRITE_URL or not TRIAGE_WRITE_SECRET:
    raise RuntimeError("OSTICKET_WRITE_URL and TRIAGE_WRITE_SECRET must both be set")

WRITTEN = "written"
SKIPPED = "skipped_writes_disabled"

class OsTicketWriteError(Exception):
    def __init__(self, failure_type: str, message: str):
        self.failure_type = failure_type
        super().__init__(message)

def _sign(body: bytes) -> str:
    return "sha256=" + hmac.new(
        TRIAGE_WRITE_SECRET.encode(), body, hashlib.sha256
    ).hexdigest()

def write_note(ticket_id: int, note: str, title: str = "AI Triage") -> str:
    """Writes an internal note onto a ticket through the plugin's endpoint.

    Returns WRITTEN on success and SKIPPED when the kill switch is off. The
    switch is checked here rather than left to callers, so no future write path
    can forget it. Raises OsTicketWriteError on failure and never reports a
    write that did not happen.
    """
    if not writes_enabled():
        return SKIPPED

    payload = {
        "ticket_id": ticket_id,
        "title": title,
        "note": note,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    body = json.dumps(payload).encode()
    headers = {
        "Content-Type": "application/json",
        "X-Triage-Signature": _sign(body),
    }

    last_error = None
    for attempt in range(3):
        try:
            response = requests.post(
                OSTICKET_WRITE_URL, data=body, headers=headers, timeout=10
            )
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            last_error = ("server_down", f"Could not reach osTicket: {e}")
            time.sleep([2, 5, 10][attempt])
            continue
        except requests.exceptions.RequestException as e:
            raise OsTicketWriteError("unknown", f"{type(e).__name__}: {e}")

        if response.status_code == 200:
            return WRITTEN
        if response.status_code == 401:
            raise OsTicketWriteError("auth_failure", "osTicket rejected the write signature")
        if response.status_code in (400, 404):
            raise OsTicketWriteError(
                "bad_request", f"osTicket refused the write: HTTP {response.status_code} {response.text[:200]}"
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
