import hashlib
import hmac
import json
import os
import sys
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv
load_dotenv()

import requests

URL = os.getenv("OSTICKET_WRITE_URL")
SECRET = os.getenv("TRIAGE_WRITE_SECRET")
if not URL or not SECRET:
    raise SystemExit("OSTICKET_WRITE_URL and TRIAGE_WRITE_SECRET must both be set")

if len(sys.argv) != 2 or not sys.argv[1].isdigit():
    raise SystemExit(
        "usage: python verify_writeback.py <ticket_id>\n\n"
        "Exercises the plugin's write endpoint against a running stack. The\n"
        "last case writes a real internal note to the ticket you name, and the\n"
        "endpoint has no delete operation, so pick a ticket you don't mind\n"
        "marking. Reproduces the table in docs/TESTING.md."
    )

TICKET_ID = int(sys.argv[1])

# Assumed not to exist, which is what makes the 404 case meaningful. If it ever
# does, that check fails loudly rather than silently passing.
ABSENT_TICKET_ID = 99999

# Deliberately bypasses osticket_client so the endpoint is tested rather than
# the client, and so the kill switch does not decide whether this runs.
def post(payload, secret=SECRET, signature=None, sign=True):
    body = json.dumps(payload).encode()
    headers = {"Content-Type": "application/json"}
    if signature is not None:
        headers["X-Triage-Signature"] = signature
    elif sign:
        headers["X-Triage-Signature"] = "sha256=" + hmac.new(
            secret.encode(), body, hashlib.sha256
        ).hexdigest()
    return requests.post(URL, data=body, headers=headers, timeout=15)

def now():
    return datetime.now(timezone.utc).isoformat()

def base(**overrides):
    payload = {
        "ticket_id": TICKET_ID,
        "title": "AI Triage",
        "note": "Write-back verification.",
        "created_at": now(),
    }
    payload.update(overrides)
    return payload

failed = []

def check(name, got, expected):
    ok = got == expected
    if not ok:
        failed.append(name)
    print(f"{'PASS' if ok else 'FAIL'}  {name}: HTTP {got}, expected {expected}")

stale = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
no_note = {k: v for k, v in base().items() if k != "note"}

check("unsigned is rejected", post(base(), sign=False).status_code, 401)
check("wrong signature is rejected", post(base(), signature="sha256=" + "0" * 64).status_code, 401)
check("wrong secret is rejected", post(base(), secret="not-the-secret").status_code, 401)
check("stale timestamp is rejected", post(base(created_at=stale)).status_code, 401)
check("missing note is rejected", post(no_note).status_code, 400)
check("unknown ticket is rejected", post(base(ticket_id=ABSENT_TICKET_ID)).status_code, 404)

response = post(base(note="Write-back verification. Signed request, note written by the agent."))
check("valid signed write succeeds", response.status_code, 200)
if response.status_code == 200:
    print(f"      {response.text.strip()}")

print()
if failed:
    print(f"FAILED: {', '.join(failed)}")
    sys.exit(1)
print(f"All 7 cases passed. A note was written to ticket {TICKET_ID}; confirm it "
      f"in the ticket thread, where it should appear as an internal note.")
