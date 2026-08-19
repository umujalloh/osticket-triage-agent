import hashlib
import hmac
import json
import os
import sys
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv
load_dotenv()

import requests

URL_BASE = os.getenv("OSTICKET_WRITE_URL")
SECRET = os.getenv("TRIAGE_WRITE_SECRET")
if not URL_BASE or not SECRET:
    raise SystemExit("OSTICKET_WRITE_URL and TRIAGE_WRITE_SECRET must both be set")

if len(sys.argv) != 2 or not sys.argv[1].isdigit():
    raise SystemExit(
        "usage: python verification/verify_writeback.py <ticket_id>\n\n"
        "Exercises the plugin's write endpoints against a running stack. Two\n"
        "cases change the ticket you name, writing a real note and setting its\n"
        "priority, and the endpoints have no undo, so pick a ticket you don't\n"
        "mind marking. Reproduces the table in docs/TESTING.md."
    )

TICKET_ID = int(sys.argv[1])

# Assumed not to exist, which is what makes the 404 case meaningful. If it ever
# does, that check fails loudly rather than silently passing.
ABSENT_TICKET_ID = 99999

def post(operation, payload, secret=SECRET, signature=None, sign=True):
    body = json.dumps(payload).encode()
    headers = {"Content-Type": "application/json"}
    if signature is not None:
        headers["X-Triage-Signature"] = signature
    elif sign:
        headers["X-Triage-Signature"] = "sha256=" + hmac.new(
            secret.encode(), body, hashlib.sha256
        ).hexdigest()
    return requests.post(URL_BASE.rstrip("/") + operation, data=body,
                         headers=headers, timeout=15)

def now():
    return datetime.now(timezone.utc).isoformat()

STALE = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()

failed = []
ran = 0

def check(name, got, expected):
    global ran
    ran += 1
    ok = got == expected
    if not ok:
        failed.append(name)
    print(f"{'PASS' if ok else 'FAIL'}  {name}: HTTP {got}, expected {expected}")

def note_payload(**overrides):
    payload = {"ticket_id": TICKET_ID, "title": "AI Triage",
               "note": "Write-back verification.", "created_at": now()}
    payload.update(overrides)
    return payload

def priority_payload(**overrides):
    payload = {"ticket_id": TICKET_ID, "priority": "normal", "created_at": now()}
    payload.update(overrides)
    return payload

print("note endpoint")
check("  unsigned is rejected", post("/note", note_payload(), sign=False).status_code, 401)
check("  wrong signature is rejected",
      post("/note", note_payload(), signature="sha256=" + "0" * 64).status_code, 401)
check("  wrong secret is rejected",
      post("/note", note_payload(), secret="not-the-secret").status_code, 401)
check("  stale timestamp is rejected",
      post("/note", note_payload(created_at=STALE)).status_code, 401)
check("  missing note is rejected",
      post("/note", {k: v for k, v in note_payload().items() if k != "note"}).status_code, 400)
check("  unknown ticket is rejected",
      post("/note", note_payload(ticket_id=ABSENT_TICKET_ID)).status_code, 404)

response = post("/note", note_payload(
    note="Write-back verification. Signed request, note written by the agent."))
check("  valid signed write succeeds", response.status_code, 200)

print("priority endpoint")
check("  unsigned is rejected", post("/priority", priority_payload(), sign=False).status_code, 401)
check("  stale timestamp is rejected",
      post("/priority", priority_payload(created_at=STALE)).status_code, 401)
check("  missing priority is rejected",
      post("/priority", {k: v for k, v in priority_payload().items()
                         if k != "priority"}).status_code, 400)
check("  an unknown priority name is rejected",
      post("/priority", priority_payload(priority="urgent-ish")).status_code, 400)
check("  a priority id instead of a name is rejected",
      post("/priority", priority_payload(priority=4)).status_code, 400)
check("  unknown ticket is rejected",
      post("/priority", priority_payload(ticket_id=ABSENT_TICKET_ID)).status_code, 404)

response = post("/priority", priority_payload(priority="high"))
check("  valid signed write succeeds", response.status_code, 200)
if response.status_code == 200:
    body = response.json()
    print(f"        priority {body.get('from')} to {body.get('to')}")
    ran += 1
    if body.get("to") != "high":
        failed.append("the response reports the new priority")
        print("FAIL  the response reports the new priority")
    else:
        print("PASS  the response reports the new priority")

print()
if failed:
    print(f"FAILED: {', '.join(failed)}")
    sys.exit(1)
print(f"All {ran} checks passed. Ticket {TICKET_ID} gained a note and its "
      f"priority was changed.")
