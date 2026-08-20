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

# The agent retries a note write on a timeout, and a timeout means the reply was
# lost rather than the write failing, so the endpoint has to answer a repeat
# instead of acting on it again. Whichever of the two runs above wrote the note,
# this one finds it already there.
repeat = post("/note", note_payload(note="A second note that must not be written."))
check("  a repeat is accepted rather than refused", repeat.status_code, 200)
ran += 1
if repeat.status_code == 200 and repeat.json().get("status") == "note_exists":
    print("PASS    and reports that the note was already there")
else:
    failed.append("and reports that the note was already there")
    print("FAIL    and reports that the note was already there")

print("department endpoint")
def dept_payload(**overrides):
    payload = {"ticket_id": TICKET_ID, "created_at": now()}
    payload.update(overrides)
    return payload

check("  unsigned is rejected", post("/department", dept_payload(), sign=False).status_code, 401)
check("  stale timestamp is rejected",
      post("/department", dept_payload(created_at=STALE)).status_code, 401)
check("  unknown ticket is rejected",
      post("/department", dept_payload(ticket_id=ABSENT_TICKET_ID)).status_code, 404)

# The target is not in the request. It comes from the plugin's own config, so a
# body naming a department cannot redirect the move.
extra = post("/department", dept_payload(department="Sales"))
check("  a department named in the body is ignored", extra.status_code, 200)
ran += 1
if extra.status_code == 200 and extra.json().get("to") != "Sales":
    print("PASS    and the ticket goes where the config says")
else:
    failed.append("and the ticket goes where the config says")
    print("FAIL    and the ticket goes where the config says")

response = post("/department", dept_payload())
check("  valid signed write succeeds", response.status_code, 200)
repeat = post("/department", dept_payload())
check("  a repeat is accepted rather than refused", repeat.status_code, 200)
ran += 1
if repeat.status_code == 200 and repeat.json().get("status") == "already_routed":
    print("PASS    and reports the ticket was already there")
else:
    failed.append("and reports the ticket was already there")
    print("FAIL    and reports the ticket was already there")

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
print(f"All {ran} checks passed. Ticket {TICKET_ID} carries one agent note, "
      f"whether or not it already had one, and its priority was changed.")
