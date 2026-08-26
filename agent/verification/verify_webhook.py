import hashlib
import hmac
import json
import os
import sys
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv
load_dotenv()

import requests

URL = os.getenv("TRIAGE_WEBHOOK_URL", "http://127.0.0.1:8000/webhook/ticket")
SECRET = os.getenv("TRIAGE_HMAC_SECRET")
if not SECRET:
    raise SystemExit("TRIAGE_HMAC_SECRET must be set")

if len(sys.argv) != 2 or not sys.argv[1].isdigit():
    raise SystemExit(
        "usage: python verification/verify_webhook.py <processed_ticket_id>\n\n"
        "Exercises the gate on the endpoint osTicket calls, against a running\n"
        "agent. Every case here is refused before the agent does any work, so\n"
        "nothing is classified, written or alerted.\n\n"
        "Name a ticket the agent finished. It is used to prove duplicate\n"
        "suppression, which needs an ID the store has seen. An ID it has never\n"
        "seen would be claimed and queue real work, and one the agent was\n"
        "interrupted partway through would be resumed rather than refused,\n"
        "which queues the actions that ticket is still owed.\n\n"
        "Set TRIAGE_WEBHOOK_URL if the agent is not on 127.0.0.1:8000. It has\n"
        "to match the address the agent bound to, not the one osTicket uses.\n\n"
        "Reproduces the table in docs/verification.md."
    )

PROCESSED_TICKET_ID = int(sys.argv[1])

def send(payload, secret=SECRET, signature=None, sign=True, raw=None):
    body = raw if raw is not None else json.dumps(payload).encode()
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

def fresh(**overrides):
    """A request that would be accepted, before the case under test breaks it."""
    payload = {"ticket_id": PROCESSED_TICKET_ID, "created_at": now(),
               "ticket_number": "VERIFY", "subject": "verifier",
               "message": "verifier"}
    payload.update(overrides)
    return payload

failed = []
ran = 0

def check(name, got, expected):
    global ran
    ran += 1
    ok = got == expected
    if not ok:
        failed.append(name)
    print(f"{'PASS' if ok else 'FAIL'}  {name}: HTTP {got}, expected {expected}")

def check_value(name, got, expected):
    """For the one assertion that reads a field rather than a status code."""
    global ran
    ran += 1
    ok = got == expected
    if not ok:
        failed.append(name)
    print(f"{'PASS' if ok else 'FAIL'}  {name}: {got!r}, expected {expected!r}")

try:
    requests.post(URL, data=b"{}", timeout=5)
except requests.exceptions.RequestException:
    raise SystemExit(
        f"No agent answering at {URL}. Start it, or set TRIAGE_WEBHOOK_URL."
    )

# The gate runs in a fixed order, so each case has to be the only thing wrong
# with its request. A body that is both unsigned and malformed only ever proves
# the signature check, because nothing downstream of it runs.

print("signature")
check("  no signature header is rejected",
      send(fresh(), sign=False).status_code, 401)
check("  a wrong signature is rejected",
      send(fresh(), signature="sha256=" + "0" * 64).status_code, 401)
check("  a signature over the wrong secret is rejected",
      send(fresh(), secret="not-the-secret").status_code, 401)
check("  a signature missing its prefix is rejected",
      send(fresh(), signature="0" * 64).status_code, 401)
# Sent as raw bytes because the header has to reach the agent undecoded. An
# ASCII-only client cannot produce this case, and the timing-safe comparison
# raises on text outside ASCII rather than returning False, so before the
# length and alphabet check this answered 500 and recorded no rejection.
check("  a signature carrying a non-ASCII byte is rejected",
      send(fresh(), signature="sha256=\xe9".encode("latin-1")).status_code, 401)
check("  a signature of the wrong length is rejected",
      send(fresh(), signature="sha256=abc").status_code, 401)

print("body")
check("  a body that is not JSON is rejected",
      send(None, raw=b"not json at all").status_code, 400)
# A JSON array parses but is not a ticket, and .get() on it would raise rather
# than reject, so the type is checked before anything reads a field.
check("  a JSON array is rejected",
      send(None, raw=b'["ticket_id", 1]').status_code, 400)
check("  a JSON string is rejected",
      send(None, raw=b'"ticket_id"').status_code, 400)

print("freshness")
stale = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
check("  a timestamp 10 minutes old is rejected",
      send(fresh(created_at=stale)).status_code, 401)
# Beyond the 60 second clock-skew allowance, so a replay cannot buy itself a
# window by claiming to be from the future.
ahead = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
check("  a timestamp 5 minutes ahead is rejected",
      send(fresh(created_at=ahead)).status_code, 401)
check("  a missing timestamp is rejected",
      send(fresh(created_at=None)).status_code, 401)
check("  an unparseable timestamp is rejected",
      send(fresh(created_at="yesterday")).status_code, 401)

print("ticket id")
check("  a missing ticket id is rejected",
      send(fresh(ticket_id=None)).status_code, 400)
# isinstance(True, int) is True in Python, so a bool reaches the numeric check
# and has to be refused before it.
check("  a boolean ticket id is rejected",
      send(fresh(ticket_id=True)).status_code, 400)
check("  a list ticket id is rejected",
      send(fresh(ticket_id=[1])).status_code, 400)
check("  an object ticket id is rejected",
      send(fresh(ticket_id={"id": 1})).status_code, 400)

print("replay")
first = send(fresh())
check("  a ticket already finished is refused", first.status_code, 200)
check_value("  and says why", first.json().get("status"), "duplicate")
# Signed correctly and inside the freshness window, which is what makes this a
# replay rather than a forgery. Only the store separates it from a real request.
again = send(fresh())
check("  refused every time, not just once", again.status_code, 200)

if first.status_code == 202:
    print()
    print(f"  Ticket {PROCESSED_TICKET_ID} was resumed, not refused, so the agent")
    print("  never finished it and has now been handed the rest of its actions.")
    print("  That is the agent behaving correctly and the verifier being pointed")
    print("  at the wrong ticket. Name one the agent finished.")

print()
if failed:
    print(f"FAILED: {', '.join(failed)}")
    sys.exit(1)
print(f"All {ran} checks passed. Nothing was classified, written or alerted.")
print("The accepted path is covered by the end-to-end runs in docs/verification.md,")
print("because a 202 queues real work against a real ticket.")
