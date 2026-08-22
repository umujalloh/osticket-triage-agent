"""Checks that a ticket the agent accepted and never finished gets finished.

The webhook answers 202 before the actions run, so a crash between the two
leaves a ticket osTicket believes was delivered. The plugin will not resend it,
because from its side the send succeeded, and the resume needs a delivery to
react to. Nothing outside the agent can start this.

The stored body is what marks a ticket unfinished. It is written when the
ticket is accepted and dropped when the ticket completes, so its presence and
the ticket being outstanding are the same fact.

Nothing leaves the machine. Claude is skipped by storing a decision, every
outbound client is replaced, and the store is a throwaway file.
"""
import asyncio
import hashlib
import hmac
import itertools
import json
import os
import sqlite3
import sys
import tempfile
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

TEST_DB = os.path.join(tempfile.mkdtemp(prefix="triage-verify-recovery-"), "state.db")
os.environ["TRIAGE_STATE_DB"] = TEST_DB

from fastapi.testclient import TestClient

import main
import idempotency as store
from schemas import Category, Confidence, Severity, TicketClassification

failed = []
ran = 0

def check(name, got, expected):
    global ran
    ran += 1
    ok = got == expected
    if not ok:
        failed.append(name)
    print(f"{'PASS' if ok else 'FAIL'}  {name}")
    if not ok:
        print(f"        got {got!r}, expected {expected!r}")

acted = {"notes": [], "priorities": [], "posts": []}

main.post_alert = lambda channel, text: acted["posts"].append(channel) or "posted"
main.write_note = lambda **kw: acted["notes"].append(kw) or "written"
main.set_priority = lambda **kw: acted["priorities"].append(kw) or {
    "outcome": "set", "from": "normal", "to": "emergency"}
main.route_to_security = lambda **kw: {"outcome": "routed", "from": "a", "to": "b"}
main.send_page = lambda destination, event: "queued"
main.enrich_ticket = lambda **kw: []
for name in [n for n in dir(main) if n.startswith("log_")]:
    setattr(main, name, lambda *a, **kw: True)

# Every logger above is silenced, which would hide whether the abandon path
# recorded anything. This one keeps what it was asked to record so the test can
# read it back.
acted["reviews"] = []
main.log_human_review = lambda **kw: acted["reviews"].append(kw.get("reason")) or True

CRITICAL = TicketClassification(
    category=Category.security_incident, severity=Severity.critical,
    confidence=Confidence.high_confidence,
)

def payload_for(ticket_id):
    return {"ticket_id": ticket_id, "ticket_number": "465581",
            "subject": "verifier", "message": "verifier",
            "requester": "someone@example.com", "requester_verified": True,
            "submitter_ip": "192.0.2.1"}

_ids = itertools.count(1000)

def new_ticket():
    """An ID no other section here has used.

    Written-in numbers collide with each other as sections are added, and they
    read as though the check were about that ticket in the real helpdesk when
    it never is.
    """
    return next(_ids)

def age_row(ticket_id, seconds):
    """Backdates a ticket so the recovery window treats it as old."""
    when = (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat()
    with store._connect() as conn:
        conn.execute("UPDATE processed_tickets SET accepted_at = ? WHERE ticket_id = ?",
                     (when, store.ticket_key(ticket_id)))

print("the stored body tracks whether a ticket is finished")
print()

store.claim_ticket(1)
store.save_payload(1, payload_for(1))
fresh, stale = store.unfinished_payloads(3600)
check("an accepted ticket is unfinished", [p["ticket_id"] for p in fresh], [1])

store.clear_payload(1)
fresh, stale = store.unfinished_payloads(3600)
check("  and finished once its body is dropped", fresh, [])

# The body is dropped by process_ticket itself when nothing is outstanding, so
# an ordinary run leaves no ticket text behind.
store.claim_ticket(2)
store.save_classification(2, CRITICAL)
store.save_payload(2, payload_for(2))
main.begin_processing(2)
main.process_ticket(payload_for(2))
fresh, _ = store.unfinished_payloads(3600)
check("a completed run drops the body itself",
      [p["ticket_id"] for p in fresh], [])

print()
print("recovery finishes what a crash interrupted")
print()

# Ticket 3 stands in for a crash after the note and before everything else.
store.claim_ticket(3)
store.save_classification(3, CRITICAL)
store.save_payload(3, payload_for(3))
store.mark_done(3, "note_written")
acted["notes"].clear(); acted["priorities"].clear(); acted["posts"].clear()

asyncio.run(main._finish_interrupted())

check("the interrupted ticket is no longer outstanding",
      main.outstanding_actions(3), [])
check("  its priority was set", len(acted["priorities"]), 1)
check("  its alert was posted", acted["posts"], ["urgent"])
check("  the note it already had was not written again", acted["notes"], [])
fresh, _ = store.unfinished_payloads(3600)
check("  and its body is gone", [p["ticket_id"] for p in fresh], [])

print()
print("a ticket too old to act on")
print()

store.claim_ticket(4)
store.save_classification(4, CRITICAL)
store.save_payload(4, payload_for(4))
age_row(4, 7200)
for key in ("notes", "priorities", "posts", "reviews"):
    acted[key].clear()

asyncio.run(main._finish_interrupted())

check("it is not finished", main.completed_actions(4)["priority_set"], False)
check("  nothing is triaged for it", acted["priorities"], [])
check("  a note explains why", len(acted["notes"]), 1)
check("  the note says triage did not finish",
      "did not finish" in acted["notes"][0].get("note", ""), True)
# The same answer a classification failure gets. The agent never decided
# anything, so it cannot know whether this was a critical incident, and a note
# nobody opens is not enough on a ticket that might have been one.
check("  the review channel is told", acted["posts"], ["review"])
check("  and the abandonment is recorded",
      acted["reviews"], ["interrupted_past_recovery_window"])
fresh, stale = store.unfinished_payloads(3600)
check("  and it is not rescanned", [p["ticket_id"] for p in fresh + stale], [])

print()
print("a body this build cannot read")
print()

store.claim_ticket(5)
with store._connect() as conn:
    conn.execute("UPDATE processed_tickets SET payload = 'not json' "
                 "WHERE ticket_id = '5'")
fresh, stale = store.unfinished_payloads(3600)
check("is dropped rather than acted on", fresh + stale, [])

print()
print("a store that fails does not strand the ticket")
print()

client = TestClient(main.app, raise_server_exceptions=False)

handed_over = []
main.process_ticket = lambda payload: handed_over.append(payload.get("ticket_id"))

def deliver(ticket_id):
    """Sends one signed webhook the way osTicket does."""
    body = json.dumps({**payload_for(ticket_id),
                       "created_at": datetime.now(timezone.utc).isoformat()}).encode()
    return client.post(
        "/webhook/ticket", content=body,
        headers={"X-Triage-Signature": "sha256=" + hmac.new(
            main.HMAC_SECRET.encode(), body, hashlib.sha256).hexdigest(),
            "Content-Type": "application/json"})

def store_is_down(*args, **kwargs):
    raise sqlite3.OperationalError("database is locked")

# Storing the body is the one step between the in-flight mark and the handover
# that touches the store, so it is the one that can fail with the mark still
# set. A mark that is never released refuses the ticket for the life of the
# process.
working = main.save_payload
main.save_payload = store_is_down

interrupted = new_ticket()

check("a delivery whose store write fails is not reported as delivered",
      deliver(interrupted).status_code, 500)
check("  and the ticket is not left marked in flight",
      store.ticket_key(interrupted) in main._in_flight, False)

main.save_payload = working

# The plugin reads every 2xx as delivered. An in_flight answer here would take
# the ticket out of its retry queue and nothing would ever send it again.
check("  so the retry is accepted once the store recovers",
      deliver(interrupted).status_code, 202)
check("  and the work is handed over", handed_over, [interrupted])

print()
print("one ticket failing does not strand the ones behind it")
print()

# Earlier sections leave bodies behind, and recovery reads every one of them,
# so they are cleared first. What is left is exactly the three tickets below.
for leftover in sum(store.unfinished_payloads(3600), []):
    store.clear_payload(leftover["ticket_id"])

# These are the tickets nothing else will retry, so a loop that stops at the
# first failure leaves the rest unfinished with nothing to pick them up.
first, failing, last = new_ticket(), new_ticket(), new_ticket()
for ticket in (first, failing, last):
    store.claim_ticket(ticket)
    store.save_payload(ticket, payload_for(ticket))
    store.save_classification(ticket, CRITICAL)

attempted = []

def one_ticket_fails(payload):
    ticket_id = payload.get("ticket_id")
    attempted.append(ticket_id)
    if ticket_id == failing:
        raise RuntimeError("simulated failure partway through the backlog")
    for column in ("classification_audited", "note_written", "priority_set",
                   "slack_posted", "paged"):
        store.mark_done(ticket_id, column)
    store.clear_payload(ticket_id)

main.process_ticket = one_ticket_fails

# A loop with no per-ticket guard lets this escape, which would end the run
# here and report nothing. Caught so the checks below say what was stranded.
try:
    asyncio.run(main._finish_interrupted())
except Exception as e:
    print(f"      recovery aborted: {type(e).__name__}: {e}")

check("every queued ticket is attempted", attempted, [first, failing, last])
check("  the ones behind the failure still finish",
      [t for t in (first, last) if not main.outstanding_actions(t)],
      [first, last])
check("  the failed one keeps its body for the next start",
      sorted(p["ticket_id"] for p in store.unfinished_payloads(3600)[0]),
      [failing])
check("  and it is not left marked in flight",
      store.ticket_key(failing) in main._in_flight, False)

print()
if failed:
    print(f"FAILED: {', '.join(failed)}")
    sys.exit(1)
print(f"All {ran} checks passed. Nothing was sent. Store: {TEST_DB}")
