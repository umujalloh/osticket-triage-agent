"""Checks that the channel post reports what happened to the page.

The renderer is covered in verify_slack.py. This covers the wiring, which is
where the bug was: _page returned whether the page went out and both callers
discarded it, so the alert named the destination the action table had chosen
whether or not anyone was reached. A reader seeing a page in the alert assumes
the on-call is awake.

The whole real path runs here, from process_ticket down to the text handed to
Slack. Nothing leaves the machine. Claude is skipped by storing a decision
first, so the ticket takes the resume path, and every outbound client is
replaced.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

TEST_DB = os.path.join(tempfile.mkdtemp(prefix="triage-verify-page-"), "state.db")
os.environ["TRIAGE_STATE_DB"] = TEST_DB

import main
import idempotency as store
from pagerduty_client import PagerDutyError
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

# Everything the agent would reach out to. Audit writes are stubbed as well, so
# a run here leaves nothing in the real index.
posted = {}

def stub_post_alert(channel, text):
    posted["channel"] = channel
    posted["text"] = text
    return "posted"

main.post_alert = stub_post_alert
main.enrich_ticket = lambda **kw: []
main.write_note = lambda **kw: "written"
main.set_priority = lambda **kw: {"outcome": "set", "from": "normal", "to": "emergency"}
main.route_to_security = lambda **kw: {"outcome": "routed", "from": "Support", "to": "Security"}
for name in [n for n in dir(main) if n.startswith("log_")]:
    setattr(main, name, lambda *a, **kw: True)

CRITICAL = TicketClassification(
    category=Category.security_incident, severity=Severity.critical,
    confidence=Confidence.high_confidence,
)

def run(ticket_id, send_page):
    """Drives one ticket through the real path and returns the alert text."""
    posted.clear()
    main.send_page = send_page
    store.claim_ticket(ticket_id)
    store.save_classification(ticket_id, CRITICAL)
    main.process_ticket({
        "ticket_id": ticket_id,
        "ticket_number": "465581",
        "subject": "verifier",
        "message": "verifier",
        "requester": "someone@example.com",
        "requester_verified": True,
        "submitter_ip": "192.0.2.1",
    })
    return posted.get("text", "")

print("a page that PagerDuty refuses")
print()

def refuse(destination, event):
    raise PagerDutyError("server_down", "PagerDuty is unreachable")

text = run(1, refuse)
check("the alert reaches the channel anyway", bool(text), True)
check("  and says the page failed", "WAKE PAGE FAILED" in text, True)
check("  and does not claim it paged", "paged WAKE" in text, False)
check("  and says what to do instead", "escalate manually" in text, True)
check("  the failure is not recorded as a completed page",
      store.completed_actions(1)["paged"], False)

print()
print("a page PagerDuty accepts")
print()

text = run(2, lambda destination, event: "queued")
check("the alert names the destination", "paged WAKE" in text, True)
check("  and reports no failure", "PAGE FAILED" in text, False)
check("  the page is recorded", store.completed_actions(2)["paged"], True)

print()
print("a ticket resumed after its page but before its alert")
print()

# _page returns True for a page that already went out, without calling
# PagerDuty. The alert has to read that as sent. send_page is set to raise so a
# regression that called it anyway would fail loudly here rather than pass by
# accident.
store.claim_ticket(3)
store.save_classification(3, CRITICAL)
store.mark_done(3, "paged")
text = run(3, refuse)
check("a page already sent is not reported as failed",
      "PAGE FAILED" in text, False)
check("  it still names the destination", "paged WAKE" in text, True)

print()
if failed:
    print(f"FAILED: {', '.join(failed)}")
    sys.exit(1)
print(f"All {ran} checks passed. Nothing was sent. Store: {TEST_DB}")
