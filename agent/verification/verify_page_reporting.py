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

# Kept so a check can read back what the page's outcome recorded.
audited = []
main.log_paged = lambda *a, **kw: audited.append(("paged", a)) or True
main.log_page_failure = lambda *a, **kw: audited.append(("page_failed", a)) or True
key_checks = []
main.check_routing_keys = lambda: key_checks.append(1) or {}

# The confirmation runs on a thread pool in the agent. Here each task runs at
# once, so a check reads what it recorded as soon as the ticket is done.
from concurrent.futures import Future

class RunAtOnce:
    def submit(self, fn, *args):
        done = Future()
        try:
            done.set_result(fn(*args))
        except Exception as e:
            done.set_exception(e)
        return done

main._confirmations = RunAtOnce()
main._routing_checks = RunAtOnce()

# Writes on, whatever .env says, since a resumed page is confirmed again only
# with writes on. Nothing is sent, because every client above is a stub.
main.writes_enabled = lambda: True

CRITICAL = TicketClassification(
    category=Category.security_incident, severity=Severity.critical,
    confidence=Confidence.high_confidence,
)

def run(ticket_id, send_page, confirm=lambda destination, dedup_key, **_: "confirmed"):
    """Drives one ticket through the real path and returns the alert text."""
    posted.clear()
    audited.clear()
    key_checks.clear()
    main.send_page = send_page
    main.confirm_page = confirm
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

# A page an earlier start sent is confirmed again while its Slack post is
# still owed, because that start may have ended before learning whether the
# page reached anyone. send_page is set to raise, so a regression that sent it
# again fails these checks.
store.claim_ticket(3)
store.save_classification(3, CRITICAL)
store.mark_done(3, "paged")
asked = []
text = run(3, refuse,
           lambda destination, dedup_key, **kw: asked.append(
               (destination, kw.get("include_resolved"))) or "confirmed")
check("a page already sent is not reported as failed",
      "PAGE FAILED" in text, False)
check("  it still names the destination", "paged WAKE" in text, True)
check("  it is confirmed again, counting a resolved incident too",
      asked, [("wake", True)])
check("  the earlier start's audit event is not written a second time",
      audited, [])

store.claim_ticket(8)
store.save_classification(8, CRITICAL)
store.mark_done(8, "paged")
text = run(8, refuse, lambda destination, dedup_key, **_: "no_incident")
check("a resumed page that reached nobody is reported as reaching nobody",
      "WAKE PAGE REACHED NOBODY" in text and "paged WAKE" not in text, True)
check("  and it starts no second routing key check", len(key_checks), 0)

# With the Slack post already sent, or writes off, no confirmation is started.
store.claim_ticket(11)
store.save_classification(11, CRITICAL)
store.mark_done(11, "paged")
store.mark_done(11, "slack_posted")
asked = []
run(11, refuse, lambda destination, dedup_key, **_: asked.append(destination) or "confirmed")
check("a resumed page whose Slack post went out is not confirmed again", asked, [])

store.claim_ticket(12)
store.save_classification(12, CRITICAL)
store.mark_done(12, "paged")
real_writes = main.writes_enabled
main.writes_enabled = lambda: False
asked = []
run(12, refuse, lambda destination, dedup_key, **_: asked.append(destination) or "confirmed")
main.writes_enabled = real_writes
check("a resumed page with writes off is not confirmed again", asked, [])

print()
print("a page PagerDuty accepts and drops")
print()

def accept(destination, event):
    return "queued"

text = run(4, accept, lambda destination, dedup_key, **_: "no_incident")
check("the alert says the page reached nobody",
      "WAKE PAGE REACHED NOBODY" in text, True)
check("  and does not claim it paged", "paged WAKE" in text, False)
check("  and says what to do instead", "escalate manually" in text, True)
check("  the audit records a failed page with its own type",
      [(kind, args[2]) for kind, args in audited], [("page_failed", "no_incident")])
check("  the routing key check runs at once", len(key_checks), 1)
check("  the page is not sent again on a later start",
      store.completed_actions(4)["paged"], True)

print()
print("a page the agent could not confirm")
print()

text = run(5, accept, lambda destination, dedup_key, **_: "unconfirmed")
check("the alert says it paged, not confirmed",
      "paged WAKE, not confirmed" in text, True)
check("  and reports no failure", "PAGE FAILED" in text or "NOBODY" in text, False)
check("  the audit records the page as unconfirmed",
      [(kind, args[3]) for kind, args in audited], [("paged", False)])
check("  no routing key check is run for it", len(key_checks), 0)

def broken(destination, dedup_key):
    raise RuntimeError("lookup crashed")

text = run(6, accept, broken)
check("a lookup that crashes still lets the alert out, as not confirmed",
      "paged WAKE, not confirmed" in text, True)

print()
print("the confirmation the agent asks for")
print()

asked = []
text = run(7, accept,
           lambda destination, dedup_key, **_: asked.append((destination, dedup_key))
           or "confirmed")
check("a confirmed page reads as paged", "paged WAKE" in text
      and "not confirmed" not in text, True)
check("  it asks about the WAKE page by the page's own dedup key",
      asked, [("wake", main.build_page(7, "465581", CRITICAL)["dedup_key"])])
check("  the audit records the page as confirmed",
      [(kind, args[3]) for kind, args in audited], [("paged", True)])

print()
print("pages that are not confirmed, or confirmed with nothing waiting")
print()

asked = []
text = run(9, lambda destination, event: main.PD_SKIPPED,
           lambda destination, dedup_key, **_: asked.append(destination) or "confirmed")
check("a page writes being off skipped is not confirmed", asked, [])

# A low-confidence critical pages NOTIFY, and when its Slack post fails the
# agent sends the WAKE fallback, whose confirmation nothing waits on.
LOW = TicketClassification(
    category=Category.security_incident, severity=Severity.critical,
    confidence=Confidence.low_confidence,
)
real_post = main.post_alert
def lost_post(channel, text):
    raise main.SlackError("server_down", "Slack is unreachable")
main.post_alert = lost_post
asked = []
posted.clear(); audited.clear(); key_checks.clear()
main.send_page = accept
main.confirm_page = lambda destination, dedup_key, **_: asked.append(destination) or "no_incident"
store.claim_ticket(10)
store.save_classification(10, LOW)
main.process_ticket({"ticket_id": 10, "ticket_number": "465581", "subject": "v",
                     "message": "v", "requester": "someone@example.com",
                     "requester_verified": True, "submitter_ip": "192.0.2.1"})
main.post_alert = real_post
check("a failed post sends the WAKE fallback, and both pages are confirmed",
      asked, ["notify", "wake"])
check("  the fallback that reached nobody is recorded as a failed page",
      [(kind, args[1], args[2]) for kind, args in audited],
      [("page_failed", "notify", "no_incident"), ("page_failed", "wake", "no_incident")])

print()
print("with the real thread pool")
print()

# RunAtOnce records a page before process_ticket returns, so it cannot tell
# whether the post waited on the recording. These cases use real threads.
import threading
from concurrent.futures import ThreadPoolExecutor

main._confirmations = ThreadPoolExecutor(max_workers=2)
release = threading.Event()
recorded = threading.Event()
def slow_log_paged(*args, **kwargs):
    release.wait(10)
    audited.append(("paged", args))
    recorded.set()
    return True
main.log_paged = slow_log_paged
text = run(13, accept)
check("the alert goes out while the page's audit write is still running",
      ("paged WAKE" in text, recorded.is_set()), (True, False))
release.set()
recorded.wait(10)
check("  and the audit write finishes after it", recorded.is_set(), True)

never = threading.Event()
real_wait = main.CONFIRM_ANSWER_SECONDS
main.CONFIRM_ANSWER_SECONDS = 0.2
text = run(14, accept, lambda destination, dedup_key, **_: never.wait(10) and "confirmed")
main.CONFIRM_ANSWER_SECONDS = real_wait
never.set()
check("a confirmation that does not answer in time reads as not confirmed",
      "paged WAKE, not confirmed" in text, True)
main._confirmations.shutdown(wait=True)

print()
if failed:
    print(f"FAILED: {', '.join(failed)}")
    sys.exit(1)
print(f"All {ran} checks passed. Nothing was sent. Store: {TEST_DB}")
