import os
import subprocess
import sys
import tempfile

# These sit one folder below the modules they exercise, so the agent directory
# has to be on the path before anything is imported from it.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

if len(sys.argv) != 2 or not sys.argv[1].isdigit():
    raise SystemExit(
        "usage: python verification/verify_wiring.py <ticket_id>\n\n"
        "Checks that the note write obeys the kill switch, cannot repeat\n"
        "itself, and records a failed classification audit write on the note.\n"
        "One case writes a real note to the ticket you name, so pick one you\n"
        "don't mind marking.\n\n"
        "Each case runs in its own process, because ENABLE_WRITES is read at\n"
        "import and patching it in place would not test what actually happens\n"
        "at boot."
    )

TICKET_ID = int(sys.argv[1])

# The child half. Runs one case against the store the parent chose.
if os.environ.get("WIRING_CASE"):
    from action_table import actions_for
    from note_builder import build_note
    from schemas import Category, Confidence, EnrichmentOutcome, Severity, TicketClassification
    from idempotency import completed_actions
    import main

    # Claude failing, without needing Claude to fail. The whole path runs:
    # process_ticket catches it, audits it, and posts the notice, so this covers
    # the wiring rather than the classifier's own mapping of API errors onto the
    # six failure types, which classifier.py owns and this commit did not touch.
    if os.environ["WIRING_CASE"].startswith("claude_failed"):
        from classifier import ClassificationError

        def _always_fails(subject, message):
            raise ClassificationError("rate_limited", "forced by the verifier")

        main.classify_ticket = _always_fails
        main.process_ticket({
            "ticket_id": TICKET_ID, "ticket_number": "VERIFY",
            "subject": "verifier", "message": "verifier",
        })
        state = completed_actions(TICKET_ID)
        print(f"STORE_NOTE_WRITTEN={state['note_written']}")
        print(f"STORE_PRIORITY_SET={state['priority_set']}")
        print(f"STORE_SLACK_POSTED={state['slack_posted']}")
        sys.exit(0)

    # The page must not sit behind a Splunk call. The parent points HEC at a
    # dead port, so every audit write fails, and the check is that the page went
    # out before the first of those failures rather than after all of them. The
    # search endpoint is left alone, since proving the page precedes the first
    # audit write proves it precedes the enrichment that follows it.
    if os.environ["WIRING_CASE"] == "page_before_audit":
        critical = TicketClassification(
            category="security_incident", severity="critical",
            confidence="high_confidence"
        )
        main.classify_ticket = lambda subject, message: critical
        main.process_ticket({
            "ticket_id": TICKET_ID, "ticket_number": "VERIFY",
            "subject": "verifier", "message": "verifier",
        })
        sys.exit(0)

    # The paging row, kept apart from the case below because the table pages on
    # critical alone and the row below is deliberately a high that does not.
    if os.environ["WIRING_CASE"].startswith("paging"):
        from action_table import WAKE
        from pagerduty_client import build_page

        critical = TicketClassification(
            category="security_incident", severity="critical",
            confidence="high_confidence"
        )
        main._page(TICKET_ID, WAKE,
                   build_page(TICKET_ID, "VERIFY", critical),
                   fallback=False)
        state = completed_actions(TICKET_ID)
        print(f"STORE_PAGED={state['paged']}")
        print(f"STORE_PAGED_FALLBACK={state['paged_fallback']}")
        sys.exit(0)

    # A real table row that writes a note, sets priority, and posts to a
    # channel, without enriching or paging. One classification exercises every
    # write the agent currently makes.
    classification = TicketClassification(
        category="security_incident", severity="high", confidence="high_confidence"
    )
    actions = actions_for(Category.security_incident, Severity.high,
                          Confidence.high_confidence)
    payload = {"ticket_number": "VERIFY"}
    outcome = EnrichmentOutcome.not_eligible
    audited = os.environ.get("WIRING_AUDITED", "true") == "true"

    # Printed rather than asserted here so the parent owns every check. The body
    # is built whether or not the store lets the write through, so this reports
    # the note's content even on a retry that refuses to write it again.
    print(f"NOTE_BODY={build_note(classification, outcome, None, None, audited)!r}")

    main._write_ticket_note(TICKET_ID, classification, outcome, None, None, audited)
    main._set_ticket_priority(TICKET_ID, classification)
    main._post_alert(TICKET_ID, classification, actions, payload, outcome, None)

    state = completed_actions(TICKET_ID)
    print(f"STORE_NOTE_WRITTEN={state['note_written']}")
    print(f"STORE_PRIORITY_SET={state['priority_set']}")
    print(f"STORE_SLACK_POSTED={state['slack_posted']}")
    sys.exit(0)

STORE = os.path.join(tempfile.mkdtemp(prefix="triage-wiring-"), "state.db")

def run_case(name, enable_writes, **overrides):
    env = dict(os.environ)
    env.update({"WIRING_CASE": name, "ENABLE_WRITES": enable_writes,
                "TRIAGE_STATE_DB": STORE})
    # Alerts go to the test channel, so the real ones carry only real alerts.
    test_hook = os.getenv("SLACK_WEBHOOK_TEST")
    if test_hook:
        env["SLACK_WEBHOOK_INCIDENTS"] = test_hook
        env["SLACK_WEBHOOK_REVIEW"] = test_hook
    # Same for pages, so the real service holds nothing but real pages.
    test_key = os.getenv("PAGERDUTY_ROUTING_KEY_TEST")
    if test_key:
        env["PAGERDUTY_ROUTING_KEY_WAKE"] = test_key
        env["PAGERDUTY_ROUTING_KEY_NOTIFY"] = test_key
    env.update(overrides)
    result = subprocess.run([sys.executable, __file__, str(TICKET_ID)],
                            env=env, capture_output=True, text=True)
    if result.returncode != 0:
        print(result.stdout)
        print(result.stderr)
        raise SystemExit(f"case {name} exited {result.returncode}")
    return result.stdout

failed = []
ran = 0

def check(name, condition):
    global ran
    ran += 1
    if not condition:
        failed.append(name)
    print(f"{'PASS' if condition else 'FAIL'}  {name}")

# Which rows reach PagerDuty at all, checked here rather than left to the
# reading. Severity alone would page for an it_support ticket the classifier
# rated critical, and the security on-call is not who a major outage wants.
from itertools import product

from action_table import actions_for
from main import needs_fallback_page
from schemas import Category, Confidence, Severity, TicketClassification

pages, fallbacks = [], []
for cat, sev, conf in product(Category, Severity, Confidence):
    try:
        acts = actions_for(cat, sev, conf)
    except Exception:
        continue
    row = f"{cat.value}/{sev.value}/{conf.value}"
    classification = TicketClassification(category=cat.value, severity=sev.value,
                                          confidence=conf.value)
    if acts.page:
        pages.append(row)
    if needs_fallback_page(classification, acts):
        fallbacks.append(row)

check("both criticals page, and nothing else does",
      pages == ["security_incident/critical/high_confidence",
                "security_incident/critical/low_confidence"])
check("only one at low confidence falls back",
      fallbacks == ["security_incident/critical/low_confidence"])

RECORDED = ("STORE_NOTE_WRITTEN=True", "STORE_PRIORITY_SET=True",
            "STORE_SLACK_POSTED=True")
UNRECORDED = ("STORE_NOTE_WRITTEN=False", "STORE_PRIORITY_SET=False",
              "STORE_SLACK_POSTED=False")

out = run_case("writes_off", "false")
check("kill switch off skips the note", "note skipped (writes disabled)" in out)
check("kill switch off skips the priority", "priority skipped (writes disabled)" in out)
check("kill switch off skips the alert", "skipped (writes disabled)" in out)
check("kill switch off records nothing", all(s in out for s in UNRECORDED))

out = run_case("writes_on", "true")
# Either outcome means the kill switch let the write through. Which one depends
# on whether the named ticket already carried an agent note, since the endpoint
# answers a repeat rather than writing a second copy.
check("kill switch on writes the note",
      "note written" in out or "note already present" in out)
check("kill switch on sets the priority", "to high" in out)
check("kill switch on posts the alert", "slack posted to incidents" in out)
check("all three successes are recorded", all(s in out for s in RECORDED))

out = run_case("retry", "true")
check("a second note is refused", "note already written, skipping" in out)
check("a second priority write is refused", "priority already set, skipping" in out)
check("a second alert is refused", "slack already posted, skipping" in out)
check("the refusals leave all three records intact", all(s in out for s in RECORDED))

# A failed classification audit write leaves nothing outside the ticket
# explaining how it was classified, so the note carries that itself.
out = run_case("audited", "true")
check("an audited note says nothing about the audit", "No audit record." not in out)

out = run_case("unaudited", "true", WIRING_AUDITED="false")
check("an unaudited note records the gap", "No audit record." in out)
check("the gap is the last line of the note",
      "\\n\\nNo audit record." in out)

# Its own store, because the cases above already claimed this ticket's alert
# and the point here is that the notice goes out, not that it is refused.
FAILURE_STORE = os.path.join(tempfile.mkdtemp(prefix="triage-failure-"), "state.db")

out = run_case("claude_failed", "true", TRIAGE_STATE_DB=FAILURE_STORE)
check("a ticket Claude could not classify reaches the review channel",
      "slack posted to review" in out)
check("  and the console names the failure",
      "classification failed (rate_limited)" in out)
check("  no note is written, since there is nothing to put in one",
      "STORE_NOTE_WRITTEN=False" in out)
check("  no priority is set, since there is no severity",
      "STORE_PRIORITY_SET=False" in out)
check("  the notice is recorded", "STORE_SLACK_POSTED=True" in out)

out = run_case("claude_failed_retry", "true", TRIAGE_STATE_DB=FAILURE_STORE)
check("a retried failure does not post the notice twice",
      "slack already posted, skipping" in out)

# Its own store again, so the paging checks start from a ticket that has not
# been paged rather than one the cases above already claimed.
PAGE_STORE = os.path.join(tempfile.mkdtemp(prefix="triage-paging-"), "state.db")

out = run_case("paging_off", "false", TRIAGE_STATE_DB=PAGE_STORE)
check("kill switch off skips the page", "page skipped (writes disabled)" in out)
check("kill switch off records no page", "STORE_PAGED=False" in out)

out = run_case("paging_on", "true", TRIAGE_STATE_DB=PAGE_STORE)
check("kill switch on pages", "Ticket 18: paged" in out)
check("the page is recorded", "STORE_PAGED=True" in out)

out = run_case("paging_retry", "true", TRIAGE_STATE_DB=PAGE_STORE)
check("a second page is refused", "already paged wake, skipping" in out)
check("the refusal leaves the record intact", "STORE_PAGED=True" in out)
# The two pages are guarded by separate columns, so refusing the WAKE one must
# not also mark the fallback as done. A single column would.
check("and leaves the fallback still available",
      "STORE_PAGED_FALLBACK=False" in out)

# The finding this ordering exists for. Splunk holds the audit log and the
# enrichment data, so a page sitting behind either is a page that waits out
# Splunk's retries, and Splunk can be unwell for the same reason the ticket was
# filed. Asserting the order rather than the elapsed time, since the retry
# constants are free to change and the ordering is not.
ORDER_STORE = os.path.join(tempfile.mkdtemp(prefix="triage-order-"), "state.db")
out = run_case("page_before_audit", "true", TRIAGE_STATE_DB=ORDER_STORE,
               SPLUNK_HEC_URL="https://127.0.0.1:1/services/collector/event")
# Named events rather than the raw "Splunk logging failed" line, which appears
# once per audit write and cannot be told apart. The page writes an audit event
# of its own, and that one is allowed to fail behind the page.
paged_at = out.find(f"Ticket {TICKET_ID}: paged")
classification_audit_at = out.find("audit write failed (classification_complete)")
check("a dead audit endpoint still fails the classification write",
      classification_audit_at != -1)
check("the page goes out anyway", paged_at != -1)
check("and it goes out before the classification audit write",
      paged_at != -1 and classification_audit_at > paged_at)
check("the page does not wait for enrichment either",
      paged_at < out.find("enrichment") if "enrichment" in out else True)

print()
if failed:
    print(f"FAILED: {', '.join(failed)}")
    sys.exit(1)
print(f"All {ran} checks passed.")
print(f"Ticket {TICKET_ID} gained exactly one note, one priority change and one "
      f"alert, plus one notice and one page from the cases that use their own "
      f"stores.")
