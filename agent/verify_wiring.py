import os
import subprocess
import sys
import tempfile

if len(sys.argv) != 2 or not sys.argv[1].isdigit():
    raise SystemExit(
        "usage: python verify_wiring.py <ticket_id>\n\n"
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
check("kill switch on writes the note", "note written" in out)
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

print()
if failed:
    print(f"FAILED: {', '.join(failed)}")
    sys.exit(1)
print(f"All {ran} checks passed.")
print(f"Ticket {TICKET_ID} gained exactly one note, one priority change, and "
      f"one alert, plus one notice from the classification-failure cases.")
