import os
import subprocess
import sys
import tempfile

if len(sys.argv) != 2 or not sys.argv[1].isdigit():
    raise SystemExit(
        "usage: python verify_wiring.py <ticket_id>\n\n"
        "Checks that the note write obeys the kill switch and cannot repeat\n"
        "itself. One case writes a real note to the ticket you name, so pick\n"
        "one you don't mind marking.\n\n"
        "Each case runs in its own process, because ENABLE_WRITES is read at\n"
        "import and patching it in place would not test what actually happens\n"
        "at boot."
    )

TICKET_ID = int(sys.argv[1])

# The child half. Runs one case against the store the parent chose.
if os.environ.get("WIRING_CASE"):
    from action_table import actions_for
    from schemas import Category, Confidence, EnrichmentOutcome, Severity, TicketClassification
    from idempotency import completed_actions
    import main

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

    main._write_ticket_note(TICKET_ID, classification, outcome, None, None)
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

print()
if failed:
    print(f"FAILED: {', '.join(failed)}")
    sys.exit(1)
print(f"All {ran} checks passed.")
print(f"Across three runs ticket {TICKET_ID} gained exactly one note, one "
      f"priority change, and one alert.")
