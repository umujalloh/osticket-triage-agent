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
    from schemas import TicketClassification
    from idempotency import completed_actions
    import main

    # it_support at high confidence writes a note and skips enrichment, which
    # isolates the write path from everything upstream of it.
    classification = TicketClassification(
        category="it_support", severity="low", confidence="high_confidence"
    )
    main._write_ticket_note(TICKET_ID, classification, None, None)
    main._set_ticket_priority(TICKET_ID, classification)
    state = completed_actions(TICKET_ID)
    print(f"STORE_NOTE_WRITTEN={state['note_written']}")
    print(f"STORE_PRIORITY_SET={state['priority_set']}")
    sys.exit(0)

STORE = os.path.join(tempfile.mkdtemp(prefix="triage-wiring-"), "state.db")

def run_case(name, enable_writes):
    env = dict(os.environ, WIRING_CASE=name, ENABLE_WRITES=enable_writes,
               TRIAGE_STATE_DB=STORE)
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

out = run_case("writes_off", "false")
check("kill switch off skips the note", "note skipped (writes disabled)" in out)
check("kill switch off skips the priority", "priority skipped (writes disabled)" in out)
check("kill switch off records neither",
      "STORE_NOTE_WRITTEN=False" in out and "STORE_PRIORITY_SET=False" in out)

out = run_case("writes_on", "true")
check("kill switch on writes the note", "note written" in out)
check("kill switch on sets the priority", "to low" in out)
check("both successes are recorded",
      "STORE_NOTE_WRITTEN=True" in out and "STORE_PRIORITY_SET=True" in out)

out = run_case("retry", "true")
check("a second note is refused", "note already written, skipping" in out)
check("a second priority write is refused", "priority already set, skipping" in out)
check("the refusals leave both records intact",
      "STORE_NOTE_WRITTEN=True" in out and "STORE_PRIORITY_SET=True" in out)

print()
if failed:
    print(f"FAILED: {', '.join(failed)}")
    sys.exit(1)
print(f"All {ran} checks passed.")
print(f"Ticket {TICKET_ID} gained exactly one note and its priority was set "
      f"once, across three runs.")
