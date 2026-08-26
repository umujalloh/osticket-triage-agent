"""Checks what the agent does with a ticket it accepted once already.

A repeat delivery is either a duplicate to refuse, a ticket to pick up where an
interrupted run left it, or a ticket another run is working on right now. These
are the three, and getting them confused means either acting twice on one ticket
or leaving one half acted on.

Nothing here reaches Claude, Slack, PagerDuty, osTicket or Splunk. It exercises
the decision, against a throwaway store.
"""
import os
import sys
import tempfile

# These sit one folder below the modules they exercise, so the agent directory
# has to be on the path before anything is imported from it.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Point the store at a throwaway file before importing it. Running these against
# the real store would insert ticket IDs that then refuse the genuine ticket
# carrying the same number.
TEST_DB = os.path.join(tempfile.mkdtemp(prefix="triage-verify-resume-"), "state.db")
os.environ["TRIAGE_STATE_DB"] = TEST_DB

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

def decision(category, severity, confidence):
    return TicketClassification(category=category, severity=severity,
                                confidence=confidence)

def outstanding(ticket_id):
    return sorted(main.outstanding_actions(ticket_id))

def finish(ticket_id, columns):
    for column in columns:
        store.mark_done(ticket_id, column)

print("What a repeat delivery finds")
print()

check("a ticket the store has never seen is undecided",
      main.outstanding_actions(1), [main.UNDECIDED])

# Claimed and nothing else. This is the run that died between the claim and the
# classification, so there is no decision to resume on and the ticket starts
# over. Nothing has been acted on, so starting over is safe.
store.claim_ticket(2)
check("a claim on its own is still undecided",
      main.outstanding_actions(2), [main.UNDECIDED])

print()
print("A confident critical, which selects all five actions")
print()

CRITICAL = ["classification_audited", "note_written", "paged", "priority_set",
            "slack_posted"]

store.claim_ticket(3)
store.save_classification(3, decision(Category.security_incident, Severity.critical,
                                      Confidence.high_confidence))
check("a decision with nothing done lists every action the row selects",
      outstanding(3), sorted(CRITICAL))

store.mark_done(3, "paged")
check("what already happened drops off the list",
      outstanding(3), sorted(c for c in CRITICAL if c != "paged"))

finish(3, CRITICAL)
check("a finished ticket has nothing outstanding", outstanding(3), [])

# The fallback page happens only when a channel post fails. Counting it would
# make every ticket that alerted successfully look unfinished forever.
check("a page that never had to fall back is not outstanding",
      store.completed_actions(3)["paged_fallback"], False)

print()
print("Rows are not all the same shape")
print()

store.claim_ticket(4)
store.save_classification(4, decision(Category.it_support, Severity.low,
                                      Confidence.high_confidence))
check("a routine request wants no alert, no page and no routing",
      outstanding(4), sorted(["classification_audited", "note_written", "priority_set"]))

store.claim_ticket(5)
store.save_classification(5, decision(Category.security_question, Severity.low,
                                      Confidence.high_confidence))
check("a security question wants the move to the security department",
      outstanding(5), sorted(["classification_audited", "note_written",
                              "priority_set", "routed"]))

# The audit write is not something a person sees, and it is still work. A
# decision Splunk never recorded is a decision nobody can check afterwards.
store.claim_ticket(6)
store.save_classification(6, decision(Category.it_support, Severity.low,
                                      Confidence.high_confidence))
finish(6, ["note_written", "priority_set"])
check("a ticket acted on but never audited is unfinished",
      outstanding(6), ["classification_audited"])

print()
print("Two runs at one ticket")
print()

check("a ticket nobody is working on can be started", main.begin_processing(7), True)
check("and cannot be started twice", main.begin_processing(7), False)
check("int 7 and str '7' are one ticket here too", main.begin_processing("7"), False)
check("a different ticket is unaffected", main.begin_processing(8), True)

main.end_processing(7)
check("a ticket that finished can be started again", main.begin_processing(7), True)
main.end_processing(7)
main.end_processing(8)

# The mark is only useful if it is always released. A run that raises still has
# to let the next delivery through, or one failure locks the ticket out until
# the process restarts.
def explode(payload):
    raise RuntimeError("something upstream broke")

main.begin_processing(9)
real = main._process_ticket
main._process_ticket = explode
try:
    main.process_ticket({"ticket_id": 9})
    raised = "nothing"
except RuntimeError:
    raised = "RuntimeError"
finally:
    main._process_ticket = real

check("a run that raises does not swallow the error", raised, "RuntimeError")
check("and still releases the ticket", main.begin_processing(9), True)
main.end_processing(9)

print()
if failed:
    print(f"FAILED: {', '.join(failed)}")
    sys.exit(1)
print(f"All {ran} checks passed. Temporary store: {TEST_DB}")
