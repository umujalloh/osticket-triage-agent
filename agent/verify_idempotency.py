import importlib
import os
import sys
import tempfile

# Point the store at a throwaway file before importing it. Running these
# against the real store would insert ticket IDs that then refuse the genuine
# ticket carrying the same number.
TEST_DB = os.path.join(tempfile.mkdtemp(prefix="triage-verify-"), "state.db")
os.environ["TRIAGE_STATE_DB"] = TEST_DB

import idempotency as store

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

nothing_done = {a: False for a in store.ACTIONS}

check("first claim wins", store.claim_ticket(42), True)
check("second claim loses", store.claim_ticket(42), False)
check("a different ticket still wins", store.claim_ticket(43), True)
check("int 42 and str '42' are one ticket", store.claim_ticket("42"), False)

check("a fresh ticket has no actions done", store.completed_actions(43), nothing_done)

store.mark_done(43, "note_written")
check("a marked action is recorded", store.completed_actions(43)["note_written"], True)
check("marking one action leaves the others alone", store.completed_actions(43)["paged"], False)

store.mark_done(43, "note_written")
check("marking the same action twice is harmless", store.completed_actions(43)["note_written"], True)

check("an unknown ticket reports nothing done", store.completed_actions(9999), nothing_done)

# A completed action must survive even if the claim never happened, or a retry
# would repeat it.
store.mark_done(77, "note_written")
check("marking an unclaimed ticket still records it",
      store.completed_actions(77)["note_written"], True)

try:
    store.mark_done(43, "not_a_real_action")
    check("an unknown action is rejected", "no exception", "ValueError")
except ValueError:
    check("an unknown action is rejected", "ValueError", "ValueError")

# The point of the store. Drop the module and load it again against the same
# file, which is what a restart does.
del sys.modules["idempotency"]
restarted = importlib.import_module("idempotency")

check("a claim survives a restart", restarted.claim_ticket(42), False)
check("action state survives a restart", restarted.completed_actions(43)["note_written"], True)
check("an unseen ticket is still claimable after a restart", restarted.claim_ticket(44), True)

print()
if failed:
    print(f"FAILED: {', '.join(failed)}")
    sys.exit(1)
print(f"All {ran} checks passed. Temporary store: {TEST_DB}")
