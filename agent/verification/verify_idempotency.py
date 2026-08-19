import importlib
import os
import sys
import tempfile

# These sit one folder below the modules they exercise, so the agent directory
# has to be on the path before anything is imported from it.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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

# A store written before an action existed. CREATE TABLE IF NOT EXISTS does
# nothing to a table that is already there, so without the migration the new
# column would be missing and every read of the store would fail.
import sqlite3

OLD_DB = os.path.join(tempfile.mkdtemp(prefix="triage-verify-old-"), "state.db")
with sqlite3.connect(OLD_DB) as conn:
    conn.execute("""CREATE TABLE processed_tickets (
        ticket_id TEXT PRIMARY KEY,
        accepted_at TEXT NOT NULL,
        note_written INTEGER NOT NULL DEFAULT 0
    )""")
    conn.execute("INSERT INTO processed_tickets VALUES ('99', 'then', 1)")

os.environ["TRIAGE_STATE_DB"] = OLD_DB
del sys.modules["idempotency"]
migrated = importlib.import_module("idempotency")

state = migrated.completed_actions(99)
check("an older store gains the columns it is missing",
      sorted(state), sorted(migrated.ACTIONS))
check("what it already recorded survives", state["note_written"], True)
check("a column added by the migration reads as not done", state["paged_fallback"], False)
check("and the migrated store still works", migrated.claim_ticket(99), False)

print()
if failed:
    print(f"FAILED: {', '.join(failed)}")
    sys.exit(1)
print(f"All {ran} checks passed. Temporary store: {TEST_DB}")
