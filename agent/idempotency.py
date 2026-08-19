import os
import sqlite3
from datetime import datetime, timezone

DB_PATH = os.getenv(
    "TRIAGE_STATE_DB",
    os.path.join(os.path.dirname(__file__), "triage_state.db"),
)

# One column per effectful action. Adding a name here adds it to the schema and
# to any database that already exists, see init_db.
#
# The two pages are separate columns because one ticket can receive both. A
# critical at low confidence pages NOTIFY at once, and pages WAKE afterwards if
# its channel post fails. A single column would let the first refuse the second.
ACTIONS = ("note_written", "priority_set", "slack_posted", "paged", "paged_fallback")

_SCHEMA = f"""
CREATE TABLE IF NOT EXISTS processed_tickets (
    ticket_id   TEXT PRIMARY KEY,
    accepted_at TEXT NOT NULL,
    {", ".join(f"{a} INTEGER NOT NULL DEFAULT 0" for a in ACTIONS)}
);
"""

def _connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    # Background tasks run in a threadpool, so readers and the writer overlap.
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def _key(ticket_id) -> str:
    """osTicket sends an integer, but the webhook accepts a string too.
    Both spellings name the same ticket, so they have to collide here or a
    resend with the other type would be processed twice.
    """
    return str(ticket_id)

def init_db():
    """Creates the store, and adds any action column an older one is missing.

    CREATE TABLE IF NOT EXISTS does nothing to a table that already exists, so
    adding a name to ACTIONS would leave every existing store one column short
    and every read of it failing. Each missing column is added with the same
    default a new table would give it, which reads as "this action has not
    happened", and that is the right answer for a ticket processed before the
    action existed.
    """
    with _connect() as conn:
        conn.executescript(_SCHEMA)
        have = {r["name"] for r in conn.execute("PRAGMA table_info(processed_tickets)")}
        for action in ACTIONS:
            if action not in have:
                conn.execute(
                    f"ALTER TABLE processed_tickets "
                    f"ADD COLUMN {action} INTEGER NOT NULL DEFAULT 0"
                )
                print(f"Idempotency store: added the {action} column")

# A store that cannot be opened means duplicate protection is not in force,
# and writes are not safe without it.
try:
    init_db()
except sqlite3.Error as e:
    raise RuntimeError(f"Could not open the idempotency store at {DB_PATH}: {e}")

def claim_ticket(ticket_id) -> bool:
    """Records the ticket as accepted and reports whether this caller won it.

    Returns True the first time a ticket ID is seen and False every time
    after, including across restarts. The insert and the check are one
    statement, so two overlapping requests for the same ticket cannot both
    win.
    """
    with _connect() as conn:
        cur = conn.execute(
            "INSERT OR IGNORE INTO processed_tickets (ticket_id, accepted_at) VALUES (?, ?)",
            (_key(ticket_id), datetime.now(timezone.utc).isoformat()),
        )
        return cur.rowcount == 1

def mark_done(ticket_id, action):
    """Records that one action completed for a ticket.

    claim_ticket should already have created the row. If it has not, the row is
    created here anyway: losing the record of a completed action is what lets a
    retry repeat it, which is worse than a row with a late timestamp. The
    anomaly is printed rather than raised, because raising after a successful
    write would report it as a failure and invite the retry.
    """
    if action not in ACTIONS:
        raise ValueError(f"Unknown action: {action}")
    with _connect() as conn:
        unclaimed = conn.execute(
            "INSERT OR IGNORE INTO processed_tickets (ticket_id, accepted_at) VALUES (?, ?)",
            (_key(ticket_id), datetime.now(timezone.utc).isoformat()),
        ).rowcount == 1
        conn.execute(
            f"UPDATE processed_tickets SET {action} = 1 WHERE ticket_id = ?",
            (_key(ticket_id),),
        )
    if unclaimed:
        print(f"Ticket {ticket_id}: recorded {action} for a ticket that was never claimed")

def completed_actions(ticket_id) -> dict:
    """Returns which actions have completed for a ticket.

    An unknown ticket reports every action as incomplete rather than raising,
    so a caller can treat "never seen" and "nothing done yet" the same way.
    """
    with _connect() as conn:
        row = conn.execute(
            f"SELECT {', '.join(ACTIONS)} FROM processed_tickets WHERE ticket_id = ?",
            (_key(ticket_id),),
        ).fetchone()
    if row is None:
        return {a: False for a in ACTIONS}
    return {a: bool(row[a]) for a in ACTIONS}
