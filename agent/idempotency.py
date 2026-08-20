import os
import sqlite3
from datetime import datetime, timezone

from pydantic import ValidationError

from schemas import TicketClassification

DB_PATH = os.getenv(
    "TRIAGE_STATE_DB",
    os.path.join(os.path.dirname(__file__), "triage_state.db"),
)

# One column per thing that must not happen twice. Adding a name here adds it to
# the schema and to any database that already exists, see init_db.
#
# The two pages are separate columns because one ticket can receive both. A
# critical at low confidence pages NOTIFY at once, and pages WAKE afterwards if
# its channel post fails. A single column would let the first refuse the second.
#
# classification_audited is not an action anyone outside sees. It is here
# because a resumed ticket has to know whether the first attempt's audit write
# landed: re-logging records a decision that was made once as though it were
# made twice, and skipping it loses the record when the first write failed.
ACTIONS = ("classification_audited", "note_written", "priority_set",
           "slack_posted", "paged", "paged_fallback", "routed")

# Every column beyond the two the table is created with. Actions are flags; the
# classification is the decision itself, held so a resumed ticket finishes on
# the decision it was already given rather than asking Claude a second question.
COLUMNS = {
    **{a: "INTEGER NOT NULL DEFAULT 0" for a in ACTIONS},
    "classification": "TEXT",
}

_SCHEMA = f"""
CREATE TABLE IF NOT EXISTS processed_tickets (
    ticket_id   TEXT PRIMARY KEY,
    accepted_at TEXT NOT NULL,
    {", ".join(f"{name} {decl}" for name, decl in COLUMNS.items())}
);
"""

def _connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    # Background tasks run in a threadpool, so readers and the writer overlap.
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def ticket_key(ticket_id) -> str:
    """osTicket sends an integer, but the webhook accepts a string too.
    Both spellings name the same ticket, so they have to collide here or a
    resend with the other type would be processed twice.

    Public because anything else keeping per-ticket state has to agree with the
    store on what counts as the same ticket.
    """
    return str(ticket_id)

def init_db():
    """Creates the store, and adds any column an older one is missing.

    CREATE TABLE IF NOT EXISTS does nothing to a table that already exists, so
    adding a name to COLUMNS would leave every existing store one column short
    and every read of it failing. Each missing column is added with the same
    declaration a new table would give it. For an action that means a default
    reading "this has not happened", which is the right answer for a ticket
    processed before the action existed. For the classification it means NULL,
    read as "nothing was stored", so a ticket claimed by an older build
    classifies fresh instead of resuming on a decision that was never kept.
    """
    with _connect() as conn:
        conn.executescript(_SCHEMA)
        have = {r["name"] for r in conn.execute("PRAGMA table_info(processed_tickets)")}
        for name, decl in COLUMNS.items():
            if name not in have:
                conn.execute(
                    f"ALTER TABLE processed_tickets ADD COLUMN {name} {decl}"
                )
                print(f"Idempotency store: added the {name} column")

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
            (ticket_key(ticket_id), datetime.now(timezone.utc).isoformat()),
        )
        return cur.rowcount == 1

def _ensure_row(conn, ticket_id) -> bool:
    """Creates the ticket's row if it has none. Returns True if it created one.

    True means something is writing about a ticket that was never claimed, which
    every caller reports rather than raises.
    """
    return conn.execute(
        "INSERT OR IGNORE INTO processed_tickets (ticket_id, accepted_at) VALUES (?, ?)",
        (ticket_key(ticket_id), datetime.now(timezone.utc).isoformat()),
    ).rowcount == 1

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
        unclaimed = _ensure_row(conn, ticket_id)
        conn.execute(
            f"UPDATE processed_tickets SET {action} = 1 WHERE ticket_id = ?",
            (ticket_key(ticket_id),),
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
            (ticket_key(ticket_id),),
        ).fetchone()
    if row is None:
        return {a: False for a in ACTIONS}
    return {a: bool(row[a]) for a in ACTIONS}

def save_classification(ticket_id, classification):
    """Keeps the decision made for a ticket, before any action acts on it.

    A ticket the agent starts and does not finish is resumed later, and it has
    to finish on this decision rather than on a fresh one. Asking Claude twice
    invites two answers, and the second would be acting on a ticket an alert has
    already described in the first one's words.
    """
    with _connect() as conn:
        unclaimed = _ensure_row(conn, ticket_id)
        conn.execute(
            "UPDATE processed_tickets SET classification = ? WHERE ticket_id = ?",
            (classification.model_dump_json(), ticket_key(ticket_id)),
        )
    if unclaimed:
        print(f"Ticket {ticket_id}: stored a classification for a ticket that "
              f"was never claimed")

def stored_classification(ticket_id):
    """The decision already made for a ticket, or None if there is not one.

    None covers a ticket nobody has classified and a stored value this build can
    no longer read, and both mean the same thing to the caller: decide it now.
    Validating on the way out is what makes the second case safe, since a column
    written by an older schema would otherwise be handed on as a classification
    the action table never agreed to.
    """
    with _connect() as conn:
        row = conn.execute(
            "SELECT classification FROM processed_tickets WHERE ticket_id = ?",
            (ticket_key(ticket_id),),
        ).fetchone()
    if row is None or row["classification"] is None:
        return None
    try:
        return TicketClassification.model_validate_json(row["classification"])
    except ValidationError as e:
        print(f"Ticket {ticket_id}: stored classification is unreadable, "
              f"classifying again ({e.error_count()} error(s))")
        return None
