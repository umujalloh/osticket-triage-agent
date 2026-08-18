from collections import Counter

from schemas import EnrichmentOutcome, enrichment_line

# Human label to the Splunk fields that feed it. Several vendors name the same
# thing differently and BOTSv3 has no CIM normalisation, so the grouping happens
# here rather than in the query. Order is the reading order of the note, so
# outcomes come before the addresses that produced them.
FIELD_GROUPS = (
    ("Sign-in outcomes", ("loginStatus",)),
    ("Source addresses", ("ipAddress", "src_ip")),
    ("Destination addresses", ("dest_ip",)),
    ("Accounts", ("userPrincipalName", "user", "email")),
    ("Applications", ("appDisplayName",)),
    ("Error codes", ("signinErrorCode",)),
    ("Actions", ("action",)),
)

# Bounded here rather than trusting the query's head 20, which lives in another
# module and could change. High enough that current data never truncates.
MAX_VALUES_PER_LINE = 20

def _clean(values):
    """Drops values a reader cannot use.

    Splunk returns whatever the source logged, which includes stray
    punctuation. One BOTSv3 event carries an email field of a single
    backslash. Anything without an alphanumeric character is noise in a note.
    """
    out = set()
    for value in values:
        text = str(value).strip()
        if text and any(c.isalnum() for c in text):
            out.add(text)
    return sorted(out)

def _selection(query):
    """The part of the query that chooses events, without the formatting.

    An analyst pasting this into Splunk should see the matching events, so the
    table and head clauses that narrow the agent's own view are left off.
    """
    if not query:
        return None
    selection = query.split("|")[0].strip()
    # Splunk's search bar implies the leading search command, so leaving it in
    # only makes the line stutter.
    return selection[7:].strip() if selection.startswith("search ") else selection

def _finish(lines, audited):
    """Closes the note, recording an unrecorded decision when there is one.

    A failed classification audit write means nothing outside this ticket
    explains how it was classified, so the ticket carries that itself. osTicket
    is reachable when Splunk is not. architecture.md, Section 9.
    """
    if not audited:
        lines += ["", "No audit record."]
    return "\n".join(lines)

def build_note(classification, outcome=EnrichmentOutcome.not_eligible,
               events=None, query=None, audited=True) -> str:
    """Assembles the internal note body from enrichment results.

    Written in code, never by Claude, so a ticket cannot influence what the
    note says about it. Returns the body only; the title is set by the caller.

    The four enrichment outcomes are in schemas.py, shared with the alert so the
    two cannot describe the same search differently.
    """
    lines = [
        f"{classification.category.value} / {classification.severity.value} "
        f"/ {classification.confidence.value}",
    ]
    selection = _selection(query)

    # A ticket that was never eligible has no search to report, so the note is
    # the classification alone.
    if outcome == EnrichmentOutcome.not_eligible:
        return _finish(lines, audited)

    # Anything other than a completed search with results is one line: nothing
    # was searched, or the search found nothing, or it did not finish.
    if outcome != EnrichmentOutcome.completed or not events:
        lines += ["", enrichment_line(outcome, len(events) if events else 0)]
        if selection:
            lines += ["", f"Search: {selection}"]
        return _finish(lines, audited)

    lines.append("")
    times = sorted(e["_time"] for e in events if e.get("_time"))
    if times:
        lines.append(f"{len(events)} events, {times[0]} to {times[-1]}.")
    else:
        lines.append(f"{len(events)} events.")
    lines.append("")

    width = max(len(label) for label, _ in FIELD_GROUPS) + 1
    for label, fields in FIELD_GROUPS:
        values = _clean(v for e in events for f in fields if (v := e.get(f)))
        if not values:
            continue
        shown = values[:MAX_VALUES_PER_LINE]
        text = ", ".join(shown)
        if len(values) > len(shown):
            text += f" (first {len(shown)} of {len(values)})"
        lines.append(f"{(label + ':').ljust(width)} {text}")

    sourcetypes = Counter(e.get("sourcetype", "unknown") for e in events)
    lines += ["", "Sources: " + ", ".join(
        f"{name} ({count})" for name, count in sourcetypes.most_common()
    )]

    if selection:
        lines += ["", f"Search: {selection}"]

    return _finish(lines, audited)
