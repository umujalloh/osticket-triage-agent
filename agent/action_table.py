from dataclasses import dataclass
from typing import Optional

from schemas import Category, Confidence, Severity

# The three Slack channels. They live here, not in slack_client, because which
# channel a ticket reaches is a column of docs/action-table.md, the same as the
# note and the page. The Slack client posts to whichever channel it is handed
# and decides nothing.
URGENT = "urgent"
INCIDENTS = "incidents"
REVIEW = "review"

# The two page destinations, named for what happens to the person rather than
# for the urgency setting that produces it. WAKE is meant to interrupt. NOTIFY
# creates an incident somebody owns and has to acknowledge, without waking them.
# Each is a separate PagerDuty service, because urgency is a property of the
# service and not something an event can ask for.
WAKE = "wake"
NOTIFY = "notify"

# The table sets priority from severity for every category that writes a note,
# so category does not appear here. The values are osTicket's priority names.
PRIORITY_FOR_SEVERITY = {
    Severity.critical: "emergency",
    Severity.high: "high",
    Severity.medium: "normal",
    Severity.low: "low",
}

# Every category the table has a row for. A category outside this tuple is
# refused rather than defaulted, so adding one to schemas.py without adding its
# row here fails loudly instead of silently picking an action for it.
HANDLED_CATEGORIES = (
    Category.security_incident,
    Category.security_question,
    Category.it_support,
    Category.unclear,
)

@dataclass(frozen=True)
class Actions:
    """What the agent does with one classification.

    Every field is decided by the table in docs/action-table.md and nothing
    else. Claude produces the classification; this turns it into actions.
    """
    enrich: bool = False
    write_note: bool = False
    set_priority: bool = False
    # None means no alert. One field rather than a channel plus a post_slack
    # flag, which could disagree with each other.
    channel: Optional[str] = None
    mention: bool = False
    # None means this row pages nowhere. A destination rather than a flag, for
    # the same reason channel is one.
    page: Optional[str] = None
    route_security_queue: bool = False
    human_review: bool = False

# Only critical security incidents are enriched, at either confidence. Read
# the reasoning in docs/architecture.md, Section 7, before changing this.
def _should_enrich(category, severity) -> bool:
    return category == Category.security_incident and severity == Severity.critical

def _channel_for(category, severity, confidence) -> Optional[str]:
    """The Channel column. None means this row alerts nowhere.

    Every security incident reaches a channel, split at the line the severity
    rubric already draws: critical means someone unauthorized holds access now,
    everything below it means nobody does. Tickets nobody could place, and
    tickets placed without confidence, go to review instead.
    """
    if category == Category.security_incident:
        return URGENT if severity == Severity.critical else INCIDENTS
    if category == Category.unclear or confidence == Confidence.low_confidence:
        return REVIEW
    return None

def _mentions(category, severity, confidence) -> bool:
    """A confident critical security incident mentions its channel.

    One at low confidence does not. It reaches the same channel and pages NOTIFY,
    so a mention would be the loudest signal on the classification the agent is
    least sure of, and it would shout at the whole team about something one
    person already owns.
    """
    return (category == Category.security_incident
            and severity == Severity.critical
            and confidence == Confidence.high_confidence)

def _page_for(category, severity, confidence) -> Optional[str]:
    """The Page column. None means this row pages nowhere.

    Only a critical security incident pages, and confidence decides which
    destination rather than whether one exists at all. Withholding the page
    entirely left a critical at low confidence with a channel post as its only
    push, which arrives last and behind every retry above it. A quiet page is
    still visibility, which is what confidence is supposed to gate.
    """
    if category != Category.security_incident or severity != Severity.critical:
        return None
    return WAKE if confidence == Confidence.high_confidence else NOTIFY

def actions_for(category, severity, confidence) -> Actions:
    """Implements docs/action-table.md. Change them together or neither."""
    if category not in HANDLED_CATEGORIES:
        raise ValueError(f"No action table row for category {category!r}")

    # The override, applied before any row. It changes how loudly a ticket is
    # escalated and nothing else. See the override rule in docs/action-table.md.
    human_review = (category == Category.unclear
                    or confidence == Confidence.low_confidence)

    return Actions(
        enrich=_should_enrich(category, severity),
        # True on all ten current rows: every ticket the agent classifies gets a
        # note and a priority. Kept as fields because the table decides them, so
        # a future row that must not write has somewhere to say so.
        write_note=True,
        set_priority=True,
        channel=_channel_for(category, severity, confidence),
        mention=_mentions(category, severity, confidence),
        # The override quietens the page rather than withholding it.
        page=_page_for(category, severity, confidence),
        route_security_queue=category == Category.security_question,
        human_review=human_review,
    )
