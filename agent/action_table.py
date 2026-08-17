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
    page: bool = False
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

def _mentions(category, severity) -> bool:
    """Every critical security incident mentions its channel.

    Independent of whether it pages: a page tasks the one person on call, a
    mention tells the rest of the team.
    """
    return category == Category.security_incident and severity == Severity.critical

def actions_for(category, severity, confidence) -> Actions:
    """Implements docs/action-table.md. Change them together or neither."""
    if category not in HANDLED_CATEGORIES:
        raise ValueError(f"No action table row for category {category!r}")

    # The override, applied before any row. It withholds the page and nothing
    # else: see the override rule in docs/action-table.md.
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
        mention=_mentions(category, severity),
        # The one action the override withholds.
        page=(category == Category.security_incident
              and severity == Severity.critical
              and confidence == Confidence.high_confidence),
        route_security_queue=category == Category.security_question,
        human_review=human_review,
    )
