from dataclasses import dataclass

from schemas import Category, Confidence, Severity

# The table sets priority from severity for every category that writes a note,
# so category does not appear here. The values are osTicket's priority names.
PRIORITY_FOR_SEVERITY = {
    Severity.critical: "emergency",
    Severity.high: "high",
    Severity.medium: "normal",
    Severity.low: "low",
}

@dataclass(frozen=True)
class Actions:
    """What the agent does with one classification.

    Every field is decided by the table in docs/action-table.md and nothing
    else. Claude produces the classification; this turns it into actions.
    """
    enrich: bool = False
    write_note: bool = False
    set_priority: bool = False
    post_slack: bool = False
    page: bool = False
    route_security_queue: bool = False
    human_review: bool = False

# Only critical security incidents are enriched, at either confidence. Read
# the reasoning in docs/architecture.md, Section 7, before changing this.
def _should_enrich(category, severity) -> bool:
    return category == Category.security_incident and severity == Severity.critical

def actions_for(category, severity, confidence) -> Actions:
    """Implements docs/action-table.md. Change them together or neither."""
    enrich = _should_enrich(category, severity)

    # The override: unclear, or anything the classifier was not confident
    # about, goes to a human. It suppresses alerts and writes, not enrichment,
    # so a low-confidence critical still reaches the reviewer with context.
    if category == Category.unclear or confidence == Confidence.low_confidence:
        return Actions(enrich=enrich, human_review=True)

    if category == Category.security_incident:
        return Actions(
            enrich=enrich,
            write_note=True,
            set_priority=True,
            # Low severity is logged silently. Everything above it reaches the
            # team channel, and only critical wakes someone.
            post_slack=severity in (Severity.critical, Severity.high, Severity.medium),
            page=severity == Severity.critical,
        )

    if category == Category.security_question:
        return Actions(write_note=True, set_priority=True, route_security_queue=True)

    if category == Category.it_support:
        return Actions(write_note=True, set_priority=True)

    # A category exists that this function does not handle. Refusing is safer
    # than defaulting, which would silently pick an action for it.
    raise ValueError(f"No action table row for category {category!r}")
