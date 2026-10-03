import ipaddress
import re
from enum import Enum
from typing import Optional
from pydantic import BaseModel, ConfigDict, field_validator, model_validator

class Category(str, Enum):
    security_incident = "security_incident"
    security_question = "security_question"
    it_support = "it_support"
    unclear = "unclear"

class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"

class Confidence(str, Enum):
    high_confidence = "high_confidence"
    low_confidence = "low_confidence"

class EnrichmentOutcome(str, Enum):
    """How enrichment ended, which the note and the alert both report.

    Four states rather than two, because "searched and found nothing" and
    "never searched" read the same to a reader and mean opposite things. See
    architecture.md, Section 7.
    """
    not_eligible = "not_eligible"
    no_identifier = "no_identifier"
    completed = "completed"
    unavailable = "unavailable"

# The wording the design specifies, kept here so the note and the alert cannot
# drift apart. `completed` has no fixed text: it renders with its result count.
ENRICHMENT_TEXT = {
    EnrichmentOutcome.no_identifier: "no verified identifier",
    EnrichmentOutcome.unavailable: "enrichment unavailable",
}

def enrichment_line(outcome, event_count=None):
    """The one line describing enrichment, or None when there is nothing to say."""
    if outcome == EnrichmentOutcome.not_eligible:
        return None
    if outcome == EnrichmentOutcome.completed:
        if not event_count:
            return "no related events"
        return f"{event_count} related events"
    return ENRICHMENT_TEXT[outcome]

HOSTNAME_PATTERN = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9._-]{0,253}[a-zA-Z0-9])?$")
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9._-]{1,64}\$?$")

class TicketClassification(BaseModel):
    # A field the tool definition does not name fails validation. Dropping it
    # quietly would accept an answer shaped differently from the one asked for.
    model_config = ConfigDict(extra="forbid")

    category: Category
    severity: Severity
    confidence: Confidence
    hostname: Optional[str] = None
    username: Optional[str] = None
    source_ip: Optional[str] = None

    @field_validator("hostname")
    @classmethod
    def validate_hostname(cls, v):
        if v is None:
            return v
        if not HOSTNAME_PATTERN.match(v):
            return None
        return v

    @field_validator("username")
    @classmethod
    def validate_username(cls, v):
        if v is None:
            return v
        if not USERNAME_PATTERN.match(v):
            return None
        return v

    @field_validator("source_ip")
    @classmethod
    def validate_source_ip(cls, v):
        if v is None:
            return v
        try:
            ipaddress.ip_address(v)
        except ValueError:
            return None
        return v

    # The rubric offers critical only to a security incident, and an unclear
    # ticket is always low confidence. The prompt offers critical only to a
    # security incident and states the unclear rule, and this checks that
    # Claude kept to both, so a pair the rubric forbids fails
    # validation and goes to review. A routine ticket marked critical would
    # otherwise be raised to emergency priority with no alert saying why.
    @model_validator(mode="after")
    def validate_rubric_pairs(self):
        if (self.severity == Severity.critical
                and self.category != Category.security_incident):
            raise ValueError("critical is only for a security_incident")
        if (self.category == Category.unclear
                and self.confidence != Confidence.low_confidence):
            raise ValueError("an unclear ticket must be low_confidence")
        return self
