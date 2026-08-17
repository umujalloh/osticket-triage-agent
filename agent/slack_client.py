import os
import time

import requests

# The channel names come from the action table, which is what selects a channel
# for a classification. This module posts to the channel it is handed.
from action_table import INCIDENTS, REVIEW, URGENT
from schemas import Category, EnrichmentOutcome, Severity, enrichment_line
from writes import writes_enabled

WEBHOOKS = {
    URGENT: os.getenv("SLACK_WEBHOOK_URGENT"),
    INCIDENTS: os.getenv("SLACK_WEBHOOK_INCIDENTS"),
    REVIEW: os.getenv("SLACK_WEBHOOK_REVIEW"),
}
OSTICKET_BASE_URL = os.getenv("OSTICKET_BASE_URL")

# Asserted only when writes are on, the one relaxation of the fail-closed rule.
# Reasoning in architecture.md, Section 7. All three are required together: a
# deployment missing one would believe it is alerting on the class of ticket
# that webhook carries.
if writes_enabled():
    missing = [name for name, url in WEBHOOKS.items() if not url]
    if missing:
        raise RuntimeError(
            "ENABLE_WRITES is true, so a webhook is required for every channel. "
            f"Missing: {', '.join(sorted(missing))}"
        )
    if not OSTICKET_BASE_URL:
        raise RuntimeError("OSTICKET_BASE_URL must be set when ENABLE_WRITES is true")

DONE = "done"
SKIPPED = "skipped_writes_disabled"

SEVERITY_ICON = {
    Severity.critical: ":red_circle:",
    Severity.high: ":large_orange_circle:",
    Severity.medium: ":large_yellow_circle:",
    Severity.low: ":white_circle:",
}
REVIEW_ICON = ":white_circle:"

class SlackError(Exception):
    def __init__(self, failure_type: str, message: str):
        self.failure_type = failure_type
        super().__init__(message)

def build_message(ticket_id, ticket_number, classification, channel, mention=False,
                  outcome=EnrichmentOutcome.not_eligible, event_count=None) -> str:
    """Assembles the alert from values the agent generated, and nothing a user
    typed.

    The channel and the mention are decided by the action table and passed in,
    so the contract lives in one module rather than two.

    The ticket subject is absent on purpose: it is attacker-controlled text and
    Slack renders bare URLs as links, so including it would let anyone who files
    a ticket put a clickable link into a trusted channel under the agent's name.
    What crosses to Slack is listed in architecture.md, Section 8.
    """
    category = classification.category.value

    if channel == REVIEW:
        # Severity is a guess on a ticket nobody could place, so the reason it
        # is here is shown instead.
        head = f"{REVIEW_ICON} *{category}*  ·  Ticket #{ticket_number or ticket_id}"
        if classification.category != Category.unclear:
            head += "  ·  low confidence"
    else:
        icon = SEVERITY_ICON.get(classification.severity, REVIEW_ICON)
        head = (f"{icon} *{classification.severity.value} {category}*"
                f"  ·  Ticket #{ticket_number or ticket_id}")

    lines = ["<!here>", head] if mention else [head]

    line = enrichment_line(outcome, event_count)
    if line:
        lines.append(line)

    # A raw URL rather than text hiding one, so a reader can see where it points
    # before clicking. Anyone holding a webhook can post a convincing fake.
    lines.append(f"{OSTICKET_BASE_URL.rstrip('/')}/scp/tickets.php?id={ticket_id}")
    return "\n".join(lines)

def post_alert(channel: str, text: str) -> str:
    """Posts one alert. Returns DONE, or SKIPPED when writes are off.

    Raises SlackError on failure and never reports a post that did not happen.
    The webhook URL is never included in an error, because these propagate into
    console output and the audit index.
    """
    if not writes_enabled():
        return SKIPPED
    if channel not in WEBHOOKS:
        raise SlackError("bad_request", f"Unknown channel: {channel}")

    url = WEBHOOKS[channel]
    last_error = None
    for attempt in range(3):
        try:
            response = requests.post(url, json={"text": text}, timeout=10)
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            # The exception text embeds the URL, so only its type is reported.
            last_error = ("server_down", f"Could not reach Slack for the {channel} channel")
            time.sleep([2, 5, 10][attempt])
            continue
        except requests.exceptions.RequestException as e:
            raise SlackError("unknown", f"{type(e).__name__} posting to the {channel} channel")

        if response.status_code == 200:
            return DONE
        # A malformed payload, a disabled app, a revoked webhook and an archived
        # channel are none of them fixed by trying again.
        if response.status_code in (400, 403, 404, 410):
            raise SlackError(
                "bad_request",
                f"Slack refused the post to {channel}: HTTP {response.status_code} "
                f"{response.text[:100]}",
            )
        if response.status_code == 429:
            last_error = ("rate_limited", f"Slack rate limited the {channel} channel")
            time.sleep([5, 15, 30][attempt])
            continue
        raise SlackError(
            "unknown", f"Unexpected Slack response for {channel}: HTTP {response.status_code}"
        )

    failure_type, message = last_error
    raise SlackError(failure_type, message)
