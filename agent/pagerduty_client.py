import os
import time
from urllib.parse import urlparse

import requests

from schemas import Severity
from writes import writes_enabled

# The Events API v2 endpoint is the same for every account in a region and holds
# no secret, so it is configuration rather than a credential. EU accounts use
# events.eu.pagerduty.com.
PAGERDUTY_EVENTS_URL = os.getenv(
    "PAGERDUTY_EVENTS_URL", "https://events.pagerduty.com/v2/enqueue"
)
# PagerDuty's UI calls this the Integration Key. The API field is routing_key.
PAGERDUTY_ROUTING_KEY = os.getenv("PAGERDUTY_ROUTING_KEY")
OSTICKET_BASE_URL = os.getenv("OSTICKET_BASE_URL")

# Asserted only when writes are on, the same exception the Slack webhooks get and
# for the same reason. Nothing is ever sent with the kill switch off, so a
# read-only deployment should not have to hold a credential it cannot use.
if writes_enabled() and not PAGERDUTY_ROUTING_KEY:
    raise RuntimeError(
        "ENABLE_WRITES is true, so PAGERDUTY_ROUTING_KEY is required"
    )

DONE = "done"
SKIPPED = "skipped_writes_disabled"

# Ours to theirs. Only critical is reachable today, since the action table pages
# on critical alone, but mapping the rest keeps the assumption out of the code,
# so a table change would produce the right urgency rather than a silent lie.
PAGERDUTY_SEVERITY = {
    Severity.critical: "critical",
    Severity.high: "error",
    Severity.medium: "warning",
    Severity.low: "info",
}

class PagerDutyError(Exception):
    def __init__(self, failure_type: str, message: str):
        self.failure_type = failure_type
        super().__init__(message)

def _ticket_url(ticket_id) -> str:
    return f"{OSTICKET_BASE_URL.rstrip('/')}/scp/tickets.php?id={ticket_id}"

def build_page(ticket_id, ticket_number, classification) -> dict:
    """The page for a ticket the table said to page on.

    Carries nothing a user typed. The ticket subject is absent for the reason in
    architecture.md, Section 8.

    No enrichment result, because the page is sent before enrichment runs. A
    count would have been the only field that varies between one page and the
    next, and waiting for it put the pager behind a Splunk call that can retry
    for a minute and a half. The enrichment lands on the ticket a moment later,
    which is where a woken responder is going anyway.
    """
    summary = (f"{classification.severity.value} {classification.category.value}"
               f"  ·  Ticket #{ticket_number or ticket_id}")
    return _event(ticket_id, summary, classification.severity)

def build_fallback_page(ticket_id, ticket_number, classification) -> dict:
    """The page sent when a critical could not be delivered to Slack.

    It leads with the delivery failure because that is what justifies the
    interruption. Leading with the classification would read exactly like a
    confident critical, which is the one thing this page must not do. The table
    declined to page on it, and the responder is owed that distinction.
    """
    summary = (f"alert delivery failed  ·  Ticket #{ticket_number or ticket_id}"
               f"  ·  {classification.severity.value} "
               f"{classification.category.value}, "
               f"{classification.confidence.value.replace('_', ' ')}")
    return _event(ticket_id, summary, classification.severity)

def _event(ticket_id, summary, severity) -> dict:
    """Assembles the request body.

    dedup_key is the ticket id, so a replay PagerDuty sees twice attaches to the
    open incident instead of waking someone again. The idempotency store is the
    first guard; this is the one that still holds when the store is wrong.

    The link's text is the URL itself rather than a friendly label. Anyone
    holding the routing key can create a convincing incident, so a responder
    should see where a link points before tapping it, the same rule the Slack
    alert follows.
    """
    url = _ticket_url(ticket_id)
    return {
        "event_action": "trigger",
        "dedup_key": str(ticket_id),
        "payload": {
            "summary": summary,
            "severity": PAGERDUTY_SEVERITY[severity],
            "source": urlparse(OSTICKET_BASE_URL).netloc or "osticket",
        },
        "links": [{"href": url, "text": url}],
    }

def send_page(event: dict) -> str:
    """Sends one page. Returns DONE, or SKIPPED when writes are off.

    Raises PagerDutyError on failure and never reports a page that did not
    happen. The routing key travels in the body rather than the URL, so an
    exception carrying the request URL is safe here in a way it is not for a
    Slack webhook. Response text is still truncated, since a rejection can
    quote the field it rejected.
    """
    if not writes_enabled():
        return SKIPPED

    body = dict(event, routing_key=PAGERDUTY_ROUTING_KEY)
    last_error = None
    for attempt in range(3):
        try:
            response = requests.post(PAGERDUTY_EVENTS_URL, json=body, timeout=10)
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            last_error = ("server_down", "Could not reach PagerDuty")
            time.sleep([2, 5, 10][attempt])
            continue
        except requests.exceptions.RequestException as e:
            raise PagerDutyError("unknown", f"{type(e).__name__} sending the page")

        # The Events API answers 202, not 200, because it queues the event.
        if response.status_code == 202:
            return DONE
        # An invalid key, a malformed body and a disabled integration are none
        # of them fixed by trying again.
        if response.status_code in (400, 401, 403, 404):
            raise PagerDutyError(
                "bad_request",
                f"PagerDuty refused the page: HTTP {response.status_code} "
                f"{response.text[:100]}",
            )
        if response.status_code == 429:
            last_error = ("rate_limited", "PagerDuty rate limited the page")
            time.sleep([5, 15, 30][attempt])
            continue
        raise PagerDutyError(
            "unknown", f"Unexpected PagerDuty response: HTTP {response.status_code}"
        )

    failure_type, message = last_error
    raise PagerDutyError(failure_type, message)
