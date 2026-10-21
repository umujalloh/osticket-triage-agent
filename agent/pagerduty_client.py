import hashlib
import hmac
import os
import time
from urllib.parse import urlparse

import requests

from action_table import NOTIFY, WAKE
from schemas import PAGE_CONFIRMED, PAGE_NO_INCIDENT, PAGE_UNCONFIRMED, Severity
from writes import writes_enabled

# The Events API v2 endpoint is the same for every account in a region and holds
# no secret, so it is configuration rather than a credential. EU accounts use
# events.eu.pagerduty.com.
PAGERDUTY_EVENTS_URL = os.getenv(
    "PAGERDUTY_EVENTS_URL", "https://events.pagerduty.com/v2/enqueue"
)
# One key per destination, the same shape as the Slack webhooks. PagerDuty's UI
# calls these Integration Keys; the API field is routing_key. Urgency belongs to
# the service, not the event, so two services is the only way an event can
# choose how loudly it arrives.
ROUTING_KEYS = {
    WAKE: os.getenv("PAGERDUTY_ROUTING_KEY_WAKE"),
    NOTIFY: os.getenv("PAGERDUTY_ROUTING_KEY_NOTIFY"),
}
OSTICKET_BASE_URL = os.getenv("OSTICKET_BASE_URL")

# The REST API, used only to confirm that each page reached an open incident
# and to ask whether each routing key still reaches a live PagerDuty service.
# A read-only REST API key is enough. One made under API Access Keys reads the
# whole PagerDuty account, which architecture.md, Section 8 records.
PAGERDUTY_API_URL = os.getenv("PAGERDUTY_API_URL", "https://api.pagerduty.com")
PAGERDUTY_API_KEY = os.getenv("PAGERDUTY_API_KEY")

# The secret behind the deduplication key. It has to be set even when writes
# are off, because a page is built before send_page checks the switch. It is
# not one of the shared secrets. Rotating those would change the dedup key of
# an incident that is already open.
PAGERDUTY_DEDUP_SECRET = os.getenv("PAGERDUTY_DEDUP_SECRET")
if not PAGERDUTY_DEDUP_SECRET:
    raise RuntimeError("PAGERDUTY_DEDUP_SECRET is not set")

# Asserted only when writes are on, the same exception the Slack webhooks get and
# for the same reason. Nothing is ever sent with the kill switch off, so a
# read-only deployment should not have to hold a credential it cannot use. Both
# are required together, since a deployment missing one would believe it is
# escalating a class of incident it cannot reach.
if writes_enabled():
    missing = [name for name, key in ROUTING_KEYS.items() if not key]
    if missing:
        raise RuntimeError(
            "ENABLE_WRITES is true, so a routing key is required for every page "
            f"destination. Missing: {', '.join(sorted(missing))}"
        )
    # Without it no page can be confirmed and the routing key check cannot
    # run, so a dead routing key would go unnoticed.
    if not PAGERDUTY_API_KEY:
        raise RuntimeError(
            "ENABLE_WRITES is true, so PAGERDUTY_API_KEY is required to confirm "
            "pages and to check that the routing keys still reach a PagerDuty "
            "service"
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

def _dedup_key(ticket_id) -> str:
    """The deduplication key for a ticket.

    The Events API resolves and acknowledges an incident on the routing key and
    the dedup key. Ticket ids are small consecutive integers, so using one
    directly would let anyone holding a stolen routing key close real incidents
    by counting from one. The HMAC leaves nothing to count.

    The same ticket always produces the same key. The WAKE and NOTIFY pages for
    one ticket share it, and the service they arrive at is what keeps them
    apart.
    """
    return hmac.new(
        PAGERDUTY_DEDUP_SECRET.encode(),
        str(ticket_id).encode(),
        hashlib.sha256,
    ).hexdigest()

def build_page(ticket_id, ticket_number, classification) -> dict:
    """The page for a ticket the table said to page on.

    Carries nothing a user typed. The ticket subject is absent for the reason in
    architecture.md, Section 8.

    No enrichment result, because the page is sent before enrichment runs. A
    count would have been the only field that varies between one page and the
    next, and waiting for it put the pager behind a Splunk call that can retry
    for over a minute. The enrichment lands on the ticket a moment later,
    which is where a woken responder is going anyway.
    """
    summary = (f"{classification.severity.value} {classification.category.value}"
               f"  ·  Ticket #{ticket_number or ticket_id}")
    return _event(ticket_id, summary, classification.severity)

def build_fallback_page(ticket_id, ticket_number, classification) -> dict:
    """The WAKE page sent when a critical could not be delivered to Slack.

    Only a critical at low confidence reaches this. It already paged NOTIFY,
    and the channel post that was meant to carry it failed, so the delivery
    failure is what upgrades it to an interruption.

    It leads with that failure because that is what justifies waking someone.
    Leading with the classification would read exactly like a confident
    critical, which is the one thing this page must not do, and the responder is
    owed that distinction.

    It goes to a different service from the NOTIFY page it follows, so the
    shared dedup key raises a second incident rather than folding into the quiet
    one. That is the intent. The quiet incident is the record; this is the
    interruption.
    """
    summary = (f"alert delivery failed  ·  Ticket #{ticket_number or ticket_id}"
               f"  ·  {classification.severity.value} "
               f"{classification.category.value}, "
               f"{classification.confidence.value.replace('_', ' ')}")
    return _event(ticket_id, summary, classification.severity)

def _event(ticket_id, summary, severity) -> dict:
    """Assembles the request body.

    dedup_key is derived from the ticket id, so a replay PagerDuty sees twice
    attaches to the open incident instead of waking someone again. The
    idempotency store is the first guard; this is the one that still holds when
    the store is wrong. _dedup_key has the reason it is derived.

    The link's text is the URL itself rather than a friendly label. Anyone
    holding the routing key can create a convincing incident, so a responder
    should see where a link points before tapping it, the same rule the Slack
    alert follows.
    """
    url = _ticket_url(ticket_id)
    return {
        "event_action": "trigger",
        "dedup_key": _dedup_key(ticket_id),
        "payload": {
            "summary": summary,
            "severity": PAGERDUTY_SEVERITY[severity],
            "source": urlparse(OSTICKET_BASE_URL).netloc or "osticket",
        },
        "links": [{"href": url, "text": url}],
    }

# No wait after the last attempt, since no call follows it.
ATTEMPTS = 3

def send_page(destination: str, event: dict) -> str:
    """Sends one page to the destination it is handed. Returns DONE, or SKIPPED
    when writes are off.

    The destination is decided by the action table and passed in, so the
    contract lives in one module rather than two.

    Raises PagerDutyError on failure and never reports a page that did not
    happen. The routing key travels in the body rather than the URL, so an
    exception carrying the request URL is safe here in a way it is not for a
    Slack webhook. The response body is never recorded, since a rejection can
    quote the field it rejected.
    """
    if not writes_enabled():
        return SKIPPED
    if destination not in ROUTING_KEYS:
        raise PagerDutyError("bad_request", f"Unknown page destination: {destination}")

    body = dict(event, routing_key=ROUTING_KEYS[destination])
    last_error = None
    for attempt in range(ATTEMPTS):
        try:
            response = requests.post(PAGERDUTY_EVENTS_URL, json=body, timeout=10)
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            last_error = ("server_down", f"Could not reach PagerDuty for the {destination} service")
            if attempt < ATTEMPTS - 1:
                time.sleep([2, 5][attempt])
            continue
        except requests.exceptions.RequestException as e:
            raise PagerDutyError("unknown", f"{type(e).__name__} sending the {destination} page")

        # The Events API answers 202, not 200, because it queues the event.
        if response.status_code == 202:
            return DONE
        # A malformed routing key or body is refused, and trying again does not
        # fix it. A page whose routing key's integration was deleted, or whose
        # PagerDuty service is disabled or in maintenance, is answered 202 and
        # never reaches here. confirm_page and the routing key check below
        # catch it.
        if response.status_code in (400, 401, 403, 404):
            raise PagerDutyError(
                "bad_request",
                f"PagerDuty refused the {destination} page: HTTP {response.status_code}",
            )
        if response.status_code == 429:
            last_error = ("rate_limited", f"PagerDuty rate limited the {destination} service")
            if attempt < ATTEMPTS - 1:
                time.sleep([5, 15][attempt])
            continue
        # A 503 says the service is down for now, so a later attempt can get past it.
        if response.status_code == 503:
            last_error = ("server_down", f"PagerDuty is unavailable for the {destination} service")
            if attempt < ATTEMPTS - 1:
                time.sleep([2, 5][attempt])
            continue
        raise PagerDutyError(
            "unknown", f"Unexpected PagerDuty response for {destination}: HTTP {response.status_code}"
        )

    failure_type, message = last_error
    raise PagerDutyError(failure_type, message)

ALIVE = "alive"
DEAD = "dead"
UNCHECKED = "unchecked"

# The statuses PagerDuty gives a PagerDuty service that creates incidents.
# warning and critical mean incidents are open on it.
LIVE_SERVICE_STATUSES = {"active", "warning", "critical"}
# A PagerDuty service in either status takes a page with 202 and creates no
# incident. Any other status is treated as dead too, so a status PagerDuty
# adds later raises the alert.
DEAD_SERVICE_STATUSES = {
    "disabled": "is on a disabled PagerDuty service",
    "maintenance": "is on a PagerDuty service in maintenance",
}

def _unchecked(because):
    reason = f"could not be checked, because {because}"
    return {dest: (UNCHECKED, reason) for dest in ROUTING_KEYS}

def check_routing_keys() -> dict:
    """Whether each destination's routing key still reaches a live PagerDuty
    service.

    The Events API answers 202 to a page whose routing key's integration was
    deleted, or whose PagerDuty service is disabled or in maintenance, and
    creates no incident. confirm_page catches that when a page is sent, and
    this catches it between pages, from the REST API's list of every
    PagerDuty service with its integrations.

    Returns {destination: (result, reason)}, where result is ALIVE, DEAD or
    UNCHECKED, and reason finishes a sentence that starts "The wake routing
    key", so the console and the alert email read as plain sentences.
    UNCHECKED means the check did not get an answer it could use. It is
    reported as its own result, so revoking the REST API key cannot blind the
    check. Never raises, for the same reason. No routing key or REST API key
    appears in a reason.
    """
    try:
        return _check_routing_keys()
    except Exception as e:
        return _unchecked(f"the check failed with {type(e).__name__}")

# Statuses a retry can clear. A 401 or 403 is not retried.
RETRY_STATUSES = {429, 500, 502, 503, 504}

def _get_services_page(headers, offset):
    """One page of the PagerDuty service listing.

    A dropped request or an answer in RETRY_STATUSES is tried again, ATTEMPTS
    times in all, because one network blip would otherwise mark both routing
    keys unchecked and send an alert email for nothing. The last failure is
    returned or raised for the caller to report.
    """
    for attempt in range(ATTEMPTS):
        last = attempt == ATTEMPTS - 1
        try:
            response = requests.get(
                f"{PAGERDUTY_API_URL.rstrip('/')}/services", headers=headers,
                params={"include[]": "integrations", "limit": 100,
                        "offset": offset},
                timeout=15,
            )
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            if last:
                raise
        else:
            if last or response.status_code not in RETRY_STATUSES:
                return response
        time.sleep([2, 5][attempt])

def _rest_headers():
    return {
        "Authorization": f"Token token={PAGERDUTY_API_KEY}",
        "Accept": "application/vnd.pagerduty+json;version=2",
    }

class _ListingFailed(Exception):
    """The REST API gave no usable listing. The message is the reason, worded
    to follow "because"."""

def _list_services(headers) -> list:
    """Every PagerDuty service in the account, with its integrations."""
    services, offset = [], 0
    try:
        while True:
            response = _get_services_page(headers, offset)
            if response.status_code != 200:
                raise _ListingFailed("the PagerDuty REST API answered "
                                     f"HTTP {response.status_code}")
            body = response.json()
            page = body.get("services") or []
            services.extend(page)
            if not body.get("more") or not page:
                return services
            offset += len(page)
    # requests' JSONDecodeError is both a ValueError and a RequestException,
    # so it has to be caught first.
    except ValueError:
        raise _ListingFailed("the PagerDuty REST API sent an unreadable answer")
    except requests.exceptions.RequestException:
        raise _ListingFailed("the PagerDuty REST API could not be reached")

def _check_routing_keys() -> dict:
    try:
        services = _list_services(_rest_headers())
    except _ListingFailed as e:
        return _unchecked(str(e))

    status_by_key = {}
    for service in services:
        for integration in service.get("integrations") or []:
            key = integration.get("integration_key")
            if key:
                status_by_key[key] = service.get("status")

    results = {}
    for dest, key in ROUTING_KEYS.items():
        if key not in status_by_key:
            results[dest] = (DEAD, "reaches no PagerDuty service")
            continue
        status = status_by_key[key]
        if status in LIVE_SERVICE_STATUSES:
            results[dest] = (ALIVE, "reaches a live PagerDuty service")
        elif status in DEAD_SERVICE_STATUSES:
            results[dest] = (DEAD, DEAD_SERVICE_STATUSES[status])
        else:
            results[dest] = (DEAD, "is on a PagerDuty service in a status the "
                                   "agent does not recognize")
    return results

# On 2026-10-10, accepted pages showed in the REST API between 1.1 and 3.2
# seconds after the 202. The wait leaves a wide margin over that.
CONFIRM_POLL_SECONDS = 2
CONFIRM_WAIT_SECONDS = 20

def confirm_page(destination: str, dedup_key: str,
                 include_resolved: bool = False) -> str:
    """Whether a page PagerDuty answered 202 reached an open incident.

    A 202 says only that the event was queued. A page whose routing key is dead
    is answered 202 and dropped, so the agent asks the REST API for an open
    incident on the destination's PagerDuty service holding an alert with the
    page's dedup key. PagerDuty can group a page into an incident an earlier
    page opened, and the search still finds it there, so it is not limited to
    incidents created after the page.

    include_resolved also counts a resolved incident. A page an earlier start
    sent may have been answered and resolved since, and the dedup key belongs
    to one ticket, so a resolved incident holding it is that page's.

    Returns PAGE_CONFIRMED when it finds one, PAGE_NO_INCIDENT when no
    PagerDuty service holds the routing key or the last lookup answered with
    none, and PAGE_UNCONFIRMED when the last lookup gave no usable answer.
    Never raises, so a broken lookup cannot stop the alert that reports the
    page.
    """
    try:
        return _confirm_page(destination, dedup_key, include_resolved)
    except Exception:
        return PAGE_UNCONFIRMED

def _confirm_page(destination, dedup_key, include_resolved) -> str:
    headers = _rest_headers()
    try:
        services = _list_services(headers)
    except _ListingFailed:
        return PAGE_UNCONFIRMED
    routing_key = ROUTING_KEYS[destination]
    service_id = next((service.get("id") for service in services
                       if any(integration.get("integration_key") == routing_key
                              for integration in service.get("integrations") or [])),
                      None)
    if service_id is None:
        return PAGE_NO_INCIDENT

    # WAKE and NOTIFY pages for one ticket share a dedup key, so filtering by
    # PagerDuty service separates this page's incident from the other one.
    params = {"incident_key": dedup_key, "service_ids[]": service_id,
              "statuses[]": ["triggered", "acknowledged"]
              + (["resolved"] if include_resolved else [])}
    deadline = time.monotonic() + CONFIRM_WAIT_SECONDS
    while True:
        answered = False
        try:
            response = requests.get(f"{PAGERDUTY_API_URL.rstrip('/')}/incidents",
                                    headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                if response.json().get("incidents"):
                    return PAGE_CONFIRMED
                answered = True
        # An answer that is not a list of incidents counts as no answer, so
        # the lookup keeps trying until the deadline.
        except (requests.exceptions.RequestException, ValueError, AttributeError):
            pass
        # Decided on the last answer, so a REST API that failed at the end is
        # not read as an empty one.
        if time.monotonic() >= deadline:
            return PAGE_NO_INCIDENT if answered else PAGE_UNCONFIRMED
        time.sleep(CONFIRM_POLL_SECONDS)
