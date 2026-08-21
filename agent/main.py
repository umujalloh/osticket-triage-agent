import asyncio
import hmac
import hashlib
import os
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import JSONResponse
from dotenv import load_dotenv

load_dotenv()

from action_table import actions_for, PRIORITY_FOR_SEVERITY, REVIEW, WAKE
from classifier import classify_ticket, ClassificationError
from idempotency import (
    claim_ticket, completed_actions, mark_done, save_classification,
    stored_classification, ticket_key,
)
from note_builder import build_note
from osticket_client import (
    write_note, set_priority, route_to_security, OsTicketWriteError, SKIPPED,
    ALREADY_WRITTEN, ALREADY_ROUTED,
)
from pagerduty_client import (
    build_page, build_fallback_page, send_page, PagerDutyError,
    SKIPPED as PD_SKIPPED,
)
from schemas import Category, EnrichmentOutcome, Severity
from slack_client import (
    build_message, build_failure_message, post_alert, SlackError,
    SKIPPED as SLACK_SKIPPED,
)
from writes import writes_enabled
from splunk_enrichment import build_enrichment_query, enrich_ticket, EnrichmentError
from splunk_logger import (
    log_request_rejected, log_resumed, log_heartbeat,
    log_classification, log_classification_failure,
    log_enrichment, log_enrichment_failure, log_enrichment_skipped,
    log_note_written, log_note_skipped, log_note_failure,
    log_priority_set, log_priority_skipped, log_priority_failure,
    log_slack_posted, log_slack_skipped, log_slack_failure,
    log_paged, log_page_skipped, log_page_failure,
    log_routed, log_routing_skipped, log_routing_failure,
    log_human_review,
)

HEARTBEAT_INTERVAL_SECONDS = int(os.getenv("HEARTBEAT_INTERVAL_SECONDS", "60"))

async def _heartbeat_loop():
    """Writes a liveness event to Splunk on a fixed interval, forever.

    The agent cannot report its own death. Everything else it writes is
    triggered by a ticket arriving, so an index that has gone quiet says
    nothing on its own: an idle night and a dead process look identical. These
    events are what tell them apart, and what a deployment alerts on is their
    absence. architecture.md, Section 9.

    Each beat is sent from a worker thread, because the Splunk client blocks
    and this loop runs on the event loop serving webhooks.
    """
    started = time.monotonic()
    while True:
        try:
            ok = await asyncio.to_thread(
                log_heartbeat,
                uptime_seconds=int(time.monotonic() - started),
                writes_enabled=writes_enabled(),
            )
            if not ok:
                print("Heartbeat: Splunk did not accept it")
        except asyncio.CancelledError:
            raise
        except Exception as e:
            # A heartbeat that raises must not take down the loop that proves
            # the agent is alive.
            print(f"Heartbeat failed: {type(e).__name__}: {e}")
        await asyncio.sleep(HEARTBEAT_INTERVAL_SECONDS)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Starts the heartbeat with the app, not with the module.

    Importing main must stay free of side effects, because the verifiers do it
    to exercise the decision logic and would otherwise beat against the real
    Splunk index while they ran.
    """
    beat = asyncio.create_task(_heartbeat_loop())
    print(f"Heartbeat every {HEARTBEAT_INTERVAL_SECONDS}s")
    try:
        yield
    finally:
        beat.cancel()

app = FastAPI(lifespan=lifespan)

print(f"Effectful writes are {'ENABLED' if writes_enabled() else 'DISABLED'}")

HMAC_SECRET = os.getenv("TRIAGE_HMAC_SECRET")
if not HMAC_SECRET:
    raise RuntimeError("TRIAGE_HMAC_SECRET is not set")

def verify_signature(raw_body: bytes, signature_header: str) -> bool:
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    received_signature = signature_header.split("=", 1)[1]
    expected_signature = hmac.new(
        HMAC_SECRET.encode(), raw_body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(received_signature, expected_signature)

REPLAY_WINDOW_SECONDS = 300
CLOCK_SKEW_TOLERANCE_SECONDS = 60

def is_fresh(created_at) -> bool:
    if not created_at:
        return False
    try:
        ts = datetime.fromisoformat(created_at)
    except (TypeError, ValueError):
        return False
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    age = (datetime.now(timezone.utc) - ts).total_seconds()
    return -CLOCK_SKEW_TOLERANCE_SECONDS <= age <= REPLAY_WINDOW_SECONDS

_in_flight = set()
_in_flight_lock = threading.Lock()

def begin_processing(ticket_id) -> bool:
    """Marks a ticket as being worked on now. False means it already was.

    The plugin retries a send that failed, and a send can fail after the agent
    has already accepted the ticket and started on it, so a retry can arrive
    mid-run. Without this, both runs read the same action columns as incomplete
    and both act on them.

    Held in memory rather than in the store, because the store is a file beside
    a single process and KNOWN_LIMITATIONS.md already says so. A restart empties
    this, which is correct: whatever it was tracking died with the process, and
    that ticket genuinely does need resuming.
    """
    with _in_flight_lock:
        key = ticket_key(ticket_id)
        if key in _in_flight:
            return False
        _in_flight.add(key)
        return True

def end_processing(ticket_id):
    with _in_flight_lock:
        _in_flight.discard(ticket_key(ticket_id))

# Named the way the action columns are, since it appears in the same list. A
# ticket carrying no decision has classification outstanding and nothing else,
# because nothing downstream of it can have run.
UNDECIDED = "classified"

def outstanding_actions(ticket_id) -> list:
    """What a ticket the store already holds still has left to do.

    This is what separates a ticket the agent finished from one it was
    interrupted partway through. A delivery the plugin repeats reaches the first
    as a duplicate and the second as work to pick up. Empty means finished.

    paged_fallback is not consulted. Nothing selects it, it happens only when a
    channel post fails, so a ticket without one is the ordinary case rather than
    an unfinished one.
    """
    classification = stored_classification(ticket_id)
    if classification is None:
        # Claimed, and nothing decided, so nothing was done either.
        return [UNDECIDED]

    actions = actions_for(classification.category, classification.severity,
                          classification.confidence)
    done = completed_actions(ticket_id)
    expected = {
        "classification_audited": True,
        "note_written": actions.write_note,
        "priority_set": actions.set_priority,
        "slack_posted": actions.channel is not None,
        "paged": actions.page is not None,
        "routed": actions.route_security_queue,
    }
    return [column for column, needed in expected.items()
            if needed and not done[column]]

def process_ticket(payload: dict):
    try:
        _process_ticket(payload)
    finally:
        end_processing(payload.get("ticket_id"))

def _process_ticket(payload: dict):
    ticket_id = payload.get("ticket_id")

    # A ticket already carrying a decision is being resumed, and it finishes on
    # the decision it was given. Asking Claude a second time invites a second
    # answer, and an alert may already have described this ticket in the words
    # of the first one.
    classification = stored_classification(ticket_id)
    resumed = classification is not None

    if not resumed:
        try:
            classification = classify_ticket(
                subject=payload.get("subject", ""),
                message=payload.get("message", "")
            )
        except ClassificationError as e:
            _handle_classification_failure(ticket_id, payload, e.failure_type, str(e))
            return
        except Exception as e:
            _handle_classification_failure(ticket_id, payload, "unknown",
                                           f"{type(e).__name__}: {e}")
            return
        # Stored before anything acts on it, so an attempt that dies partway
        # through leaves the decision behind for the next one.
        save_classification(ticket_id, classification)

    # Normalised once here so the audit log records exactly what the enrichment
    # gate will act on, rather than the raw payload value.
    requester_verified = payload.get("requester_verified") is True

    print(f"Ticket {ticket_id}: {'resuming on the stored' if resumed else 'classified'} "
          f"{classification.category.value}/{classification.severity.value}/"
          f"{classification.confidence.value}, "
          f"requester_verified={requester_verified}")

    actions = actions_for(
        classification.category, classification.severity, classification.confidence
    )

    # The page goes out before anything else, including the audit write, because
    # everything between here and the actions talks to Splunk. Enrichment and
    # audit are the same system, so leaving the page behind either of them means
    # a Splunk outage delays the pager by as long as those retries take, and
    # Splunk can be struggling for the same reason the ticket exists. PagerDuty
    # is the page's only dependency now. The cost is that the page cannot carry
    # an enrichment count, since nothing has searched yet. architecture.md,
    # Section 7.
    if actions.page:
        _page(ticket_id, actions.page,
              build_page(ticket_id, payload.get("ticket_number"), classification),
              fallback=False)

    # The actions still run when this write fails: a note and a channel post are
    # themselves records, so acting leaves evidence in osTicket and Slack even
    # when Splunk has none, where returning here would leave a critical incident
    # unhandled and unannounced. The note carries the gap, since nothing outside
    # the ticket would otherwise explain how it was classified.
    audit_ok = _audit_classification(ticket_id, payload, classification,
                                     requester_verified)

    # Enrichment adds context; alerting is the point. Every path below records
    # what happened and carries on, so neither a Splunk outage nor a ticket with
    # nothing safe to query can silence a critical incident. The four outcomes
    # are in architecture.md, Section 7.
    events = None
    query = None
    outcome = EnrichmentOutcome.not_eligible

    if actions.enrich:
        query = build_enrichment_query(
            submitter_email=payload.get("requester"),
            submitter_ip=payload.get("submitter_ip"),
            requester_verified=requester_verified,
        )
        outcome, events = _enrich(ticket_id, payload, requester_verified)

    _take_actions(ticket_id, classification, actions, payload, outcome, events,
                  query, audit_ok)

def _audit_classification(ticket_id, payload, classification, requester_verified) -> bool:
    """Records the decision in the audit index. Returns whether it is recorded.

    A ticket resumed after the first attempt already wrote this does not write
    it again, which would enter one decision twice. A ticket resumed after that
    write failed does, which is the only chance the record gets. The return
    value is also what the note reports, so a note written on either attempt
    says the same thing about whether the decision reached Splunk.
    """
    if completed_actions(ticket_id)["classification_audited"]:
        return True

    if not log_classification(
        ticket_id=ticket_id,
        subject=payload.get("subject", ""),
        classification=classification,
        requester_verified=requester_verified,
    ):
        _audit_failed(ticket_id, "classification_complete")
        return False

    mark_done(ticket_id, "classification_audited")
    return True

def _handle_classification_failure(ticket_id, payload, failure_type, error):
    """A ticket Claude never classified.

    With no classification there is no action table row, no note content and no
    priority, so the post to the review channel is the whole of what the agent
    can correctly do. architecture.md, Section 6.
    """
    audit_ok = log_classification_failure(
        ticket_id=ticket_id, failure_type=failure_type, error=error
    )
    print(f"Ticket {ticket_id}: classification failed ({failure_type})")
    if not audit_ok:
        _audit_failed(ticket_id, "classification_failed")

    text = build_failure_message(
        ticket_id=ticket_id,
        ticket_number=payload.get("ticket_number"),
        failure_type=failure_type,
    )
    _post(ticket_id, REVIEW, text, mention=False)

def _audit_failed(ticket_id, event):
    """A Splunk write that failed after the thing it records already happened.

    The note is on the ticket, the priority is set, the message is in the
    channel, so the evidence exists and only the audit index is missing it. That
    is a fact about a component rather than about this ticket, and it reaches a
    person through the deployment's own watch on the audit index rather than
    through an alert per ticket. architecture.md, Section 9.
    """
    print(f"Ticket {ticket_id}: audit write failed ({event})")

def _enrich(ticket_id, payload, requester_verified):
    """Runs the enrichment query and reports which of the four outcomes it hit."""
    try:
        events = enrich_ticket(
            submitter_email=payload.get("requester"),
            submitter_ip=payload.get("submitter_ip"),
            requester_verified=requester_verified,
        )
    except EnrichmentError as e:
        log_enrichment_failure(ticket_id=ticket_id, failure_type=e.failure_type,
                               error=str(e))
        print(f"Ticket {ticket_id}: enrichment failed ({e.failure_type})")
        return EnrichmentOutcome.unavailable, None
    except Exception as e:
        log_enrichment_failure(ticket_id=ticket_id, failure_type="unknown",
                               error=f"{type(e).__name__}: {e}")
        print(f"Ticket {ticket_id}: enrichment failed (unknown)")
        return EnrichmentOutcome.unavailable, None

    if events is None:
        log_enrichment_skipped(ticket_id=ticket_id, reason="no_verified_identifier")
        print(f"Ticket {ticket_id}: nothing safe to search on, skipped")
        return EnrichmentOutcome.no_identifier, None

    log_enrichment(ticket_id=ticket_id, events=events)
    print(f"Ticket {ticket_id}: enrichment found {len(events)} related event(s)")
    return EnrichmentOutcome.completed, events

def _take_actions(ticket_id, classification, actions, payload, outcome, events,
                  query, audited):
    """Runs the actions the table selected, after enrichment has settled.

    Ordered so the ticket is ready before anyone is told. The note and priority
    land first, and only then does the channel post invite someone to open it.
    The page is not here. It runs in process_ticket ahead of enrichment, so it
    cannot be delayed by a dependency that only reads.
    """
    if actions.human_review:
        _flag_human_review(ticket_id, "unclear_category"
                           if classification.category == Category.unclear
                           else "low_confidence")

    if actions.write_note:
        _write_ticket_note(ticket_id, classification, outcome, events, query, audited)

    if actions.set_priority:
        _set_ticket_priority(ticket_id, classification)

    # After the ticket is annotated and ordered, before anyone is invited to
    # open it, so a reader following the channel link finds it already in the
    # department that owns it.
    if actions.route_security_queue:
        _route_to_security(ticket_id)

    if actions.channel:
        _post_alert(ticket_id, classification, actions, payload, outcome, events)

def _flag_human_review(ticket_id, reason):
    """Records that a ticket needs a person, and why.

    It does not deliver anything itself. What reaches a person is the channel
    post the action table selected, so this is the audit half of that outcome.
    """
    audit_ok = log_human_review(ticket_id=ticket_id, reason=reason)
    print(f"Ticket {ticket_id}: needs human review ({reason})")
    if not audit_ok:
        _audit_failed(ticket_id, "human_review")

def _post_alert(ticket_id, classification, actions, payload, outcome, events):
    text = build_message(
        ticket_id=ticket_id,
        ticket_number=payload.get("ticket_number"),
        classification=classification,
        channel=actions.channel,
        mention=actions.mention,
        outcome=outcome,
        event_count=len(events) if events else None,
        page=actions.page,
    )
    if not _post(ticket_id, actions.channel, text, actions.mention):
        # A failed alert means nobody has been told, which is the one failure
        # that cannot be left sitting in a log.
        _flag_human_review(ticket_id, "alert_delivery_failed")
        # A critical incident the table declined to page on has now had no
        # delivery at all, so the page becomes the fallback and says so. Where
        # the table did page, the page already ran ahead of this and a second
        # one would repeat it. Both failing is the boundary in
        # KNOWN_LIMITATIONS.md.
        if needs_fallback_page(classification, actions):
            _page(
                ticket_id, WAKE,
                build_fallback_page(ticket_id, payload.get("ticket_number"),
                                    classification),
                fallback=True,
            )

def needs_fallback_page(classification, actions) -> bool:
    """Whether an undelivered alert justifies waking someone.

    Only a critical security incident does. Severity alone is not enough,
    because the classifier can rate an it_support ticket critical and a major
    outage is not what the security on-call is there for.

    A row that already paged WAKE is excluded, since that page ran before the
    alert and a second would repeat it. That leaves the critical at low
    confidence, which paged NOTIFY and was counting on the channel post to reach
    anyone actually looking. With the post gone, the quiet incident is all there
    is, and a delivery failure is the one thing that turns it loud.
    """
    return (classification.category == Category.security_incident
            and classification.severity == Severity.critical
            and actions.page != WAKE)

def _page(ticket_id, destination, event, fallback) -> bool:
    """Sends one page to one destination. Returns False only when nobody was
    paged.

    Writes being off is not a failure to page, and neither is a page that
    already went out.

    The two kinds are guarded by separate columns, because a ticket that paged
    NOTIFY can still need the WAKE that follows a failed alert, and one column
    would let the first refuse the second.
    """
    column = "paged_fallback" if fallback else "paged"
    if completed_actions(ticket_id)[column]:
        print(f"Ticket {ticket_id}: already paged {destination}, skipping")
        return True

    try:
        result = send_page(destination, event)
    except PagerDutyError as e:
        log_page_failure(ticket_id, destination, e.failure_type, str(e))
        print(f"Ticket {ticket_id}: {destination} page failed ({e.failure_type})")
        return False
    except Exception as e:
        log_page_failure(ticket_id, destination, "unknown", f"{type(e).__name__}: {e}")
        print(f"Ticket {ticket_id}: {destination} page failed (unknown)")
        return False

    if result == PD_SKIPPED:
        log_page_skipped(ticket_id=ticket_id, destination=destination,
                         reason="writes_disabled")
        print(f"Ticket {ticket_id}: {destination} page skipped (writes disabled)")
        return True

    # Recorded only after PagerDuty queued it, so a failure leaves the ticket
    # retryable rather than marked done.
    mark_done(ticket_id, column)
    audit_ok = log_paged(ticket_id, destination, fallback)
    print(f"Ticket {ticket_id}: paged {destination}"
          f"{' as a fallback' if fallback else ''}")
    if not audit_ok:
        _audit_failed(ticket_id, "paged")
    return True

def _post(ticket_id, channel, text, mention) -> bool:
    """Posts one message. Returns False only when nobody was told.

    Shared by the classification alert and the classification-failure notice so
    the idempotency claim and the audit write live in one place. Writes being
    off is not a delivery failure, and neither is a post that already happened.
    """
    if completed_actions(ticket_id)["slack_posted"]:
        print(f"Ticket {ticket_id}: slack already posted, skipping")
        return True

    try:
        result = post_alert(channel, text)
    except SlackError as e:
        log_slack_failure(ticket_id, channel, e.failure_type, str(e))
        print(f"Ticket {ticket_id}: slack post to {channel} failed ({e.failure_type})")
        return False
    except Exception as e:
        log_slack_failure(ticket_id, channel, "unknown", f"{type(e).__name__}: {e}")
        print(f"Ticket {ticket_id}: slack post to {channel} failed (unknown)")
        return False

    if result == SLACK_SKIPPED:
        log_slack_skipped(ticket_id=ticket_id, channel=channel, reason="writes_disabled")
        print(f"Ticket {ticket_id}: slack post to {channel} skipped (writes disabled)")
        return True

    # Recorded only after Slack accepted it, so a failure leaves the ticket
    # retryable rather than marked done.
    mark_done(ticket_id, "slack_posted")
    audit_ok = log_slack_posted(ticket_id, channel, mention)
    print(f"Ticket {ticket_id}: slack posted to {channel}")
    if not audit_ok:
        _audit_failed(ticket_id, "slack_posted")
    return True

def _route_to_security(ticket_id):
    """Moves the ticket to the department that owns security questions.

    The category exists because a security question needs someone with security
    context at any urgency, which a general helpdesk queue does not guarantee.
    Nothing about it alerts at high confidence, so without this the ticket sits
    wherever it was filed.
    """
    if completed_actions(ticket_id)["routed"]:
        print(f"Ticket {ticket_id}: already routed, skipping")
        return

    try:
        result = route_to_security(ticket_id=int(ticket_id))
    except OsTicketWriteError as e:
        audit_ok = log_routing_failure(ticket_id, e.failure_type, str(e))
        print(f"Ticket {ticket_id}: routing failed ({e.failure_type})")
        if not audit_ok:
            _audit_failed(ticket_id, "routing_failed")
        return
    except Exception as e:
        audit_ok = log_routing_failure(ticket_id, "unknown", f"{type(e).__name__}: {e}")
        print(f"Ticket {ticket_id}: routing failed (unknown)")
        if not audit_ok:
            _audit_failed(ticket_id, "routing_failed")
        return

    if result["outcome"] == SKIPPED:
        log_routing_skipped(ticket_id=ticket_id, reason="writes_disabled")
        print(f"Ticket {ticket_id}: routing skipped (writes disabled)")
        return

    mark_done(ticket_id, "routed")
    already = result["outcome"] == ALREADY_ROUTED
    audit_ok = log_routed(ticket_id, result["from"], result["to"], already_routed=already)
    print(f"Ticket {ticket_id}: "
          f"{'already in' if already else 'routed to'} {result['to']}")
    if not audit_ok:
        _audit_failed(ticket_id, "routed")

def _set_ticket_priority(ticket_id, classification):
    if completed_actions(ticket_id)["priority_set"]:
        print(f"Ticket {ticket_id}: priority already set, skipping")
        return

    priority = PRIORITY_FOR_SEVERITY[classification.severity]

    try:
        result = set_priority(ticket_id=int(ticket_id), priority=priority)
    except OsTicketWriteError as e:
        audit_ok = log_priority_failure(ticket_id, e.failure_type, str(e))
        print(f"Ticket {ticket_id}: priority write failed ({e.failure_type})")
        if not audit_ok:
            _audit_failed(ticket_id, "priority_failed")
        return
    except Exception as e:
        audit_ok = log_priority_failure(ticket_id, "unknown", f"{type(e).__name__}: {e}")
        print(f"Ticket {ticket_id}: priority write failed (unknown)")
        if not audit_ok:
            _audit_failed(ticket_id, "priority_failed")
        return

    if result["outcome"] == SKIPPED:
        log_priority_skipped(ticket_id=ticket_id, reason="writes_disabled")
        print(f"Ticket {ticket_id}: priority skipped (writes disabled)")
        return

    mark_done(ticket_id, "priority_set")
    audit_ok = log_priority_set(ticket_id, result["from"], result["to"])
    print(f"Ticket {ticket_id}: priority {result['from']} to {result['to']}")
    if not audit_ok:
        _audit_failed(ticket_id, "priority_set")

def _write_ticket_note(ticket_id, classification, outcome, events, query, audited):
    # The store, not the ticket, decides whether this already happened. A
    # retried webhook that got past the claim must not add a second note.
    if completed_actions(ticket_id)["note_written"]:
        print(f"Ticket {ticket_id}: note already written, skipping")
        return

    body = build_note(classification, outcome, events, query, audited)

    try:
        result = write_note(ticket_id=int(ticket_id), note=body)
    except OsTicketWriteError as e:
        audit_ok = log_note_failure(ticket_id, e.failure_type, str(e))
        print(f"Ticket {ticket_id}: note write failed ({e.failure_type})")
        if not audit_ok:
            _audit_failed(ticket_id, "note_failed")
        return
    except Exception as e:
        audit_ok = log_note_failure(ticket_id, "unknown", f"{type(e).__name__}: {e}")
        print(f"Ticket {ticket_id}: note write failed (unknown)")
        if not audit_ok:
            _audit_failed(ticket_id, "note_failed")
        return

    if result == SKIPPED:
        log_note_skipped(ticket_id=ticket_id, reason="writes_disabled")
        print(f"Ticket {ticket_id}: note skipped (writes disabled)")
        return

    # Recorded only after osTicket confirmed the write, so a failure leaves the
    # ticket retryable rather than marked done. A note the endpoint found
    # already there counts as confirmed, since the ticket carries it either
    # way, and it is named separately so a retry that landed on an existing
    # note is not read as a fresh one.
    mark_done(ticket_id, "note_written")
    audit_ok = log_note_written(ticket_id=ticket_id, already_written=result == ALREADY_WRITTEN)
    print(f"Ticket {ticket_id}: note "
          f"{'already present' if result == ALREADY_WRITTEN else 'written'}")
    if not audit_ok:
        _audit_failed(ticket_id, "note_written")

@app.post("/webhook/ticket", status_code=202)
async def receive_ticket(request: Request, background_tasks: BackgroundTasks):
    raw_body = await request.body()
    signature_header = request.headers.get("X-Triage-Signature")
    source_ip = request.client.host if request.client else None

    if not verify_signature(raw_body, signature_header):
        background_tasks.add_task(
            log_request_rejected, reason="invalid_signature", source_ip=source_ip
        )
        return JSONResponse(status_code=401, content={"detail": "Invalid signature"})

    try:
        payload = await request.json()
        if not isinstance(payload, dict):
            raise ValueError("body is not a JSON object")
    except ValueError:
        background_tasks.add_task(
            log_request_rejected, reason="malformed_body", source_ip=source_ip
        )
        return JSONResponse(status_code=400, content={"detail": "Body is not valid JSON"})

    if not is_fresh(payload.get("created_at")):
        background_tasks.add_task(
            log_request_rejected, reason="stale_timestamp", source_ip=source_ip,
            ticket_id=payload.get("ticket_id")
        )
        return JSONResponse(
            status_code=401, content={"detail": "Request timestamp is stale or invalid"}
        )

    ticket_id = payload.get("ticket_id")
    if ticket_id is None:
        background_tasks.add_task(
            log_request_rejected, reason="missing_ticket_id", source_ip=source_ip
        )
        return JSONResponse(status_code=400, content={"detail": "ticket_id is required"})

    # A bool is not a ticket identifier, and isinstance(True, int) is True, so
    # it has to be rejected explicitly rather than by the type check below.
    if isinstance(ticket_id, bool) or not isinstance(ticket_id, (int, str)):
        background_tasks.add_task(
            log_request_rejected, reason="invalid_ticket_id", source_ip=source_ip
        )
        return JSONResponse(
            status_code=400, content={"detail": "ticket_id must be a number or string"}
        )

    # Claiming and starting are separate. The claim is the store's record that
    # this ticket was accepted once; starting is this process saying it is
    # working on it now. A first delivery does both. A repeat delivery fails the
    # claim and has to be told apart from it.
    claimed = claim_ticket(ticket_id)

    # A repeat delivery of a ticket the agent finished is the duplicate the
    # store was built to refuse. One the agent was interrupted partway through
    # is not, and refusing it leaves a ticket half acted on with nothing left to
    # finish it. The stored decision is what lets a second run pick up where the
    # first stopped rather than start the ticket over.
    outstanding = [] if claimed else outstanding_actions(ticket_id)

    if not claimed and not outstanding:
        background_tasks.add_task(
            log_request_rejected, reason="duplicate", source_ip=source_ip,
            ticket_id=ticket_id
        )
        return JSONResponse(status_code=200,
                            content={"status": "duplicate", "ticket_id": ticket_id})

    # Last gate, and the only one that sees the other runs in this process. A
    # ticket still being worked on has actions outstanding and would read as
    # resumable, so without this a retry arriving mid-run would act alongside
    # the run it is retrying. Nothing may fail between here and the handover, or
    # the mark is never released. process_ticket releases it in a finally.
    if not begin_processing(ticket_id):
        background_tasks.add_task(
            log_request_rejected, reason="in_flight", source_ip=source_ip,
            ticket_id=ticket_id
        )
        return JSONResponse(status_code=200,
                            content={"status": "in_flight", "ticket_id": ticket_id})

    if not claimed:
        # Queued ahead of the work rather than after it. Background tasks run in
        # the order they were added, so recording the resume last would mean a
        # run that hangs or dies leaves nothing saying it was ever resumed,
        # which is the run most worth having a record of. The classification was
        # recorded on the first attempt and is not recorded again, so this is
        # the one audit event a resumed ticket is certain to produce.
        background_tasks.add_task(
            log_resumed, ticket_id=ticket_id, outstanding=outstanding
        )
        print(f"Ticket {ticket_id}: resuming, {', '.join(outstanding)} outstanding")
        background_tasks.add_task(process_ticket, payload)
        return JSONResponse(status_code=202,
                            content={"status": "resumed", "ticket_id": ticket_id})

    background_tasks.add_task(process_ticket, payload)

    return {"status": "accepted"}
