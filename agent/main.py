import hmac
import hashlib
import os
from datetime import datetime, timezone
from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import JSONResponse
from dotenv import load_dotenv

load_dotenv()

from action_table import actions_for, PRIORITY_FOR_SEVERITY, REVIEW
from classifier import classify_ticket, ClassificationError
from idempotency import claim_ticket, completed_actions, mark_done
from note_builder import build_note
from osticket_client import write_note, set_priority, OsTicketWriteError, SKIPPED
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
    log_request_rejected,
    log_classification, log_classification_failure,
    log_enrichment, log_enrichment_failure, log_enrichment_skipped,
    log_note_written, log_note_skipped, log_note_failure,
    log_priority_set, log_priority_skipped, log_priority_failure,
    log_slack_posted, log_slack_skipped, log_slack_failure,
    log_paged, log_page_skipped, log_page_failure,
    log_human_review,
)

app = FastAPI()

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

def process_ticket(payload: dict):
    ticket_id = payload.get("ticket_id")

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

    # Normalised once here so the audit log records exactly what the enrichment
    # gate will act on, rather than the raw payload value.
    requester_verified = payload.get("requester_verified") is True

    audit_ok = log_classification(
        ticket_id=ticket_id,
        subject=payload.get("subject", ""),
        classification=classification,
        requester_verified=requester_verified
    )
    print(f"Ticket {ticket_id}: classified "
          f"{classification.category.value}/{classification.severity.value}/"
          f"{classification.confidence.value}, "
          f"requester_verified={requester_verified}")
    # The actions still run when this write fails: a note and a channel post are
    # themselves records, so acting leaves evidence in osTicket and Slack even
    # when Splunk has none, where returning here would leave a critical incident
    # unhandled and unannounced. The note carries the gap, since nothing outside
    # the ticket would otherwise explain how it was classified.
    if not audit_ok:
        _audit_failed(ticket_id, "classification_complete")

    actions = actions_for(
        classification.category, classification.severity, classification.confidence
    )

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
    The page leads, because it must not wait on osTicket being healthy. A slow
    note write would otherwise delay the most urgent thing the system does.
    """
    if actions.page:
        _page(
            ticket_id,
            build_page(ticket_id, payload.get("ticket_number"), classification,
                       outcome, len(events) if events else None),
            fallback=False,
        )

    if actions.human_review:
        _flag_human_review(ticket_id, "unclear_category"
                           if classification.category == Category.unclear
                           else "low_confidence")

    if actions.write_note:
        _write_ticket_note(ticket_id, classification, outcome, events, query, audited)

    if actions.set_priority:
        _set_ticket_priority(ticket_id, classification)

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
                ticket_id,
                build_fallback_page(ticket_id, payload.get("ticket_number"),
                                    classification),
                fallback=True,
            )

def needs_fallback_page(classification, actions) -> bool:
    """Whether an undelivered alert justifies waking someone.

    Only a critical security incident does. Severity alone is not enough,
    because the classifier can rate an it_support ticket critical and a major
    outage is not what the security on-call is there for. A row the table
    already pages on is excluded, since that page ran before the alert and a
    second would repeat it.
    """
    return (classification.category == Category.security_incident
            and classification.severity == Severity.critical
            and not actions.page)

def _page(ticket_id, event, fallback) -> bool:
    """Sends one page. Returns False only when nobody was paged.

    Writes being off is not a failure to page, and neither is a page that
    already went out.
    """
    if completed_actions(ticket_id)["paged"]:
        print(f"Ticket {ticket_id}: already paged, skipping")
        return True

    try:
        result = send_page(event)
    except PagerDutyError as e:
        log_page_failure(ticket_id, e.failure_type, str(e))
        print(f"Ticket {ticket_id}: page failed ({e.failure_type})")
        return False
    except Exception as e:
        log_page_failure(ticket_id, "unknown", f"{type(e).__name__}: {e}")
        print(f"Ticket {ticket_id}: page failed (unknown)")
        return False

    if result == PD_SKIPPED:
        log_page_skipped(ticket_id=ticket_id, reason="writes_disabled")
        print(f"Ticket {ticket_id}: page skipped (writes disabled)")
        return True

    # Recorded only after PagerDuty queued it, so a failure leaves the ticket
    # retryable rather than marked done.
    mark_done(ticket_id, "paged")
    audit_ok = log_paged(ticket_id, fallback)
    print(f"Ticket {ticket_id}: paged{' as a fallback' if fallback else ''}")
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
    # ticket retryable rather than marked done.
    mark_done(ticket_id, "note_written")
    audit_ok = log_note_written(ticket_id=ticket_id)
    print(f"Ticket {ticket_id}: note written")
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

    if not claim_ticket(ticket_id):
        background_tasks.add_task(
            log_request_rejected, reason="duplicate", source_ip=source_ip,
            ticket_id=ticket_id
        )
        return JSONResponse(status_code=200, content={"status": "duplicate", "ticket_id": ticket_id})

    background_tasks.add_task(process_ticket, payload)

    return {"status": "accepted"}
