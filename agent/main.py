import hmac
import hashlib
import os
from datetime import datetime, timezone
from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import JSONResponse
from dotenv import load_dotenv

load_dotenv()

from classifier import classify_ticket, ClassificationError
from idempotency import claim_ticket
from schemas import Category, Severity
from splunk_enrichment import enrich_ticket, EnrichmentError
from splunk_logger import (
    log_request_rejected,
    log_classification, log_classification_failure,
    log_enrichment, log_enrichment_failure, log_enrichment_skipped,
)

app = FastAPI()

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
        audit_ok = log_classification_failure(
            ticket_id=ticket_id,
            failure_type=e.failure_type,
            error=str(e)
        )
        print(f"Ticket {ticket_id}: classification failed ({e.failure_type})")
        if not audit_ok:
            print(f"Ticket {ticket_id}: needs human review (audit log write failed)")
        return
    except Exception as e:
        audit_ok = log_classification_failure(
            ticket_id=ticket_id,
            failure_type="unknown",
            error=f"{type(e).__name__}: {e}"
        )
        print(f"Ticket {ticket_id}: classification failed (unknown)")
        if not audit_ok:
            print(f"Ticket {ticket_id}: needs human review (audit log write failed)")
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
    if not audit_ok:
        print(f"Ticket {ticket_id}: needs human review (audit log write failed)")
        return

    # Deliberately not gated on confidence. A low-confidence critical routes to
    # a human, and that is the ticket where a starting point matters most.
    should_enrich = (
        classification.category == Category.security_incident
        and classification.severity == Severity.critical
    )
    if not should_enrich:
        return

    try:
        events = enrich_ticket(
            submitter_email=payload.get("requester"),
            submitter_ip=payload.get("submitter_ip"),
            requester_verified=requester_verified,
        )
    except EnrichmentError as e:
        audit_ok = log_enrichment_failure(
            ticket_id=ticket_id,
            failure_type=e.failure_type,
            error=str(e)
        )
        print(f"Ticket {ticket_id}: enrichment failed ({e.failure_type})")
        if not audit_ok:
            print(f"Ticket {ticket_id}: needs human review (audit log write failed)")
        return
    except Exception as e:
        audit_ok = log_enrichment_failure(
            ticket_id=ticket_id,
            failure_type="unknown",
            error=f"{type(e).__name__}: {e}"
        )
        print(f"Ticket {ticket_id}: enrichment failed (unknown)")
        if not audit_ok:
            print(f"Ticket {ticket_id}: needs human review (audit log write failed)")
        return

    if events is None:
        audit_ok = log_enrichment_skipped(ticket_id=ticket_id, reason="no_entity")
        print(f"Ticket {ticket_id}: no entity to enrich on, skipped")
        if not audit_ok:
            print(f"Ticket {ticket_id}: needs human review (audit log write failed)")
        return

    audit_ok = log_enrichment(ticket_id=ticket_id, events=events)
    print(f"Ticket {ticket_id}: enrichment found {len(events)} related event(s)")
    if not audit_ok:
        print(f"Ticket {ticket_id}: needs human review (audit log write failed)")

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

    # Claims the ticket and reports whether this request won it. The store is
    # on disk, so a restart no longer forgets what it has already processed.
    if not claim_ticket(ticket_id):
        background_tasks.add_task(
            log_request_rejected, reason="duplicate", source_ip=source_ip,
            ticket_id=ticket_id
        )
        return JSONResponse(status_code=200, content={"status": "duplicate", "ticket_id": ticket_id})

    background_tasks.add_task(process_ticket, payload)

    return {"status": "accepted"}
