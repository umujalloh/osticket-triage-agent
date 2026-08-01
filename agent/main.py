import hmac
import hashlib
import os
from datetime import datetime, timezone
from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from dotenv import load_dotenv

load_dotenv()

from classifier import classify_ticket, ClassificationError
from splunk_logger import log_classification, log_classification_failure

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

seen_ticket_ids = set()

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

    audit_ok = log_classification(
        ticket_id=ticket_id,
        subject=payload.get("subject", ""),
        classification=classification
    )
    print(f"Ticket {ticket_id}: classified "
          f"{classification.category.value}/{classification.severity.value}/"
          f"{classification.confidence.value}")
    if not audit_ok:
        print(f"Ticket {ticket_id}: needs human review (audit log write failed)")

@app.post("/webhook/ticket", status_code=202)
async def receive_ticket(request: Request, background_tasks: BackgroundTasks):
    raw_body = await request.body()
    signature_header = request.headers.get("X-Triage-Signature")

    if not verify_signature(raw_body, signature_header):
        raise HTTPException(status_code=401, detail="Invalid signature")

    payload = await request.json()

    if not is_fresh(payload.get("created_at")):
        raise HTTPException(status_code=401, detail="Request timestamp is stale or invalid")

    ticket_id = payload.get("ticket_id")
    if ticket_id is not None:
        if ticket_id in seen_ticket_ids:
            return JSONResponse(status_code=200, content={"status": "duplicate", "ticket_id": ticket_id})
        seen_ticket_ids.add(ticket_id)

    background_tasks.add_task(process_ticket, payload)

    return {"status": "accepted"}
