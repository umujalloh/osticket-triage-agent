import hmac
import hashlib
import os
from fastapi import FastAPI, Request, HTTPException
from dotenv import load_dotenv

load_dotenv()

from classifier import classify_ticket

load_dotenv()

app = FastAPI()

HMAC_SECRET = os.getenv("TRIAGE_HMAC_SECRET")

def verify_signature(raw_body: bytes, signature_header: str) -> bool:
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    received_signature = signature_header.split("=", 1)[1]
    expected_signature = hmac.new(
        HMAC_SECRET.encode(), raw_body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(received_signature, expected_signature)

@app.post("/webhook/ticket")
async def receive_ticket(request: Request):
    raw_body = await request.body()
    signature_header = request.headers.get("X-Triage-Signature")

    if not verify_signature(raw_body, signature_header):
        raise HTTPException(status_code=401, detail="Invalid signature")

    payload = await request.json()
    print("Received ticket webhook:", payload)

    classification = classify_ticket(
        subject=payload.get("subject", ""),
        message=payload.get("message", "")
    )
    print("Classification:", classification)

    return {"status": "received", "classification": classification.model_dump()}
