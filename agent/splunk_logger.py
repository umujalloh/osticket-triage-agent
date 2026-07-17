import os
import requests
from datetime import datetime, timezone

SPLUNK_HEC_URL = os.getenv("SPLUNK_HEC_URL")
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN")

def log_classification(ticket_id, subject, classification):
    event = {
        "time": datetime.now(timezone.utc).timestamp(),
        "sourcetype": "osticket:triage:audit",
        "index": "osticket_triage",
        "event": {
            "ticket_id": ticket_id,
            "subject": subject,
            "category": classification.category.value,
            "severity": classification.severity.value,
            "confidence": classification.confidence.value,
        }
    }

    headers = {"Authorization": f"Splunk {SPLUNK_HEC_TOKEN}"}

    try:
        response = requests.post(
            SPLUNK_HEC_URL, headers=headers, json=event, verify=False, timeout=5
        )
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Splunk logging failed: {e}")
