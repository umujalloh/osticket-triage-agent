"""Checks how the agent judges whether its PagerDuty routing keys still work.

PagerDuty's Events API answers 202 to a page whose routing key's integration
was deleted, or whose PagerDuty service is disabled or in maintenance, and
creates no incident, so the page is lost with nothing failing.
check_routing_keys asks the REST API instead, trying a dropped request or a
temporary error again before it reports one. architecture.md, Section 9, and
known-limitations.md describe the gap it closes.

Nothing leaves the machine. The REST API is replaced by canned answers, one per
case, and the check's verdict on each is compared with what it should be.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Fake routing keys, so the check has something to look for and nothing real is
# used. Writes off, so the client does not require the REST API key at import.
WAKE_KEY = "wake-routing-key-for-the-verifier"
NOTIFY_KEY = "notify-routing-key-for-the-verifier"
os.environ["PAGERDUTY_ROUTING_KEY_WAKE"] = WAKE_KEY
os.environ["PAGERDUTY_ROUTING_KEY_NOTIFY"] = NOTIFY_KEY
os.environ["ENABLE_WRITES"] = "false"
os.environ.setdefault("PAGERDUTY_DEDUP_SECRET", "not-used-by-this-check")

import requests

import pagerduty_client as pd
from action_table import NOTIFY, WAKE

failed = []
ran = 0

def check(name, got, expected):
    global ran
    ran += 1
    ok = got == expected
    if not ok:
        failed.append(name)
    print(f"{'PASS' if ok else 'FAIL'}  {name}")
    if not ok:
        print(f"        got {got!r}, expected {expected!r}")

class Answer:
    def __init__(self, status, body=None, unreadable=False):
        self.status_code = status
        self._body = body
        self._unreadable = unreadable
    def json(self):
        # The exception requests itself raises on a body that is not JSON.
        if self._unreadable:
            raise requests.exceptions.JSONDecodeError("Expecting value", "<html>", 0)
        return self._body

def service(status, *keys):
    return {"status": status,
            "integrations": [{"integration_key": k} for k in keys]}

calls = []

# The pauses between attempts, skipped so the run takes no time.
pd.time.sleep = lambda seconds: None

def run_with(answers):
    """Runs the check with requests.get returning each answer in turn, and
    records the query each call sent in calls. Running out of answers is
    reported as a check failing with RanOutOfAnswers, which no case expects."""
    pending = list(answers)
    calls.clear()
    real = requests.get
    def fake_get(*args, **kwargs):
        calls.append(dict(kwargs.get("params") or {}))
        if not pending:
            raise RanOutOfAnswers()
        answer = pending.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer
    requests.get = fake_get
    try:
        return pd.check_routing_keys()
    finally:
        requests.get = real

class RanOutOfAnswers(Exception):
    pass

def results(outcome):
    return {dest: result for dest, (result, _) in outcome.items()}

def listing(*services, more=False):
    return Answer(200, {"services": list(services), "more": more})

print("live routing keys")
out = run_with([listing(service("active", WAKE_KEY),
                        service("critical", NOTIFY_KEY))])
check("  a routing key on an active PagerDuty service is alive", out[WAKE][0], pd.ALIVE)
check("  so is one on a PagerDuty service in critical status", out[NOTIFY][0], pd.ALIVE)
out = run_with([listing(service("warning", WAKE_KEY, NOTIFY_KEY))])
check("  so is one on a PagerDuty service in warning status", out[WAKE][0], pd.ALIVE)

print("dead routing keys")
out = run_with([listing(service("active", NOTIFY_KEY))])
check("  a routing key no PagerDuty service has is dead", out[WAKE][0], pd.DEAD)
out = run_with([listing(service("disabled", WAKE_KEY),
                        service("maintenance", NOTIFY_KEY))])
check("  a routing key on a disabled PagerDuty service is dead", out[WAKE][0], pd.DEAD)
check("  so is one on a PagerDuty service in maintenance", out[NOTIFY][0], pd.DEAD)
out = run_with([listing(service("some_new_status", WAKE_KEY),
                        service("active", NOTIFY_KEY))])
check("  so is one on a PagerDuty service in a status the agent does not recognize",
      out[WAKE][0], pd.DEAD)

print("PagerDuty services listed across more than one page")
out = run_with([listing(service("active", WAKE_KEY), more=True),
                listing(service("active", NOTIFY_KEY))])
check("  a routing key on the second page is still found", results(out),
      {WAKE: pd.ALIVE, NOTIFY: pd.ALIVE})
check("  each page asks for the next offset, with integrations included",
      [(c.get("offset"), c.get("include[]")) for c in calls],
      [(0, "integrations"), (1, "integrations")])
out = run_with([listing(service("active", WAKE_KEY), more=True),
                listing(more=True)])
check("  an empty page ends the listing even when it says there is more",
      (len(calls), results(out)), (2, {WAKE: pd.ALIVE, NOTIFY: pd.DEAD}))

print("a blip is tried again before anything is reported")
unreachable = requests.exceptions.ConnectionError("no route")
out = run_with([unreachable, listing(service("active", WAKE_KEY, NOTIFY_KEY))])
check("  one dropped request, then an answer, reads as alive",
      (len(calls), results(out)), (2, {WAKE: pd.ALIVE, NOTIFY: pd.ALIVE}))
out = run_with([Answer(503), Answer(429),
                listing(service("active", WAKE_KEY, NOTIFY_KEY))])
check("  so do a 503 and a 429 before an answer",
      (len(calls), results(out)), (3, {WAKE: pd.ALIVE, NOTIFY: pd.ALIVE}))
out = run_with([requests.exceptions.Timeout("read timed out"),
                listing(service("active", WAKE_KEY, NOTIFY_KEY))])
check("  so does a timeout before an answer",
      (len(calls), results(out)), (2, {WAKE: pd.ALIVE, NOTIFY: pd.ALIVE}))

print("a check that cannot run is reported as unchecked")
because = "could not be checked, because the PagerDuty REST API "
for label, answers, tries, reason in [
    ("a revoked REST API key, asked once", [Answer(401)], 1,
     because + "answered HTTP 401"),
    ("a REST API key without access, asked once", [Answer(403)], 1,
     because + "answered HTTP 403"),
    ("PagerDuty down on all three tries", [Answer(503)] * 3, 3,
     because + "answered HTTP 503"),
    ("PagerDuty unreachable on all three tries", [unreachable] * 3, 3,
     because + "could not be reached"),
    ("an answer that is not JSON, reported as unreadable",
     [Answer(200, unreadable=True)], 1, because + "sent an unreadable answer"),
    ("an answer that is not a list of PagerDuty services",
     [Answer(200, ["services"])], 1,
     "could not be checked, because the check failed with AttributeError"),
]:
    out = run_with(answers)
    check(f"  {label}", (len(calls), out),
          (tries, {WAKE: (pd.UNCHECKED, reason), NOTIFY: (pd.UNCHECKED, reason)}))

print("no routing key is ever quoted")
reasons = []
for answers in ([listing()], [Answer(401)],
                [requests.exceptions.ConnectionError(f"failed for {WAKE_KEY}")] * 3):
    reasons += [reason for _, reason in run_with(answers).values()]
check("  in any reason the check gives",
      any(WAKE_KEY in r or NOTIFY_KEY in r for r in reasons), False)

print()
if failed:
    print(f"FAILED: {', '.join(failed)}")
    sys.exit(1)
print(f"All {ran} checks passed. Nothing was sent.")
