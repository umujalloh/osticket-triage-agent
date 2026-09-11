import os
import subprocess
import sys
from urllib.parse import urlparse

# These sit one folder below the modules they exercise, so the agent directory
# has to be on the path before anything is imported from it.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

# The child half. Each case runs in its own process because ENABLE_WRITES and
# the routing key are read at import, so patching them in place would not test
# what happens at boot.
CASE = os.environ.get("PAGERDUTY_CASE")

if CASE == "kill_switch_off":
    import pagerduty_client as pd
    print(f"OUTCOME={pd.send_page(pd.WAKE, {'payload': {}})}")
    sys.exit(0)

if CASE == "missing_routing_key":
    try:
        import pagerduty_client  # noqa: F401
        print("OUTCOME=imported")
    except RuntimeError as e:
        print(f"OUTCOME=refused: {e}")
    sys.exit(0)

if CASE == "key_leak":
    import pagerduty_client as pd
    from schemas import TicketClassification
    c = TicketClassification(category="security_incident", severity="critical",
                             confidence="high_confidence")
    try:
        pd.send_page(pd.WAKE, pd.build_page(15, "465581", c))
        print("OUTCOME=no error raised")
    except pd.PagerDutyError as e:
        print(f"OUTCOME=raised {e}")
    except Exception as e:
        print(f"OUTCOME=raised {type(e).__name__} {e}")
    sys.exit(0)

if CASE == "bad_destination":
    import pagerduty_client as pd
    try:
        pd.send_page("nowhere", {"payload": {}})
        print("OUTCOME=no error raised")
    except pd.PagerDutyError as e:
        print(f"OUTCOME=raised {e}")
    sys.exit(0)

if CASE in ("live", "live_notify"):
    import pagerduty_client as pd
    from schemas import TicketClassification
    c = TicketClassification(category="security_incident", severity="critical",
                             confidence="high_confidence")
    destination = pd.NOTIFY if CASE == "live_notify" else pd.WAKE
    print(f"OUTCOME={pd.send_page(destination, pd.build_page(15, 'VERIFY', c))}")
    sys.exit(0)

import pagerduty_client as pd
from schemas import Severity, TicketClassification

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

def classification(category, severity, confidence):
    return TicketClassification(category=category, severity=severity,
                                confidence=confidence)

# Whether a classification pages at all is the action table's decision and is
# checked by verify_action_table.py. This verifier covers what the client builds
# and sends once that decision is made.

print("the page for a ticket the table said to page on")
critical = classification("security_incident", "critical", "high_confidence")
page = pd.build_page(15, "465581", critical)
check("  severity and category lead", "critical security_incident" in
      page["payload"]["summary"], True)
check("  ticket number appears", "#465581" in page["payload"]["summary"], True)
# The page is sent before enrichment runs, so there is no count to carry and
# nothing here should imply one was searched for.
check("  it claims nothing about enrichment",
      any(w in page["payload"]["summary"]
          for w in ("events", "enrichment", "identifier")), False)
check("  severity maps to pagerduty's", page["payload"]["severity"], "critical")
check("  dedup key is not the ticket id", page["dedup_key"] == "15", False)
check("  and the same ticket always produces the same key",
      pd.build_page(15, "465581", critical)["dedup_key"], page["dedup_key"])
check("  event action is trigger", page["event_action"], "trigger")
check("  source names the osticket host", page["payload"]["source"],
      urlparse(os.getenv("OSTICKET_BASE_URL")).netloc)

# Anyone holding the routing key can create a convincing incident, so a
# responder has to be able to see where a link points before tapping it.
link = page["links"][0]
check("  link text is the url itself", link["text"], link["href"])
check("  link points at the ticket", "/scp/tickets.php?id=15" in link["href"], True)

# Enrichment output stays inside the trust zone. Section 8 refuses it for Slack
# and PagerDuty is outside for the same reason, so there is nowhere to put it.
check("  no custom details are attached", "custom_details" in page["payload"], False)

print("the page sent when a critical could not be delivered")
low_conf = classification("security_incident", "critical", "low_confidence")
fb = pd.build_fallback_page(15, "465581", low_conf)
summary = fb["payload"]["summary"]
check("  it leads with the delivery failure",
      summary.startswith("alert delivery failed"), True)
check("  it says the confidence was low", "low confidence" in summary, True)
check("  it still names the classification",
      "critical security_incident" in summary, True)
check("  it does not read as a confident critical",
      summary.startswith("critical"), False)
check("  it dedups on the same ticket", fb["dedup_key"], page["dedup_key"])

check("  the ticket id stands in for a missing number",
      "#15" in pd.build_fallback_page(15, None, low_conf)["payload"]["summary"], True)

# A table change that paged on another severity would otherwise send a value
# PagerDuty rejects, and the page would fail at the moment it mattered.
print("every severity maps to a pagerduty severity")
for sev in Severity:
    check(f"  {sev.value}", sev in pd.PAGERDUTY_SEVERITY, True)

def run_case(name, **env_overrides):
    env = dict(os.environ)
    env["PAGERDUTY_CASE"] = name
    env.update(env_overrides)
    result = subprocess.run([sys.executable, __file__], env=env,
                            capture_output=True, text=True)
    return result.stdout + result.stderr

print("boot and kill switch, each in its own process")
out = run_case("kill_switch_off", ENABLE_WRITES="false")
check("  writes off returns skipped", f"OUTCOME={pd.SKIPPED}" in out, True)

out = run_case("missing_routing_key", ENABLE_WRITES="true",
               PAGERDUTY_ROUTING_KEY_NOTIFY="")
check("  a missing routing key refuses to boot", "OUTCOME=refused" in out, True)
check("  and names which destination", "notify" in out, True)

# The key travels in the request body rather than the URL, so the usual danger
# of a client library echoing the URL does not apply. What can still leak it is
# a rejection quoting the field it rejected, so the canary is the key itself.
print("a failure never leaks the routing key")
CANARY = "canary0000000000000000000000000d"
out = run_case("key_leak", ENABLE_WRITES="true", PAGERDUTY_ROUTING_KEY_WAKE=CANARY)
check("  a rejected key is not echoed", CANARY in out, False)
check("  and it still raises", "OUTCOME=raised" in out, True)

# A destination the table never produces would otherwise be sent with a routing
# key of None, which PagerDuty answers with a 400 that quotes the body.
print("an unknown destination is refused before anything is sent")
out = run_case("bad_destination", ENABLE_WRITES="true")
check("  it raises rather than posting", "OUTCOME=raised" in out, True)
check("  and names the destination", "nowhere" in out, True)

print("live delivery, to the test service only")
test_key = os.getenv("PAGERDUTY_ROUTING_KEY_TEST")
if not test_key:
    print("SKIP  PAGERDUTY_ROUTING_KEY_TEST is not set, delivery not checked")
else:
    out = run_case("live", ENABLE_WRITES="true", PAGERDUTY_ROUTING_KEY_WAKE=test_key)
    check("  a real page is queued", f"OUTCOME={pd.DONE}" in out, True)
    # Both destinations go to the one test service, so this proves delivery and
    # not urgency. Urgency is a property of the service in PagerDuty, which the
    # agent can neither read nor set, so it is a deployment precondition rather
    # than something a check here could assert.
    out = run_case("live_notify", ENABLE_WRITES="true",
                   PAGERDUTY_ROUTING_KEY_NOTIFY=test_key)
    check("  so is a page to the other destination", f"OUTCOME={pd.DONE}" in out, True)

print()
if failed:
    print(f"FAILED: {', '.join(failed)}")
    sys.exit(1)
print(f"All {ran} checks passed. Two pages were sent to the test service.")
