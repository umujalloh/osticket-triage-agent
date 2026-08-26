import os
import subprocess
import sys

# These sit one folder below the modules they exercise, so the agent directory
# has to be on the path before anything is imported from it.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

# The child half. Each case runs in its own process because ENABLE_WRITES and
# the webhooks are read at import, so patching them in place would not test what
# happens at boot.
CASE = os.environ.get("SLACK_CASE")

if CASE == "kill_switch_off":
    import slack_client as slack
    print(f"OUTCOME={slack.post_alert(slack.URGENT, 'should not be sent')}")
    sys.exit(0)

if CASE in ("missing_webhook", "missing_base_url"):
    try:
        import slack_client  # noqa: F401
        print("OUTCOME=imported")
    except RuntimeError as e:
        print(f"OUTCOME=refused: {e}")
    sys.exit(0)

if CASE == "url_leak":
    import slack_client as slack
    try:
        slack.post_alert(slack.URGENT, "should fail")
        print("OUTCOME=no error raised")
    except slack.SlackError as e:
        print(f"OUTCOME=raised: {e}")
    sys.exit(0)

if CASE == "live":
    import slack_client as slack
    from schemas import EnrichmentOutcome
    text = ("Delivery check from verify_slack.py, not a real alert.\n"
            "If you are reading this in a channel other than the test channel, "
            "the verifier is misconfigured.")
    print(f"OUTCOME={slack.post_alert(slack.URGENT, text)}")
    sys.exit(0)

from schemas import EnrichmentOutcome, TicketClassification
import slack_client as slack

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
    return TicketClassification(category=category, severity=severity, confidence=confidence)

# Which channel a classification reaches, and whether it mentions, are the
# action table's decisions and are checked by verify_action_table.py. This
# verifier covers what the client does with them.

print("message content")
critical = classification("security_incident", "critical", "high_confidence")
msg = slack.build_message(15, "465581", critical, slack.URGENT, mention=True,
                          outcome=EnrichmentOutcome.completed, event_count=20)
check("  a mention renders as here", "<!here>" in msg, True)
check("  severity and category appear", "critical security_incident" in msg, True)
check("  ticket number appears", "#465581" in msg, True)
check("  enrichment count appears", "20 related events" in msg, True)
check("  link is a raw url", "/scp/tickets.php?id=15" in msg, True)
check("  no markdown link syntax", "|Open ticket>" in msg, False)

high = classification("security_incident", "high", "high_confidence")
check("  no mention renders none",
      "<!here>" in slack.build_message(15, "465581", high, slack.INCIDENTS), False)

print("review channel shows the reason, not the severity")
unclear = classification("unclear", "high", "high_confidence")
unclear_msg = slack.build_message(15, "465581", unclear, slack.REVIEW)
check("  unclear names the category", "*unclear*" in unclear_msg, True)
# Severity is a guess on a ticket nobody could place. Matched as the bolded
# severity-and-category pair the other channels use, since "high confidence"
# legitimately contains the word on its own.
check("  unclear hides the severity guess", "*high unclear*" in unclear_msg, False)

low_conf = classification("it_support", "low", "low_confidence")
low_msg = slack.build_message(15, "465581", low_conf, slack.REVIEW)
check("  a low-confidence ticket says so", "low confidence" in low_msg, True)

# Stating only the low case would leave a reader inferring the other from an
# absence, which is the thing the urgent channel got wrong before.
print("every alert states its confidence, and any page says where")
for chan, conf, expected in [
    (slack.URGENT, "high_confidence", "high confidence"),
    (slack.URGENT, "low_confidence", "low confidence"),
    (slack.INCIDENTS, "high_confidence", "high confidence"),
    (slack.REVIEW, "high_confidence", "high confidence"),
]:
    text = slack.build_message(15, "465581",
                               classification("security_incident", "critical", conf), chan)
    check(f"  {chan} says {expected}", expected in text, True)

paged = slack.build_message(15, "465581", critical, slack.URGENT, page="wake")
check("  a paged alert names the destination", "paged WAKE" in paged, True)
quiet = slack.build_message(15, "465581",
                            classification("security_incident", "critical", "low_confidence"),
                            slack.URGENT, page="notify")
check("  and the quiet one names its own", "paged NOTIFY" in quiet, True)
check("  an alert that did not page says nothing about paging",
      "paged" in slack.build_message(15, "465581", high, slack.INCIDENTS), False)

# The case the old message got wrong. It named the table's destination whether
# or not the page was sent, so a reader was told the on-call was awake when
# nobody had been reached.
lost_page = slack.build_message(15, "465581", critical, slack.URGENT,
                                page="wake", paged=False)
check("  a page that failed says so", "WAKE PAGE FAILED" in lost_page, True)
check("  and does not claim it paged", "paged WAKE" in lost_page, False)
check("  it tells the reader what to do instead",
      "escalate manually" in lost_page, True)
check("  the quiet destination reports its own failure",
      "NOTIFY PAGE FAILED" in slack.build_message(
          15, "465581",
          classification("security_incident", "critical", "low_confidence"),
          slack.URGENT, page="notify", paged=False), True)
# A row that pages nowhere has no page to report, so paged=False must not add a
# failure line to it.
check("  a row that pages nowhere stays silent about paging",
      "PAGE FAILED" in slack.build_message(15, "465581", high, slack.INCIDENTS,
                                           paged=False), False)

print("the four enrichment states")
for outcome, count, expected in [
    (EnrichmentOutcome.not_eligible, None, None),
    (EnrichmentOutcome.no_identifier, None, "no verified identifier"),
    (EnrichmentOutcome.completed, 0, "no related events"),
    (EnrichmentOutcome.completed, 20, "20 related events"),
    (EnrichmentOutcome.unavailable, None, "enrichment unavailable"),
]:
    text = slack.build_message(15, "465581", critical, slack.URGENT,
                               outcome=outcome, event_count=count)
    present = expected is None or expected in text
    check(f"  {outcome.value}{'' if count is None else f' ({count})'}", present, True)

print("the notice for a ticket that was never classified")
fail_msg = slack.build_failure_message(15, "465581", "rate_limited")
check("  says what happened", "classification failed" in fail_msg, True)
check("  names the failure type", "rate_limited" in fail_msg, True)
check("  carries the ticket number", "#465581" in fail_msg, True)
check("  links the ticket", "/scp/tickets.php?id=15" in fail_msg, True)
check("  reuses the review icon", slack.REVIEW_ICON in fail_msg, True)
# A distinct shape would assert an urgency a ticket with no severity has no
# basis for, so the only icon it may carry is the review one.
check("  carries no severity icon",
      any(i in fail_msg for i in slack.SEVERITY_ICON.values()
          if i != slack.REVIEW_ICON), False)
check("  never mentions the channel", "<!here>" in fail_msg, False)
check("  falls back to the ticket id when there is no number",
      "#15" in slack.build_failure_message(15, None, "auth_failure"), True)

def run_case(name, **env_overrides):
    env = dict(os.environ)
    env["SLACK_CASE"] = name
    env.update(env_overrides)
    result = subprocess.run([sys.executable, __file__], env=env,
                            capture_output=True, text=True)
    return result.stdout + result.stderr

print("boot and kill switch, each in its own process")
out = run_case("kill_switch_off", ENABLE_WRITES="false")
check("  writes off returns skipped", f"OUTCOME={slack.SKIPPED}" in out, True)

out = run_case("missing_webhook", ENABLE_WRITES="true", SLACK_WEBHOOK_URGENT="")
check("  a missing webhook refuses to boot", "OUTCOME=refused" in out, True)
check("  and names which one", "urgent" in out, True)

# The webhooks are optional when writes are off. The base URL is not, because a
# message is built before the kill switch decides whether to send it, so without
# it the builder would raise inside a background task instead of at boot.
out = run_case("missing_base_url", ENABLE_WRITES="false", OSTICKET_BASE_URL="")
check("  a missing base url refuses to boot with writes off too",
      "OUTCOME=refused" in out, True)
check("  and names the value", "OSTICKET_BASE_URL" in out, True)

# A webhook URL is a bearer credential, and these errors reach the console and
# the audit index. The canary is planted in the URL, so if any error path
# interpolates the URL the canary shows up in the child's output.
print("a failure never leaks the webhook url")
CANARY = "CANARY-DO-NOT-LOG"

out = run_case("url_leak", ENABLE_WRITES="true",
               SLACK_WEBHOOK_URGENT=f"not-a-url/{CANARY}")
check("  a malformed url is not echoed", CANARY in out, False)
check("  and it still raises", "OUTCOME=raised" in out, True)

print("  (the next case retries three times, so it takes about 17 seconds)")
out = run_case("url_leak", ENABLE_WRITES="true",
               SLACK_WEBHOOK_URGENT=f"http://127.0.0.1:1/{CANARY}")
check("  an unreachable host is not echoed", CANARY in out, False)
check("  and it still raises", "OUTCOME=raised" in out, True)

print("live delivery, to the test channel only")
test_hook = os.getenv("SLACK_WEBHOOK_TEST")
if not test_hook:
    print("SKIP  SLACK_WEBHOOK_TEST is not set, delivery not checked")
else:
    out = run_case("live", ENABLE_WRITES="true", SLACK_WEBHOOK_URGENT=test_hook)
    check("  a real post succeeds", f"OUTCOME={slack.DONE}" in out, True)

print()
if failed:
    print(f"FAILED: {', '.join(failed)}")
    sys.exit(1)
print(f"All {ran} checks passed. One message was posted to the test channel.")
