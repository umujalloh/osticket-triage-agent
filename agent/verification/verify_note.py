"""Checks that log values written into the note cannot become links.

The note carries values copied from Splunk, and some of them an attacker can
choose, such as a username typed at a sign-in page. osTicket escapes a
plain-text note and then turns anything matching its link pattern into a live
link. The agent defangs every value it copies from the logs so nothing does.

The pattern below is osTicket's own, copied from Format::clickableurls in
include/class.format.php. The first check proves it links the raw values, so
its finding nothing in the note means something. An osTicket upgrade that
changes the pattern needs this copy updated too.

Nothing leaves the machine. This reads the string the agent would post.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from note_builder import MAX_VALUE_LENGTH, build_note
from schemas import (Category, Confidence, EnrichmentOutcome, Severity,
                     TicketClassification)

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

OSTICKET_LINK = re.compile(
    r"(?<!>)(((f|ht)tp(s?)://|(?<!//)www\.)([-+~%/.\w]+)(?:[-?#+=&;%@.\w\[\]\/]*)?)"
    r"|(\b[_\.0-9a-z-]+@([0-9a-z][0-9a-z-]+\.)+[a-z]{2,63})"
)

LINKED = ["https://evil.example/reset", "www.evil.example",
          "ftp://files.example/x", "alice@example.com"]
# osTicket's pattern is case-sensitive, so it leaves this one alone today. The
# agent defangs it anyway, in case a later version is not.
UPPER = "WWW.evil.example"
HOSTILE = LINKED + [UPPER]
LONG = "benign verified by SOC close ticket " * 5

CRITICAL = TicketClassification(
    category=Category.security_incident, severity=Severity.critical,
    confidence=Confidence.high_confidence,
)

def event(**fields):
    return {"_time": "2026-09-28T10:00:00", "sourcetype": "test", **fields}

events = [event(user=value) for value in HOSTILE]
events += [event(user=LONG), event(user="bob.smith", ipAddress="192.0.2.7")]
note = build_note(CRITICAL, EnrichmentOutcome.completed, events)

print("osTicket's link pattern")
print()

check("links the raw values", [v for v in HOSTILE if OSTICKET_LINK.search(v)],
      LINKED)

print()
print("the note links nothing")
print()

check("no link anywhere in the note", OSTICKET_LINK.findall(note), [])
check("  a web address stays readable", "https[:]//evil.example/reset" in note, True)
check("  so does a www address", "www[.]evil.example" in note, True)
check("  in the case it was logged in", "WWW[.]evil.example" in note, True)
check("  so does an ftp address", "ftp[:]//files.example/x" in note, True)
check("  and an email address", "alice[@]example.com" in note, True)

print()
print("a long value is cut")
print()

cut = LONG.strip()[:MAX_VALUE_LENGTH] + " (cut)"
check("to the limit, and says so", cut in note, True)
check("  and nothing past the limit survives", LONG.strip() in note, False)

print()
print("ordinary values are untouched")
print()

check("an account name", "bob.smith" in note, True)
check("  and an address", "192.0.2.7" in note, True)

print()
print("the search line is left as the agent built it")
print()

# The query holds only values the agent validated, and an analyst pastes it
# into Splunk, so it is not defanged.
query = 'search index=botsv3 ("carol@example.com") earliest=-24h | head 20'
with_search = build_note(CRITICAL, EnrichmentOutcome.completed, events, query)
check("so it can be pasted into Splunk",
      'Search: index=botsv3 ("carol@example.com") earliest=-24h' in with_search,
      True)

print()
if failed:
    print(f"FAILED: {', '.join(failed)}")
    sys.exit(1)
print(f"All {ran} checks passed. Nothing was sent.")
