"""Checks agent/action_table.py against docs/action-table.md, row by row.

The table is the contract between classification and action, so every row is
compared as a whole Actions object rather than field by field. A single wrong
field fails its row instead of hiding behind the ones that are right.
"""
import os
import sys

# These sit one folder below the modules they exercise, so the agent directory
# has to be on the path before anything is imported from it.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from action_table import (
    HANDLED_CATEGORIES, INCIDENTS, NOTIFY, PRIORITY_FOR_SEVERITY, REVIEW,
    URGENT, WAKE, Actions, actions_for,
)
from schemas import Category, Confidence, Severity

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
        print(f"        got      {got}")
        print(f"        expected {expected}")

def row(category, severity, confidence, **expected):
    """One table row. Everything not named defaults to the Actions default,
    so an unexpected True anywhere fails the row."""
    got = actions_for(Category(category), Severity(severity), Confidence(confidence))
    check(f"{category}/{severity}/{confidence}",
          got, Actions(write_note=True, set_priority=True, **expected))

print("security_incident, critical: urgent channel, and the only rows that page")
row("security_incident", "critical", "high_confidence",
    enrich=True, channel=URGENT, mention=True, page=WAKE)
# Confidence picks the destination rather than whether one exists. The quiet
# page is why this row does not also mention the channel.
row("security_incident", "critical", "low_confidence",
    enrich=True, channel=URGENT, page=NOTIFY, human_review=True)

print("security_incident below critical: incidents channel, never mentions or pages")
for sev in ("high", "medium", "low"):
    row("security_incident", sev, "high_confidence", channel=INCIDENTS)
    row("security_incident", sev, "low_confidence", channel=INCIDENTS, human_review=True)

print("security_question: always the security queue, channel only when unsure")
row("security_question", "high", "high_confidence", route_security_queue=True)
row("security_question", "high", "low_confidence",
    channel=REVIEW, route_security_queue=True, human_review=True)

print("it_support: no channel unless unsure")
row("it_support", "low", "high_confidence")
row("it_support", "low", "low_confidence", channel=REVIEW, human_review=True)

print("unclear: review at either confidence, because the category is the signal")
row("unclear", "medium", "high_confidence", channel=REVIEW, human_review=True)
row("unclear", "medium", "low_confidence", channel=REVIEW, human_review=True)

print("the override quietens the escalation and changes nothing else")
low_critical = actions_for(Category.security_incident, Severity.critical,
                           Confidence.low_confidence)
check("  a low-confidence critical still writes its note", low_critical.write_note, True)
check("  still sets its priority", low_critical.set_priority, True)
check("  still reaches a channel", low_critical.channel, URGENT)
check("  still enriches", low_critical.enrich, True)
check("  still pages, quietly", low_critical.page, NOTIFY)
check("  and does not mention the channel", low_critical.mention, False)

print("enrichment is scoped to critical incidents at either confidence")
for sev in ("high", "medium", "low"):
    check(f"  {sev} severity does not enrich",
          actions_for(Category.security_incident, Severity(sev),
                      Confidence.high_confidence).enrich, False)
check("  a non-incident does not enrich",
      actions_for(Category.it_support, Severity.critical,
                  Confidence.high_confidence).enrich, False)

print("priority comes from severity, using osTicket's names")
check("  critical maps to emergency", PRIORITY_FOR_SEVERITY[Severity.critical], "emergency")
check("  high maps to high", PRIORITY_FOR_SEVERITY[Severity.high], "high")
check("  medium maps to normal", PRIORITY_FOR_SEVERITY[Severity.medium], "normal")
check("  low maps to low", PRIORITY_FOR_SEVERITY[Severity.low], "low")
check("  every severity is mapped", len(PRIORITY_FOR_SEVERITY), len(Severity))

print("every category the classifier can return has a row")
check("  no category is missing from the table",
      sorted(c.value for c in Category),
      sorted(c.value for c in HANDLED_CATEGORIES))

print("an unknown category is refused rather than defaulted")
class FakeCategory:
    pass
try:
    actions_for(FakeCategory(), Severity.low, Confidence.high_confidence)
    check("  raises on a category with no row", "no exception", "ValueError")
except ValueError:
    check("  raises on a category with no row", "ValueError", "ValueError")

print()
if failed:
    print(f"FAILED: {', '.join(failed)}")
    sys.exit(1)
print(f"All {ran} checks passed.")
