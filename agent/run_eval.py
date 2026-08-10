import json
from dotenv import load_dotenv
load_dotenv()

from classifier import classify_ticket

with open("../tests/eval_tickets.json") as f:
    tickets = json.load(f)

passed = 0
failed = 0

# Tracked separately so a classification regression and an entity-extraction
# regression can't cancel out in the aggregate score. Entity extraction is the
# newer, less-tested judgment call, so it needs its own visible number.
classification_passed = 0
entity_passed = 0

for i, ticket in enumerate(tickets, start=1):
    result = classify_ticket(
        subject=ticket["subject"],
        message=ticket["message"]
    )

    category_match = result.category.value == ticket["expected_category"]
    severity_match = result.severity.value == ticket["expected_severity"]
    confidence_match = result.confidence.value == ticket["expected_confidence"]
    hostname_match = result.hostname == ticket["expected_hostname"]
    username_match = result.username == ticket["expected_username"]
    source_ip_match = result.source_ip == ticket["expected_source_ip"]

    classification_ok = category_match and severity_match and confidence_match
    entity_ok = hostname_match and username_match and source_ip_match
    classification_passed += classification_ok
    entity_passed += entity_ok

    if classification_ok and entity_ok:
        passed += 1
        print(f"[{i}] PASS - {ticket['subject']}")
    else:
        failed += 1
        which = ", ".join(
            part for part, ok in
            (("classification", classification_ok), ("entities", entity_ok))
            if not ok
        )
        print(f"[{i}] FAIL ({which}) - {ticket['subject']}")
        print(f"    expected: {ticket['expected_category']}, {ticket['expected_severity']}, {ticket['expected_confidence']}, "
              f"hostname={ticket['expected_hostname']}, username={ticket['expected_username']}, source_ip={ticket['expected_source_ip']}")
        print(f"    got:      {result.category.value}, {result.severity.value}, {result.confidence.value}, "
              f"hostname={result.hostname}, username={result.username}, source_ip={result.source_ip}")

total = len(tickets)
def pct(n):
    return f"{n}/{total} ({round(n / total * 100)}%)"

print(f"\noverall:        {pct(passed)}")
print(f"classification: {pct(classification_passed)}")
print(f"entities:       {pct(entity_passed)}")
