import json
from dotenv import load_dotenv
load_dotenv()

from classifier import classify_ticket

with open("../tests/eval_tickets.json") as f:
    tickets = json.load(f)

passed = 0
failed = 0

for i, ticket in enumerate(tickets, start=1):
    result = classify_ticket(
        subject=ticket["subject"],
        message=ticket["message"]
    )

    category_match = result.category.value == ticket["expected_category"]
    severity_match = result.severity.value == ticket["expected_severity"]
    confidence_match = result.confidence.value == ticket["expected_confidence"]

    if category_match and severity_match and confidence_match:
        passed += 1
        print(f"[{i}] PASS - {ticket['subject']}")
    else:
        failed += 1
        print(f"[{i}] FAIL - {ticket['subject']}")
        print(f"    expected: {ticket['expected_category']}, {ticket['expected_severity']}, {ticket['expected_confidence']}")
        print(f"    got:      {result.category.value}, {result.severity.value}, {result.confidence.value}")

print(f"\n{passed}/{len(tickets)} passed ({round(passed/len(tickets)*100)}%)")
