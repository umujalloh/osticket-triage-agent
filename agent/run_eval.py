import argparse
import json
from dotenv import load_dotenv
load_dotenv()

from classifier import ClassificationError, classify_ticket
from schemas import Category, Confidence, Severity

parser = argparse.ArgumentParser(
    description="Score the classifier against tests/eval_tickets.json."
)
parser.add_argument(
    "--runs", type=int, default=1,
    help="how many times to classify the whole set (default 1)"
)
args = parser.parse_args()
if args.runs < 1:
    parser.error("--runs must be at least 1")

with open("../tests/eval_tickets.json") as f:
    tickets = json.load(f)

total = len(tickets)
def pct(n):
    return f"{n}/{total} ({round(n / total * 100)}%)"

def is_danger(ticket, result):
    """True when a real incident is classified with high_confidence onto a
    path that skips review.

    The two paths:
    - it_support or security_question, which raise no alert
    - security_incident at low, which files the attack as a lapse with no
      attacker. It posts to the incidents Slack channel at the lowest priority.

    The criterion is defined in docs/evaluation.md, the actions in
    docs/action-table.md.
    """
    # Compared as enums, so a renamed member in schemas.py raises an
    # AttributeError. A bare string would stop matching and report no danger.
    if ticket["expected_category"] != Category.security_incident.value:
        return False
    if result.confidence != Confidence.high_confidence:
        return False
    if result.category in (Category.it_support, Category.security_question):
        return True
    return (result.category == Category.security_incident
            and result.severity == Severity.low)

def answer(result):
    """One classification's full answer, as a tuple that can be compared across runs."""
    return (result.category.value, result.severity.value,
            result.confidence.value, result.hostname, result.username,
            result.source_ip)

# Each ticket's answer in every run. A failed call is recorded by its failure
# type, so a ticket that fails in one run and classifies in another counts as
# unstable.
answers = [[] for _ in tickets]
danger_failures = []
danger_evaluated = 0
failed_calls = 0

for run in range(1, args.runs + 1):
    if args.runs > 1:
        print(f"\n=== run {run} of {args.runs} ===")

    passed = 0
    # Tracked separately so a classification regression and an entity-extraction
    # regression can't cancel out in the aggregate score. Entity extraction is the
    # newer, less-tested judgment call, so it needs its own visible number.
    classification_passed = 0
    entity_passed = 0

    for i, ticket in enumerate(tickets, start=1):
        try:
            result = classify_ticket(
                subject=ticket["subject"],
                message=ticket["message"]
            )
        except ClassificationError as e:
            failed_calls += 1
            answers[i - 1].append(f"failed: {e.failure_type}")
            print(f"[{i}] FAIL (classification failed: {e.failure_type}) - {ticket['subject']}")
            print("    " + str(e).replace("\n", "\n    "))
            continue

        answers[i - 1].append(answer(result))

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

        # danger_evaluated counts every classification of a ticket labeled a
        # security incident. It is the denominator of the danger figure.
        danger = False
        if ticket["expected_category"] == Category.security_incident.value:
            danger_evaluated += 1
            danger = is_danger(ticket, result)
            if danger:
                danger_failures.append((run, i))

        if classification_ok and entity_ok:
            passed += 1
            print(f"[{i}] PASS - {ticket['subject']}")
        else:
            which = ", ".join(
                part for part, ok in
                (("classification", classification_ok), ("entities", entity_ok))
                if not ok
            )
            marker = " DANGER" if danger else ""
            print(f"[{i}] FAIL ({which}){marker} - {ticket['subject']}")
            print(f"    expected: {ticket['expected_category']}, {ticket['expected_severity']}, {ticket['expected_confidence']}, "
                  f"hostname={ticket['expected_hostname']}, username={ticket['expected_username']}, source_ip={ticket['expected_source_ip']}")
            print(f"    got:      {result.category.value}, {result.severity.value}, {result.confidence.value}, "
                  f"hostname={result.hostname}, username={result.username}, source_ip={result.source_ip}")

    print(f"\noverall:        {pct(passed)}")
    print(f"classification: {pct(classification_passed)}")
    print(f"entities:       {pct(entity_passed)}")

print(f"\ndanger failures: {len(danger_failures)} in {danger_evaluated} classifications of security incidents")
for run, i in danger_failures:
    print(f"    run {run}, [{i}] {tickets[i - 1]['subject']}")
print(f"failed calls:    {failed_calls}")

if args.runs > 1:
    unstable = [i for i, seen in enumerate(answers, start=1) if len(set(seen)) > 1]
    print(f"unstable:        {len(unstable)} of {total} tickets across {args.runs} runs")
    for i in unstable:
        print(f"    [{i}] {tickets[i - 1]['subject']}")
        seen = answers[i - 1]
        for distinct in sorted(set(seen), key=seen.index):
            print(f"        {seen.count(distinct)}x {distinct}")
