# Known Limitations

Findings from evaluating the classifier against the eval set in
[tests/eval_tickets.json](../tests/eval_tickets.json), and constraints of the
Splunk enrichment added in Phase 2. Measurements and the method behind them are
in [TESTING.md](TESTING.md). Design rationale, including the threat model and
the residual risk left after each defense, lives in
[architecture.md](architecture.md).

## Residual non-determinism at temperature 0

Classification runs at `temperature=0`, which selects the highest-probability
output but does not guarantee bitwise determinism. Where two values are near
equally probable, the result can shift between runs.

Two tickets behaved this way under earlier versions of the severity rubric,
alternating between `low` and `medium` and landing on `low` in four runs of
six. Severity had been defined only for security incidents, so tickets in the
other three categories had no rule to sit on. Defining severity separately for
each category removed the ambiguity, and nine full runs on 2026-08-06 produced
identical results.

The property has not gone away, only the tickets exposed to it. A future ticket
sitting between two values can still flip, and the harness scores one run per
ticket, so a single run cannot distinguish a flip from a regression.

## Text-only classification

The classifier sees only the ticket subject and body. It has no access to logs,
endpoint telemetry, network data, or the user's history. Some real incidents are
not distinguishable from routine issues on ticket text alone, and the system
prompt instructs the classifier to escalate unexplained behavior with
`low_confidence` rather than dismiss it.

The same constraint limits what confidence can express. The prompt treats a
ticket as uncertain when the user cannot account for what happened, but a user
can describe an event clearly and still have no idea whether it mattered. A
report of clicking a suspicious link and seeing an error page is complete as a
narrative and empty as evidence. One eval ticket of that shape returns
`high_confidence` where the label expects `low_confidence`.

In production, cases that ticket text cannot resolve are expected to be caught
by endpoint and network monitoring, not by this component.

## Evaluation set

The eval set is 36 tickets written by hand to cover seven shapes: unambiguous
security incidents, unambiguous routine requests, real incidents worded
benignly, benign issues worded alarmingly, tickets too vague to categorize,
tickets naming an entity to extract, and a prompt injection attempt. The set is
not drawn from production ticket data and does not represent real-world class
distribution, which would skew heavily toward routine requests. Several expected
labels have changed as the severity and confidence definitions were tightened,
most recently on 2026-08-06.

Four of the ten rows in [action-table.md](action-table.md) are not produced by
any ticket in the set, so those paths are unexercised. They are listed with
current results in [TESTING.md](TESTING.md).

The score is a regression detector, not an estimate of real-world accuracy.

## Splunk enrichment queries a frozen, fictional dataset

The Splunk instance is loaded with BOTSv3, a static training dataset. Its events
span 2018-08-20 to 2019-09-19 and every entity in it is invented, so no real
ticket will match it. Enrichment returns results only for demo tickets written
to reference known BOTSv3 hosts and accounts.

The pipeline itself is real: validated entities, a least-privilege role scoped
to a single index, and read-only searches over TLS against a live Splunk
instance. What is not real is any correspondence between a ticket and the log
data, so this demonstrates the enrichment path rather than live incident
correlation.
