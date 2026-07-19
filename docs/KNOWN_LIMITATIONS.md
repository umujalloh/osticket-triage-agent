# Known Limitations

Findings from evaluating the classifier against the eval set in [tests/eval_tickets.json](../tests/eval_tickets.json).
Design rationale for the classification model lives in [architecture.md](architecture.md).

## Confidence on fully uninformative tickets

The system prompt instructs the classifier to always return `low_confidence`
when the category is `unclear`. On one eval ticket ("Question about my
account"), the model consistently returns `high_confidence` instead, across
every run. The ticket contains no information at all, and the model appears
to read this as strong support for the `unclear` classification rather than
as ambiguity. This has no routing effect, since `unclear` tickets always
escalate to human review regardless of confidence.

## Residual non-determinism at temperature 0

Classification runs at `temperature=0`, which eliminated variance on 29 of
30 eval tickets. One ticket alternates between `low` and `medium` severity
across batches of runs, with no changes to the prompt or eval set.
Temperature 0 selects the highest-probability output but does not guarantee
bitwise determinism, and where two severity values are near-equally
probable, the result can shift.

Observed accuracy: 93-97% across eight runs. Category accuracy is stable at
100%. All variance is severity, on tickets where the correct value is
genuinely arguable.

## Text-only classification

The classifier sees only the ticket subject and body. It has no access to
logs, endpoint telemetry, network data, or the user's history. Some real
incidents are not distinguishable from routine issues on ticket text alone,
and the system prompt instructs the classifier to escalate unexplained
behavior with `low_confidence` rather than dismiss it. In production, cases
that ticket text cannot resolve are expected to be caught by endpoint and
network monitoring, not by this component.

## Evaluation set

The eval set is 30 tickets written by hand to cover five shapes: unambiguous
security incidents, unambiguous routine requests, real incidents worded
benignly, benign issues worded alarmingly, and tickets too vague to
categorize. Security questions appear across several of these rather than
having a separate shape. Several expected labels changed during evaluation
as the severity definitions were tightened. The set is not drawn from
production ticket data and does not represent real-world class distribution,
which would skew heavily toward routine requests.
