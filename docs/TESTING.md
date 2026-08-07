# Testing

How the classifier is evaluated and what has been measured. Figures here state
the date, the number of runs, and the files they were measured against. A
figure without that method cannot be reproduced and should not be trusted.

## Running the evaluation

```bash
cd agent
python run_eval.py
```

Needs `ANTHROPIC_API_KEY` in `agent/.env`. One run is 36 API calls.

Classification and entity extraction are scored separately. A ticket passes
classification only if category, severity, and confidence all match. Entity
extraction is scored on hostname, username, and source IP together. Keeping
them apart stops a regression in one from being hidden by the other.

## What the eval set covers

36 hand-written tickets in [tests/eval_tickets.json](../tests/eval_tickets.json),
covering seven shapes:

- unambiguous security incidents
- unambiguous routine requests
- real incidents worded benignly
- benign issues worded alarmingly
- tickets too vague to categorise
- tickets naming a hostname, username, or IP to be extracted
- a prompt injection attempt

## Two pass criteria

**Label accuracy** is the headline number, but it weights every disagreement
equally and they are not equal. Classifying a critical incident as high
over-pages an analyst. Classifying a real incident as routine means nobody is
told.

**The danger criterion** measures only the second kind. A run fails it if any
ticket whose expected category is `security_incident` is classified onto a path
that raises no alert under [action-table.md](action-table.md):

- classified `it_support` or `security_question` with `high_confidence`
- classified `security_incident` at `low` severity with `high_confidence`

Everything else still puts a human in front of the ticket, either through an
alert or through the low confidence override that routes to human review.

The criterion is defined before a run, not after, so results cannot be graded
against whatever the model happened to produce.

## Current results

Measured 2026-08-06 against `agent/classifier.py` and
`tests/eval_tickets.json` as committed alongside this document. Nine full runs,
same result every time. Two of those were captured in full and compared line by
line with no differences.

| Metric | Result |
|---|---|
| Full label | 34 of 36 |
| Category | 36 of 36 |
| Entity extraction | 36 of 36 |
| Unstable tickets | 0 |
| Danger criterion | 0 failures in 180 classifications where it was evaluated |

Both failures are severity or confidence disagreements, neither on category:

- One ticket returns `high_confidence` where the label expects `low_confidence`.
  The user describes clicking a link from a text impersonating internal IT and
  seeing an error page, then says they are unsure whether to worry. The
  confidence rule covers uncertainty about cause; this ticket is uncertain about
  consequence.
- One ticket returns `high` severity where the label expects `medium`. Both
  values carry `low_confidence`, so the override routes the ticket to human
  review either way and the disagreement changes nothing the agent does.

Four of the ten rows in [action-table.md](action-table.md) are not produced by
any ticket in the set, so those paths are unexercised:

- `security_incident` at `medium` severity with `high_confidence`
- `security_incident` at `low` severity with `high_confidence`
- `security_question` at `low` confidence
- `it_support` at `low` confidence

## Comparison against the previous rubric

The severity and confidence rubric was rewritten on 2026-08-06. Both versions
were run against the same 36 tickets, with the same labels, in the same
session, so the difference is attributable to the rubric rather than to a
changed test set or model drift. Two runs each.

| | previous rubric | current rubric |
|---|---|---|
| Full label | 31 of 36 | 34 of 36 |
| Category | 35 of 36 | 36 of 36 |
| Danger criterion failures | 1 | 0 |

The danger failure under the previous rubric was a wire transfer request
impersonating a company executive. It classified as `security_question` with
`high_confidence` in both runs, a path that raises no alert. The category
definition covered security events that had already occurred but not an attack
in progress that nobody had acted on yet. Extending the definition fixed it.

Two further defects were found and closed in the same rewrite:

- **Severity was defined only for security incidents**, leaving the other three
  categories with no rule to sit on. Two tickets alternated between `low` and
  `medium`, landing on `low` in four runs of six. Defining severity separately
  for each category removed the ambiguity.
- **Confidence was defined in three places that disagreed.** The enum
  descriptions and one guidance paragraph described it as how strongly the text
  supported the classification, while a later paragraph said behaviour a user
  could not account for should be `low_confidence`. The model followed the first
  reading, so tickets describing something unexplained were not reaching human
  review. Confidence is now defined once.

## How prompt changes are validated

Prompt changes are not applied and then measured. Both versions run in the same
session against the same ticket set, and the comparison is per ticket rather
than on the aggregate score, because an aggregate can stay flat while one
ticket improves and another regresses.

A change is accepted only if it holds across at least three runs, does not
introduce an unstable ticket, and does not introduce a danger criterion failure.

Two rubric drafts were rejected under this rule before the current one was
applied. The first fixed the unstable tickets but regressed two others, and
contained a contradiction of its own: its `high` definition said an incident of
unknown extent belonged there, while its `critical` definition said not knowing
what an intruder did does not lower severity. The second removed that
contradiction but still gave different severities to two structurally identical
tickets, both reporting a successful unauthorized login with nothing stated to
have ended it. The third added an explicit rule that access persists until the
ticket says otherwise, which resolved it.
