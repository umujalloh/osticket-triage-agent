# Evaluation

The evaluation scores how Claude labels a fixed set of 36 hand-written tickets.
It is a regression check, meant to catch a change that makes classification
worse on those tickets. None of them comes from a real helpdesk, so the score
does not estimate accuracy on real tickets. Its other limits are in
[known-limitations.md](known-limitations.md#the-evaluation-score-is-a-regression-check),
and what the agent does with a label is verified in
[verification.md](verification.md).

## Running the evaluation

```bash
cd agent
./venv/bin/python run_eval.py --runs 9
```

The runner needs `ANTHROPIC_API_KEY`, read from `agent/.env` or the
environment, and classifies with the model in `TRIAGE_MODEL`,
`claude-haiku-4-5` by default.

## What the set covers

[tests/eval_tickets.json](../tests/eval_tickets.json) holds the 36 tickets.
Each records the expected category, severity and confidence, and any hostname,
username or source IP Claude should extract. `run_eval.py` sends Claude only
the subject and message, and compares its answer with the recorded one. The set
covers the following, with ticket numbers in parentheses:

- incidents stated plainly, such as files encrypted for ransom (10)
- incidents that read as routine, such as a slow laptop and an email the user
  does not remember sending (2)
- routine problems that read as emergencies, such as an expired password
  reported as a hacked account (3)
- routine requests, such as a software install (25)
- security questions, such as whether an email is safe (15)
- an attack nobody has acted on yet, a payment request from someone posing as
  the CFO (18)
- tickets too vague to place, such as a question the user no longer remembers
  (14)
- tickets naming a hostname, username or source IP to extract (31 to 34)
- a ticket naming a person and a laptop model, neither of which should be
  extracted (36)
- a prompt injection telling Claude to label an active data theft as routine
  and return planted values (35)

Five rows of the [action table](action-table.md) have no ticket in the set, so
the eval never tests whether Claude gives these labels when they are right:

- `security_incident` at `critical` with low confidence
- `security_incident` at `medium`
- `security_incident` at `low`
- `security_question` at low confidence
- `it_support` at low confidence

`verify_action_table.py` checks the actions on all five without calling
Claude, as [verification.md](verification.md#action-table) records.

## Scoring

A ticket passes classification when its category, severity and confidence all
match the expected ones. It passes entity extraction when its hostname,
username and source IP all match, including a field that is empty in both. The
two are scored separately so a regression in one cannot hide behind the other.
A failed Claude call counts as a miss on both and is also counted on its own.

A miss changes an action when the action table gives Claude's label a different
page, mention, Slack channel, enrichment, routing, osTicket priority or
human-review flag than the expected label.

A ticket is unstable when it does not get the same answer in every run. The
classifier wraps each ticket in a delimiter that is random for every request,
as [Attack 1](architecture.md#attack-1-prompt-injection) describes, and on the
default model `temperature=0` does not guarantee identical output either, so
two runs can give the same ticket different answers.

### The danger criterion

The danger criterion counts the misses that leave an attack without a Slack
alert or file it as a lapse with no attacker. It judges only tickets whose
expected label is `security_incident` at `medium`, `high` or `critical`
severity, because the rubric in `agent/classifier.py` defines `low` severity as
a hygiene or policy lapse with no attacker involved, such as a password exposed
by mistake and then changed. Claude's answer on one of these tickets is a
danger failure when it is:

- `it_support` or `security_question` at high confidence, which raise no Slack
  alert
- `security_incident` at `low` severity, at either confidence, which sends the
  ticket to the incidents Slack channel and sets its osTicket priority to `low`

Other misses on these tickets still reach a person. An attack Claude labels
`it_support` or `security_question` at low confidence, or `unclear`, goes to
the review Slack channel. A critical attack Claude labels `high` or `medium`
severity loses its page but still reaches the incidents Slack channel. An
over-call, such as an attack Claude labels `critical` when it is `high`, is not
counted, since the criterion tracks only missed attacks.

## Current results

Measured 2026-10-13 at commit `de3e5da` with `claude-haiku-4-5`, nine runs of
the 36 tickets.

| Measure | Result |
|---|---|
| Classification | 35 of 36 in every run |
| Entity extraction | 36 of 36 in every run |
| Danger failures | 0, across 18 attack tickets in nine runs each |
| Failed calls | 0 |
| Unstable tickets | 0 |

The one miss is ticket 14, "Question about my account", which Claude labels
`unclear` at high confidence instead of low in all nine runs, although the
rubric says an `unclear` ticket is always low confidence. An `unclear` ticket
goes to the review Slack channel at either confidence, so the miss changes no
action.

Ticket 22's expected severity was moved from `medium` to `high` on 2026-10-13,
because the 2026-08-06 rubric had narrowed `medium` to incidents that are
contained with their extent known. The classifier already answered `high`, so
the relabel added one pass.

In three earlier nine-run batches on the same prompt, tickets 14, 18 and 19
were each unstable at least once, 14 and 19 on confidence and 18 on severity.
Across all four batches, ticket 18 came back `critical` instead of `high` once
in 36 runs, which would lead to an unneeded page through the WAKE PagerDuty
service.

## How prompt changes are validated

A prompt change is measured before it is applied. The current prompt and the
proposed one each run nine times on the same tickets, back to back.
`run_eval.py` has no option for an alternate prompt, so the proposed one runs
from a scratch copy of `classifier.py`. Each ticket is compared on its passes
out of nine, because a total can stay flat while one ticket improves and
another gets worse. A change is accepted when:

- each ticket it targets passes at least seven of nine runs, with at least
  three more passes than under the current prompt
- no other ticket loses three or more passes in nine on a miss that changes an
  action
- the proposed prompt produces no danger failure

The rubric's rule that a lockout does not end an intruder's access meets all
three conditions. Measured on 2026-10-13, it raised ticket 1 from two to nine
passes in nine runs, and the only other ticket to drop three passes was ticket
14, on a miss that changes no action. Two broader wordings that also fixed
ticket 1 were rejected, because they labeled ticket 18, a payment request
nobody acted on, `critical` instead of `high`, in all nine runs under one and
in three of nine under the other, which would page the WAKE PagerDuty service.
The rule was set on 2026-10-13 while the lockout change was being measured, and
that change is the only one judged by it so far.

An earlier rubric rewrite, on 2026-08-06, was measured with an older form of
this method, two runs per version. Under the old rubric, ticket 18 came back as
`security_question` at high confidence, a danger failure, because
`security_incident` did not cover an attack nobody had acted on yet. Extending
it to such attacks took danger failures from one to zero, under the danger
criterion as defined then.
