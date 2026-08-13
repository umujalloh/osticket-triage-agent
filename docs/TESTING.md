# Testing

How the agent is tested and what has been measured, both the classifier on its
own and the full path from osTicket through to Splunk. Figures here state
the date, the number of runs, and the files they were measured against. A
figure without that method cannot be reproduced and should not be trusted.

## Running the evaluation

```bash
cd agent
./venv/bin/python run_eval.py
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

## End-to-end verification

The eval harness above tests the classifier directly. It scores classifier
output against ticket text and never touches the plugin, the webhook, or the
Splunk clients, so a fault anywhere on that path scores clean. This section
covers a single live run through the full path, not a repeated measurement like
the eval numbers above.

**Method.** A ticket was submitted through osTicket's own ticket form, not a
direct call to the agent's webhook endpoint, so the run exercises
`class.TriagePlugin.php`, its HMAC signing, and the PHP-to-Python payload.

**Result.** Measured 2026-08-09, ticket 9, submitted through the real osTicket
form with requester `bgist@froth.ly` and ticket text naming `BGIST-L`. Confirmed
in Splunk under `ticket_id: 9`:

| Event | Field | Value |
|---|---|---|
| classification_complete | category | security_incident |
| classification_complete | severity | critical |
| classification_complete | confidence | high_confidence |
| classification_complete | extracted_hostname | BGIST-L |
| enrichment_complete | event_count | 20 |

The extracted hostname is recorded on the classification event but does not
appear in the enrichment query. Entities come from ticket text the submitter
writes, so letting one in would hand the search target to whoever filed the
ticket. All 20 stored events contain `bgist@froth.ly` and none contain
`BGIST-L`, which on its own matches 10,327 events in the index.

This run predates two changes and no longer describes current behavior. It was a
guest submission, which the authenticated-session gate now excludes from the
email clause, and it stored whole raw events, which the named field list now
replaces. Reproducing it takes a confirmed account and returns the named fields.

## Authentication gate verification

**Method.** Measured 2026-08-11. Two tickets filed through the real osTicket
form with the same requester address and identical text. The only variable is
whether the submitter held an authenticated client session.

**Result.**

| | Ticket 10 | Ticket 11 |
|---|---|---|
| Submitted as | guest, private window | signed in as `bgist@froth.ly` |
| Requester address | `bgist@froth.ly` | `bgist@froth.ly` |
| Attached to user record | 3, Bill Gist | 3, Bill Gist |
| Recorded submitter IP | `172.21.0.1` | `172.21.0.1` |
| Classification | security_incident / critical / high_confidence | identical |
| `requester_verified` | `false` | `true` |
| Events returned | 0 | 20 |

Both tickets attached to the same user record, because osTicket binds an address
typed into the guest form to whatever user already owns it. That is what makes
ticket 10 an impersonation rather than an unknown sender.

Bill Gist holds a confirmed account and ticket 10 is attached to it, so a gate
that read the ticket owner's account status would have returned true and
searched his address for an anonymous submitter. Only the session check
separates these two runs.

No stored event on ticket 11 contains `_raw`. The fields present are `_time`,
`host`, `sourcetype`, `src_ip`, `dest_ip`, `ipAddress`, `userPrincipalName`,
`email`, `loginStatus`, `signinErrorCode`, and `appDisplayName`, totalling 3,540
bytes across 20 events.

## Write-back endpoint verification

Measured 2026-08-12 against the running stack.

| Request | Result |
|---|---|
| Unsigned | 401 |
| Wrong signature | 401 |
| Correct shape, wrong secret | 401 |
| Timestamp 10 minutes old | 401 |
| Signed, note field missing | 400 |
| Signed, ticket 99999 | 404 |
| Signed, valid, ticket 11 | 200 |

The successful write was confirmed in the database rather than from the response
code: an internal thread entry on ticket 11, type N, poster `Triage Agent`.
Ticket 11 carries two of them, entries 14 and 15, because the run was repeated
when the script below was added. Type N is an internal note, which is what makes
the Attack 3 claim that notes are invisible to the submitter true rather than
aspirational.

Reproduce with `./venv/bin/python verify_writeback.py <ticket_id>` from
`agent/`. The last case writes a real note, and the endpoint has no delete
operation, so name a ticket you don't mind marking.

## Idempotency store verification

Measured 2026-08-12, fourteen checks, all passing. Run against a temporary
database so the live store is never written to. That separation matters: a test
that inserted ticket IDs into the real store would later refuse the genuine
ticket carrying the same number.

| Property | How it was checked | Result |
|---|---|---|
| A ticket can be claimed | first `claim_ticket(42)` | `True` |
| It cannot be claimed twice | second `claim_ticket(42)` | `False` |
| Claiming one does not block others | `claim_ticket(43)` | `True` |
| One ticket, either spelling | `claim_ticket("42")` after `42` | `False` |
| A fresh ticket has done nothing | `completed_actions(43)` | all four `False` |
| A marked action is recorded | mark then read `note_written` | `True` |
| Actions are independent | mark `note_written`, read `paged` | `False` |
| Marking twice is harmless | mark `note_written` again | still `True` |
| An unknown ticket does not raise | `completed_actions(9999)` | all four `False` |
| A misspelled action is refused | `mark_done(43, "not_a_real_action")` | `ValueError` |
| A completed action outlives a missing claim | `mark_done(77)` with no claim | recorded, warning printed |
| A claim survives a restart | reload module, `claim_ticket(42)` | `False` |
| Action state survives a restart | reload module, read `note_written` | `True` |
| The store still accepts new tickets | reload module, `claim_ticket(44)` | `True` |

The last row exists to stop the two above it passing for the wrong reason. A
store that refused everything after a restart would satisfy both, and only fail
this one.

Reproduce with `./venv/bin/python verify_idempotency.py` from `agent/`.

Whether a retried webhook actually avoids writing a second note is not verified
here, because nothing calls the store's action tracking yet. That belongs with
the end-to-end run once the write path is wired.

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
