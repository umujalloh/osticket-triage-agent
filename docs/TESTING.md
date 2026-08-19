# Testing

How the agent is tested and what has been measured, both the classifier on its
own and the full path from a submitted ticket through to the note, the alert and
the page. Figures here state the date, the number of runs, and the files they
were measured against. A figure without that method cannot be reproduced and
should not be trusted.

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

It is kept because it is the only run that shows the extracted entity being
recorded and not used. A high-severity ticket does not enrich, and the runs below
are the ones that exercise Phase 3.

### The full path, 2026-08-19, ticket 20

A confident critical, the only row that reaches every action the agent has.
Submitted through the osTicket form as a confirmed user, with text describing an
account the submitter could not lock an intruder out of.

| Time | Event | Value |
|---|---|---|
| 03:49:06.604 | classification_complete | security_incident / critical / high_confidence |
| 03:49:07.494 | enrichment_complete | 20 events |
| 03:49:08.037 | paged | fallback false |
| 03:49:08.065 | note_written | |
| 03:49:08.096 | priority_set | normal to emergency |
| 03:49:08.365 | slack_posted | urgent, mentioned true |

Confirmed outside Splunk as well. The osTicket note is `format: text` and holds
20 events spanning 2018-08-20 13:10 to 15:07, grouped into sign-in outcomes,
three source addresses and the account `bgist@froth.ly`. Ticket priority is
Emergency. The idempotency store shows all four action columns set, which no
earlier run had produced. A push notification arrived on the responder's phone.

The ordering in this run has since been changed and no longer describes the
agent. The page ran after enrichment here, which meant it also ran after two
audit writes, so a Splunk that hung rather than refused would have held it for
around 133 seconds. The page now goes out before both. A fresh run is needed to
record the new order, and until it exists this table is a record of the old
one.

What the run still shows is every action reaching its destination on a confident
critical, and the enrichment content that lands on the ticket.

### Acting through a Splunk outage, 2026-08-18, ticket 18

The audit pipeline stopped while the agent kept working. Splunk was stopped with
`docker stop`, then a ticket was submitted normally.

Every audit write failed after three attempts. The note was still written, the
priority was still set, and the alert still reached the incidents channel,
confirmed in the osTicket database rather than from console output.

The delay is measurable without Splunk, because the idempotency store records
when the webhook was accepted and osTicket records when the note was written.
Ticket 17 was submitted with identical text 38 minutes earlier and produced an
identical classification, so the two runs differ only in whether Splunk was up.

| | Webhook accepted | Note written | Elapsed |
|---|---|---|---|
| Ticket 17, Splunk up | 23:31:38.365 | 23:31:39 | about 0.6s |
| Ticket 18, Splunk down | 00:09:12.341 | 00:09:22 | about 9.7s |

osTicket stores thread entries to the second, so each figure carries up to a
second of error. Two audit writes fail before the note is reached, the
classification and the human-review record, and each burns three attempts with
one and three second backoffs. That accounts for eight of the nine seconds, with
the Claude call making up the rest. Three more failed writes follow the note, so
the full sequence runs longer still.

An earlier build returned as soon as the classification audit write failed, so a
Splunk outage produced a console line and nothing else.

### What the live runs found that the verifiers did not

Three faults that no verifier would have caught, however many checks it ran,
because none of them is in the code those checks call.

The agent was bound to `127.0.0.1`, so the osTicket container could not reach it
at all. A verifier calls functions directly and never crosses the container
boundary. The plugin logged the refused connection to `ost_syslog`, nothing else
noticed, and the ticket was never triaged.

Console output was block-buffered when stdout was redirected to a file, so every
diagnostic the agent prints sat in a buffer. A verifier reads subprocess output,
which flushes on exit, so it never sees this. In a deployment it means a log tail
shows nothing.

The first attempt at the ticket 20 run was processed by an agent started seven
hours earlier, before the paging code existed. It classified, enriched, wrote and
alerted correctly and never paged, because `uvicorn` does not reload on file
change. The run measured a build that no longer matched the repository.

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

Reproduce with `./venv/bin/python verification/verify_writeback.py <ticket_id>`
from `agent/`. The last case writes a real note, and the endpoint has no delete
operation, so name a ticket you don't mind marking.

## Idempotency store verification

Measured 2026-08-19, eighteen checks, all passing. Run against a temporary
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
| An older store gains missing columns | a store built with one action column | all five present |
| What it recorded survives the migration | the same store | unchanged |
| A migrated column reads as not done | the same store | `False` |
| A completed action outlives a missing claim | `mark_done(77)` with no claim | recorded, warning printed |
| A claim survives a restart | reload module, `claim_ticket(42)` | `False` |
| Action state survives a restart | reload module, read `note_written` | `True` |
| The store still accepts new tickets | reload module, `claim_ticket(44)` | `True` |

The last row exists to stop the two above it passing for the wrong reason. A
store that refused everything after a restart would satisfy both, and only fail
this one.

Reproduce with `./venv/bin/python verification/verify_idempotency.py` from `agent/`.

Whether a retried webhook actually avoids writing a second note is not verified
here, because this file only exercises the store. It is covered under action
wiring below, where the note write is driven through the store three times.

## Action table verification

Measured 2026-08-19, thirty-one checks, all passing. The table is the contract
between classification and action, so every row is compared as a whole `Actions`
object rather than field by field. A row that gets one field wrong fails on that
row instead of hiding behind the fields it gets right.

| Property | How it was checked | Result |
|---|---|---|
| Every documented row matches the code | 30 rows from `docs/action-table.md` | all match |
| Every category has a row | each `schemas.Category` member looked up | no gaps |
| An unknown category is refused | a category with no row | raises |

An earlier version returned `human_review` for an unknown category at low
confidence, which reads as safe and is not. It would have let a category the
table has never seen produce a plausible-looking action instead of failing
loudly.

Reproduce with `./venv/bin/python verification/verify_action_table.py` from `agent/`. Nothing
is written and no network call is made.

## Alert delivery verification

Measured 2026-08-19, thirty-three checks, all passing.

| Property | How it was checked | Result |
|---|---|---|
| A mention renders for critical | `build_message` with `mention=True` | `<!here>` present |
| Below critical does not mention | high severity to the incidents channel | absent |
| The review channel shows the reason | an unclear ticket, then a low-confidence one | category, then "low confidence" |
| All four enrichment states read differently | each outcome built in turn | four distinct lines |
| The failure notice names the failure | `build_failure_message` | "classification failed", the type |
| It carries no severity icon | every icon except the review one | none present |
| The kill switch stops delivery | writes off | returns skipped |
| A missing webhook refuses to boot | writes on, one webhook blank | refuses, names it |
| A missing base URL refuses to boot | writes off, base URL blank | refuses |
| A failure never leaks the webhook | canary planted in the URL | canary absent from output |
| A real post is delivered | one message to the test channel | accepted |

A webhook URL is a bearer credential, and HTTP client errors routinely embed the
request URL in their message text, which then reaches the console and the audit
index. The canary test plants a known string inside the URL, forces two
different failures, and fails if that string appears anywhere in the child
process output.

Reproduce with `./venv/bin/python verification/verify_slack.py` from `agent/`. One case takes
about 17 seconds because it exhausts three retries against an unreachable host.
The delivery case needs `SLACK_WEBHOOK_TEST` set and skips without it, so a run
reporting fewer than thirty-three checks skipped delivery rather than proving
it.

## Paging verification

Measured 2026-08-19, twenty-nine checks, all passing.

| Property | How it was checked | Result |
|---|---|---|
| The page leads with the classification | `build_page` on a confident critical | severity and category first |
| An unknown destination is refused | `send_page` with a name the table never produces | raises before posting |
| It claims nothing about enrichment | the built page | no events, enrichment or identifier wording |
| Severity maps to PagerDuty's | every `Severity` member | all four mapped |
| The dedup key is the ticket id | the built event | `"15"` |
| The link text is the URL itself | the `links` entry | text equals href |
| No enrichment output crosses | the payload | no `custom_details` |
| The fallback leads with the failure | `build_fallback_page` | "alert delivery failed" first |
| It does not read as a confident critical | the same summary | does not start with the severity |
| The kill switch stops delivery | writes off | returns skipped |
| A missing routing key refuses to boot | writes on, key blank | refuses |
| A failure never leaks the routing key | canary as the key | canary absent from output |
| A real page is delivered | one event to the test service | accepted |

The routing key sits in the request body rather than the URL, so the usual
danger of a client library echoing the URL does not apply here. What can still
expose it is a rejection quoting the field it refused, which is why the canary
is the key itself and why the response body is truncated before it is logged.

Reproduce with `./venv/bin/python verification/verify_pagerduty.py` from `agent/`. The
delivery case needs `PAGERDUTY_ROUTING_KEY_TEST` and skips without it.

A PagerDuty developer account cannot deliver SMS or voice notifications, and
this cannot be enabled for any reason. Push and email work. Anyone reproducing
the delivery case on a developer account will see the incident created and no
call, which is the plan rather than a fault in the agent.

## Action wiring verification

Measured 2026-08-19, thirty-four checks, all passing. Covers whether the actions
obey the kill switch and whether a retry can repeat one. Each case runs in its
own process, because `ENABLE_WRITES` is read at import and patching it in place
would not test what happens at boot.

| Property | How it was checked | Result |
|---|---|---|
| Both criticals page, nothing else does | every combination in the table | two rows |
| Only the one at low confidence falls back | the same walk | one row |
| Writes off skips all four actions | kill switch off | four skips, nothing recorded |
| Writes on performs all four | kill switch on | four done, all recorded |
| A retry repeats nothing | a third run against the same store | four refusals |
| An unaudited note records the gap | note built with the audit failed | "No audit record." last |
| A failed classification reaches review | `classify_ticket` forced to raise | posted to review |
| It writes no note and sets no priority | the same case | neither recorded |
| A retried failure posts once | a second run against the same store | refused |
| A refused page leaves the fallback available | the retry case | `paged_fallback` still false |
| The page precedes the classification audit write | HEC pointed at a dead port | paged first |
| The page precedes enrichment | the same case | paged first |

The first two rows exist because of a bug this check found. The fallback page
originally tested severity alone, so an `it_support` ticket the classifier rated
critical would have paged the security on-call whenever its Slack post failed.
Walking every combination surfaced it.

The last two rows assert an order rather than a duration, because the retry
constants are free to change and the ordering is not. The case points the HEC
endpoint at a dead port so every audit write fails, then checks that the page
went out ahead of the first of them. The page's own audit event is allowed to
fail behind it, which is why the check names the classification write instead of
matching the generic Splunk failure line.

Reproduce with `./venv/bin/python verification/verify_wiring.py <ticket_id>` from `agent/`.
Several cases write a real note, set a real priority and send real alerts, so
name a ticket you don't mind marking. Alerts and pages go to the test
destinations when those are configured.

## Webhook gate verification

Measured 2026-08-19, eighteen checks across seventeen requests, all passing. The
duplicate request is asserted twice, on its status code and on the reason it
gives. The endpoint osTicket calls is the only part of the agent an outsider can
reach, and a request that fails any check here is refused before the agent does
any work.

| Request | Result |
|---|---|
| No signature header | 401 |
| Wrong signature | 401 |
| Signed with the wrong secret | 401 |
| Signature missing its `sha256=` prefix | 401 |
| Body that is not JSON | 400 |
| Body that is a JSON array | 400 |
| Body that is a JSON string | 400 |
| Timestamp 10 minutes old | 401 |
| Timestamp 5 minutes ahead | 401 |
| Timestamp missing | 401 |
| Timestamp unparseable | 401 |
| Ticket ID missing | 400 |
| Ticket ID `true` | 400 |
| Ticket ID a list | 400 |
| Ticket ID an object | 400 |
| Ticket ID already processed | 200, `status: duplicate` |
| The same request again | 200, `status: duplicate` |

Each case is the only thing wrong with its request. The gate runs in a fixed
order, so a body that is both unsigned and malformed only ever demonstrates the
signature check, and the rest of the path never runs.

A timestamp five minutes in the future is refused because the freshness window
allows 60 seconds of clock skew and no more, so a replay cannot buy itself a
window by claiming to be from ahead. A boolean ticket ID is refused explicitly,
because `isinstance(True, int)` is true in Python and it would otherwise pass
the numeric check.

The accepted path is not exercised here. A `202` queues classification, a note,
an alert and possibly a page against a real ticket, so proving it belongs with
the end-to-end runs above, where all three returned `202` through the plugin's
own signing.

Reproduce with `./venv/bin/python verification/verify_webhook.py <ticket_id>`
from `agent/`, naming a ticket the agent has already processed. That ID is used
for the duplicate cases, and an unprocessed one would be claimed and queue real
work. Set `TRIAGE_WEBHOOK_URL` if the agent is not on `127.0.0.1:8000`, and note
that this is the address the agent bound to rather than the one osTicket uses.

## Not yet verified

Four things this file does not cover, listed so the sections above are not read
as a complete picture.

The fallback page. `needs_fallback_page` is the most intricate condition in the
agent and it has only ever run in the wiring verifier. No real Slack failure has
produced one.

A classification failure end to end. The wiring verifier forces
`classify_ticket` to raise, which proves the path, but no run has been driven by
a genuine Claude failure with the real failure-type mapping.

A slow dependency in front of an action. The page now runs before enrichment and
before the audit writes, and the wiring verifier proves that order against a
dead audit endpoint. What no run has produced is the delay itself, an osTicket
or Splunk call that hangs to its full timeout rather than refusing at once, so
the numbers this ordering exists to avoid are arithmetic from the retry
constants rather than measurements.

An end-to-end run on the current ordering. The ticket 20 table above records the
old one.

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
