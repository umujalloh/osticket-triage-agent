# Verification

What the built system was checked to do, and how. The
[evaluation](evaluation.md) scores the classifier against labelled tickets and
never touches the plugin, the webhook, the Splunk clients or the action layer,
so a fault anywhere on that path would score clean. This file covers what that
cannot reach.

Two kinds of record. Live runs drive a real ticket through the whole path and
are dated to the run. Verifier sections are scripted checks, most of them
offline, that can be re-run from `agent/verification/`.

## End-to-end verification

A live run drives a ticket through the whole path: submitted on the real form,
signed by the plugin, classified, written back, alerted. These are single runs
recorded with their date, not repeated measurements.

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

A confident critical. It writes a note, sets priority, posts to the urgent
channel with a mention, and pages WAKE. Submitted through the osTicket form as a
confirmed user, with text describing an account the submitter could not lock an
intruder out of.

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
around 133 seconds. The page now goes out before both. Ticket 36 below records
the new order, and this table is a record of the old one.

What the run still shows is every action reaching its destination on a confident
critical, and the enrichment content that lands on the ticket.

### The full path on the current ordering, 2026-08-25, ticket 36

Submitted through the osTicket form as a confirmed user, reporting an account the
submitter could not lock an intruder out of. A confident critical, which writes a
note, sets priority, posts to the urgent channel with a mention, and pages WAKE.

| Time | Event | Value |
|---|---|---|
| 23:58:35.791 | paged | WAKE |
| 23:58:35.802 | classification_complete | security_incident / critical / high_confidence, `requester_verified` true |
| 23:58:37.430 | enrichment_complete | 20 events |
| 23:58:37.486 | note_written | |
| 23:58:37.530 | priority_set | normal to emergency |
| 23:58:37.786 | slack_posted | urgent, mentioned true |

This is the run the ticket 20 section was waiting for. The page is first, 11ms
ahead of the classification audit write and 1.6 seconds ahead of enrichment. That
is the order the agent was changed to on 2026-08-19, hours after the ticket 20
run, and no live run had recorded it until now.

Confirmed outside Splunk. Ticket 36, number 114404, priority Emergency, and one
internal note posted as `Triage Agent`, type N. The note holds 20 events spanning
2018-08-20 13:10:25 to 15:07:39, grouped into sign-in outcomes, source and
destination addresses, accounts and applications. Its last line is the query that
produced them, `index=botsv3 ("bgist@froth.ly" OR "172.21.0.1") earliest=0`,
which names only the verified requester address and the IP the server observed.

The three screenshots in [the README](../README.md#a-triaged-ticket) are this run.

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

Measured 2026-08-23 against the running stack, twenty-five checks, all passing.

| Request | Result |
|---|---|
| Unsigned | 401 |
| Wrong signature | 401 |
| Correct shape, wrong secret | 401 |
| Timestamp 10 minutes old | 401 |
| Signed, note field missing | 400 |
| Signed, ticket 99999 | 404 |
| Signed, valid, ticket 11 | 200 |
| Signed, valid, a second note on the same ticket | 200, `status: note_exists` |
| Unsigned, department | 401 |
| Stale timestamp, department | 401 |
| Unknown ticket, department | 404 |
| Signed, valid, department | 200, `status: routed` |
| Signed, valid, department again | 200, `status: already_routed` |
| Signed, department named in the body | 200, moved where the config says |

The successful write was confirmed in the database rather than from the response
code: an internal thread entry on ticket 11, type N, poster `Triage Agent`.
Type N is an internal note, which is what makes the Attack 3 claim that notes
are invisible to the submitter true rather than aspirational.

The repeat case is the reason the endpoint now checks. Ticket 18 accumulated 35
agent notes across the runs made before it did, each one a verifier writing
another copy onto the same ticket, which is what a retry after a timeout would
have done in production. Running the verifier against ticket 21 afterwards left
it with the one note it already had.

Reproduce with `./venv/bin/python verification/verify_writeback.py <ticket_id>`
from `agent/`. It writes a real note to a ticket that has none, and the endpoint
has no delete operation, so name a ticket you don't mind marking.

## Idempotency store verification

Measured 2026-08-20, twenty-six checks, all passing. Run against a temporary
database so the live store is never written to. That separation matters: a test
that inserted ticket IDs into the real store would later refuse the genuine
ticket carrying the same number.

| Property | How it was checked | Result |
|---|---|---|
| A ticket can be claimed | first `claim_ticket(42)` | `True` |
| It cannot be claimed twice | second `claim_ticket(42)` | `False` |
| Claiming one does not block others | `claim_ticket(43)` | `True` |
| One ticket, either spelling | `claim_ticket("42")` after `42` | `False` |
| A fresh ticket has done nothing | `completed_actions(43)` | every action `False` |
| A marked action is recorded | mark then read `note_written` | `True` |
| Actions are independent | mark `note_written`, read `paged` | `False` |
| Marking twice is harmless | mark `note_written` again | still `True` |
| An unknown ticket does not raise | `completed_actions(9999)` | every action `False` |
| A misspelled action is refused | `mark_done(43, "not_a_real_action")` | `ValueError` |
| An older store gains missing columns | a store built with one action column | all present |
| What it recorded survives the migration | the same store | unchanged |
| A migrated column reads as not done | the same store | `False` |
| A completed action outlives a missing claim | `mark_done(77)` with no claim | recorded, warning printed |
| A claim survives a restart | reload module, `claim_ticket(42)` | `False` |
| Action state survives a restart | reload module, read `note_written` | `True` |
| The store still accepts new tickets | reload module, `claim_ticket(44)` | `True` |

The last row exists to stop the two above it passing for the wrong reason. A
store that refused everything after a restart would satisfy both, and only fail
this one.

The store also holds the classification each ticket was given, which is what a
resumed ticket finishes on. It is written as JSON and validated on the way back
out, so a value this build cannot read is reported as no decision rather than
handed on as one.

| Property | How it was checked | Result |
|---|---|---|
| A ticket nobody classified has no decision | `stored_classification(43)` | `None` |
| A decision reads back unchanged | store, then read | identical object |
| Storing a decision touches no action flag | read `priority_set` after | `False` |
| A decision outlives a missing claim | store with no claim | kept, warning printed |
| An unreadable decision is no decision | column overwritten with an invalid category | `None` |
| A decision survives a restart | reload module, read it back | identical object |
| A pre-migration ticket has no decision | the store built without the column | `None` |
| And a migrated store can hold one | store, then read | identical object |

Reproduce with `./venv/bin/python verification/verify_idempotency.py` from `agent/`.

Whether a retried webhook actually avoids writing a second note is not verified
here, because this file only exercises the store. It is covered under action
wiring below, where the note write is driven through the store three times.

## Resume verification

Measured 2026-08-20, sixteen checks, all passing, against a temporary database.
Nothing here reaches Claude, Slack, PagerDuty, osTicket or Splunk. It exercises
the decision a repeat delivery lands on, which is one of three: a duplicate to
refuse, a ticket to pick up, or a ticket another run is working on now.

| Property | How it was checked | Result |
|---|---|---|
| A ticket never seen is undecided | `outstanding_actions(1)` | `["classified"]` |
| A claim with no decision is undecided | claim only, then read | `["classified"]` |
| A decision lists the actions its row selects | a confident critical, nothing done | all five |
| What happened drops off the list | mark `paged`, read again | four left |
| A finished ticket has nothing outstanding | mark all five | `[]` |
| A page that never fell back is not outstanding | read `paged_fallback` | `False` |
| A routine request wants no alert or page | `it_support`, high confidence | note, priority, audit |
| A security question wants its move | `security_question`, high confidence | those three plus `routed` |
| An unaudited decision is unfinished work | note and priority done, audit not | `["classification_audited"]` |
| A ticket nobody is on can be started | `begin_processing(7)` | `True` |
| And cannot be started twice | `begin_processing(7)` again | `False` |
| One ticket, either spelling | `begin_processing("7")` after `7` | `False` |
| Another ticket is unaffected | `begin_processing(8)` | `True` |
| A finished ticket can be started again | end, then begin | `True` |
| A run that raises does not swallow it | `_process_ticket` patched to raise | raises |
| And still releases the ticket | `begin_processing(9)` after | `True` |

The last two matter more than they look. The in-flight mark is only useful if it
is always released, and a run that raised without releasing would lock that
ticket out of every later delivery until the process restarted.

Reproduce with `./venv/bin/python verification/verify_resume.py` from `agent/`.

### Resuming a real interrupted ticket, 2026-08-20, ticket 23

The verifier above tests the decision. This tests the path. Ticket 23 was
submitted through the osTicket form as a confirmed user and classified
`security_incident` / `high` / `high_confidence`, which writes a note, sets
priority, alerts the incidents channel, and pages nowhere.

| Time | Step | Result |
|---|---|---|
| 12:20:01.817 | accepted | claimed, decision stored |
| 12:20:03.899 | classification_complete | audit recorded |
| 12:20:04.020 | note_written | |
| 12:20:04.113 | priority_set | |
| 12:20:04.298 | slack_posted | incidents |
| 16:06:28 | signed delivery repeated | `200 duplicate` |
| | `slack_posted` cleared in the store | stands in for a run that died before the alert |
| 16:17:17.807 | triage_resumed | `slack_posted` outstanding |
| 16:17:18.009 | slack_posted | incidents |

Both repeat deliveries were signed with the real secret and carried a current
timestamp, which is what makes them retries rather than replays the freshness
window would refuse. The resume is recorded before the work it authorises, so a
resumed run that then hangs still leaves a record that it was resumed. The
second delivery produced:

```
Ticket 23: resuming, slack_posted outstanding
Ticket 23: resuming on the stored security_incident/high/high_confidence, requester_verified=True
Ticket 23: note already written, skipping
Ticket 23: priority already set, skipping
Ticket 23: slack posted to incidents
```

No line reporting a classification, because none was requested. The audit index
holds one `classification_complete` for ticket 23 across all three deliveries,
which is the whole point of recording that the write landed: the decision was
made once and is entered once. Each resume added a `triage_resumed` event naming
what was outstanding, so a ticket that was interrupted is visible as one rather
than as a second round of writes with nothing accounting for them.

Both repeat deliveries were sent by hand, which is how the interruption was
staged. What re-sends them in the deployment is the retry queue below.

## Recovery verification

Measured 2026-08-22, twenty-four checks offline plus one live run. The offline
checks replace every outbound client and skip Claude through the resume path,
so nothing leaves the machine. Four of them cover a store that fails while the
agent is accepting a ticket, since a mark left set there refuses that ticket
for the life of the process. Four more cover one ticket failing partway through
the backlog, which must not stop the tickets behind it.

| Property | How it was checked | Result |
|---|---|---|
| An accepted ticket is unfinished | body stored, not yet complete | listed for recovery |
| A finished one is not | body dropped | not listed |
| A completed run drops its own body | full run through `process_ticket` | body gone |
| Recovery completes what was interrupted | note done, everything else not | priority set, alert posted |
| It does not repeat what was done | the same run | note not rewritten |
| A ticket past the window is not completed | backdated two hours | no actions, no alert |
| And says so on the ticket | the same ticket | note, "did not finish" |
| And tells the review channel | the same ticket | posted to review |
| And records the abandonment | the same ticket | `interrupted_past_recovery_window` |
| And is not rescanned | after abandoning | body cleared |
| An unreadable body is dropped | column set to invalid JSON | not acted on |

### A real interrupted ticket, 2026-08-22, ticket 32

Submitted through the osTicket form as a confirmed user. A watcher polling the
store killed the agent with `SIGKILL` the moment the ticket was claimed, before
classification. osTicket had its 202 and queued no retry, so nothing in the
deployment would have delivered that ticket again.

The agent was restarted with no delivery of any kind, and on boot:

```
Ticket 32: interrupted, finishing classified
Ticket 32: classified it_support/high/high_confidence, requester_verified=True
Ticket 32: note written
Ticket 32: priority normal to high
Recovery: 1 ticket(s) finished, 0 too old to finish
```

Confirmed outside the store: ticket 32 carries priority High and a note posted
as `Triage Agent`. No Slack post and no page, which is correct for that row.
`requester_verified` survived the kill and the restart, which matters because it
reads the submitter's live session and cannot be rebuilt.

Reproduce the offline checks with
`./venv/bin/python verification/verify_recovery.py` from `agent/`.

## Retry queue verification

Measured 2026-08-20, 21 and 23 against `osticket-plugin/class.TriagePlugin.php`.
Run against the live stack rather than a harness, because the thing under test
is what the plugin does when the agent is not there, and that is not something
a mock can be wrong about convincingly.

The agent was stopped with `pkill`, tickets were submitted through the real
osTicket form as a confirmed user, and cron was fired by sending osTicket's own
`cron` signal. Firing the signal rather than running `api/cron.php` keeps the
test to the plugin, since `Cron::run()` would also start osTicket's dormant
maintenance cycle and mark every older test ticket overdue.

| Path | Ticket | What was checked | Result |
|---|---|---|---|
| A failed send queues the ticket | 24, 25, 26, 29, 30 | agent stopped, ticket submitted | queued, `requester_verified` 1 |
| Cron drains the queue | 24, 29 | agent restarted, cron signal sent | delivered and classified |
| The window expires during the outage | 25, 30 | aged to 61 minutes, agent still down | note says triage never ran, row deleted |
| A drain stops at the first failure | 26 | same cron run as ticket 25 | still queued, attempts 1 to 2 |
| Creating a ticket drains one | 26 | ticket 27 submitted with agent up | 27 delivered, 26 drained after it |
| The queue empties | all | after each drain | no rows left |
| A store failure queues the ticket | 33 | store made read-only, agent up, ticket submitted | agent 500, queued, `requester_verified` 1 |

Ticket 33 is the one case where the agent was running and still refused. The
store was made unwritable, so the claim failed and the webhook answered 500
rather than accepting a ticket it could not record. The plugin queued it,
`api/cron.php` drained it once the store was writable again, and the agent
classified it with `requester_verified` still true. That value is the reason the
queue stores it rather than rebuilding it, and a retry an hour later would still
have carried it.

The third and fourth rows are the ones worth reading together. They ran in a
single cron pass with the agent unreachable, and they are what the design is
for. Expiry is local work, so it completed and put a note on ticket 25 while
the agent was still down, which is the only time that note is any use. The
drain in the same pass tried ticket 26, failed, and stopped rather than working
through the rest at a timeout each.

The value that matters most is `requester_verified`. Ticket 24 was submitted by
a confirmed user, queued, and delivered minutes later by cron, and the agent
logged `requester_verified=True` on the retry. Nothing in a retry can observe
that, since it reads the submitter's browser session, so it is stored at
failure time and replayed. Had it been recomputed it would have been false, the
enrichment query would have dropped its email clause, and nothing would have
reported the difference.

The note is posted as `Triage Plugin`, confirmed in the thread on tickets 25
and 29. The write endpoint decides a note is a repeat by looking for its own
poster, `Triage Agent`, so the two names have to differ or the plugin's note
would make a later triage note bounce as already present and be recorded as
written. Both were present on ticket 29 under their own names.

### One note, rewritten, 2026-08-21, tickets 29 and 30

The plugin writes its note on the first failed send and edits that same note in
place as the ticket's state changes. The note has three bodies, and a ticket
reaches the second or the third but never both. Two tickets cover all three.

**Ticket 29, delivery recovers.**

| Entry | Poster | Body |
|---|---|---|
| 92 | Triage Plugin | written 00:21:54, triage has not run, retrying until about 01:21 |
| 92 | Triage Plugin | rewritten, delivery delayed 1 minute, accepted at 00:23 |
| 93 | Triage Agent | written 00:23:37, `it_support / medium / high_confidence` |

**Ticket 30, delivery never recovers.** The agent was stopped for all of it.

| Entry | Poster | Body |
|---|---|---|
| 95 | Triage Plugin | written 00:48:04, triage has not run, retrying until about 01:48 |
| 95 | Triage Plugin | rewritten after the row was aged past the window, triage never ran |

In both runs the entry keeps its id across the rewrite, so neither ticket ever
carries two plugin notes disagreeing about whether triage ran. On ticket 29 the
agent's own note is a separate entry under its own poster, which is what the
two-poster rule is for. On ticket 30 the queue row was deleted at the same
time, and the whole sequence ran during the outage rather than after it.

The rewrite has no timestamp of its own because `setBody()` does not touch the
`updated` column, so the row still reads its original created time afterwards.
The body is what a reader sees and it is current; when the edit happened is not
recorded.

Ticket 25 earlier in the table reached the same end state as ticket 30 by a
different route. It expired before the note became rewrite-in-place, so it
wrote its note rather than editing one.

The first attempt at ticket 29 failed, and the reason is worth recording because
nothing about it is visible from the code. `Thread::getEntries()` caches its
result on the thread, and `getMessages()` does `clone $this->getEntries()` and
then filters the clone by type. The clone is shallow, so that filter reaches
back into the shared cache and narrows it to messages for the rest of the
request. `buildPayload` calls `getMessages()` immediately before the note
lookup, which left the lookup seeing one entry where the thread had four. The
note was invisible rather than absent, and the plugin wrote a second one.

The lookup now queries `ost_thread_entry` directly. Confirmed by reproducing
the sequence: after `getMessages()`, walking `getEntries()` returns 1 entry
while the direct query returns the note. `agentNoteExists` in the write
endpoint was changed the same way. Nothing on its path calls `getMessages()`
today, so it was not broken, but a dedup that silently stops deduping when
someone adds one is not worth leaving in place, and this is the same defect
that let ticket 18 collect 35 notes.

Not covered here: whether a real cron schedule fires the signal. This exercised
the handler and the signal wiring by sending the signal directly. Running
`api/cron.php` on a schedule is a deployment step, in
[architecture.md, Section 10](architecture.md#10-deployment-preconditions).

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

Measured 2026-08-21, forty-five checks, all passing.

| Property | How it was checked | Result |
|---|---|---|
| A mention renders for critical | `build_message` with `mention=True` | `<!here>` present |
| Below critical does not mention | high severity to the incidents channel | absent |
| The review channel shows the reason | an unclear ticket, then a low-confidence one | category, then "low confidence" |
| Every alert states its confidence | all three channels, both confidences | stated, never inferred |
| A paged alert names its destination | urgent, both rows | `paged WAKE`, `paged NOTIFY` |
| An alert that did not page says nothing about paging | the incidents channel | no marker |
| A page that failed says so | urgent, both destinations, page not sent | `WAKE PAGE FAILED`, never `paged WAKE` |
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
reporting forty-four checks skipped delivery rather than proving it.

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

Reproducing the delivery case on a PagerDuty developer account creates the
incident and produces no call, which is the plan rather than a fault in the
agent. What this lab can and cannot show about paging is in
[known-limitations.md](known-limitations.md), and what the design needs from
the two destinations is in architecture.md, Section 10.

## Page reporting verification

Measured 2026-08-21, ten checks, all passing. Run offline. Claude is skipped by
storing a decision so the ticket takes the resume path, and every outbound
client is replaced, so nothing reaches PagerDuty, Slack, osTicket or Splunk.

This covers wiring rather than rendering. `verify_slack.py` already checks what
`build_message` produces. The defect was upstream of it: `_page` returned
whether the page was sent and both callers discarded that, so the alert named
the destination the table had chosen whether or not anyone was reached.

| Case | Alert says | Store |
|---|---|---|
| PagerDuty refuses the event | `WAKE PAGE FAILED, escalate manually` | `paged` not recorded |
| PagerDuty accepts it | `paged WAKE` | `paged` recorded |
| Resumed after the page, before the alert | `paged WAKE` | unchanged |

The third row runs with `send_page` rigged to raise, so a regression that called
PagerDuty for a page already sent fails here rather than passing quietly.

Reproduce with `./venv/bin/python verification/verify_page_reporting.py` from
`agent/`.

## Action wiring verification

Measured 2026-08-23, thirty-nine checks, all passing. It did not run between
2026-08-19 and that date, because a required argument was added to the alert
builder and this file was not updated with it. Nothing was wrong with the agent,
but the file this section describes had stopped running while this section said
it passed. Covers whether the actions obey the kill switch and whether a retry
can repeat one. Each case runs in its
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
| Writes off skips the routing | kill switch off | skipped, nothing recorded |
| Writes on routes the ticket | kill switch on | moved and recorded |
| A second move is refused | a third run against the same store | refused |
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

Measured 2026-08-23, twenty checks across nineteen requests, all passing. The
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
| Signature carrying a byte outside ASCII | 401 |
| Signature of the wrong length | 401 |
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

## Heartbeat and the agent-down alert

Measured 2026-08-21 against `agent/main.py` and
`docker/splunk-provisioning/triage_alerts`. Run with the interval set to 20
seconds instead of the default 60, so a loop that only worked once would be
obvious inside a minute.

The agent was started and twelve consecutive beats were read back out of
Splunk:

| Property | How it was checked | Result |
|---|---|---|
| A beat is sent at startup | first event after boot | uptime 0, immediate |
| The loop keeps going | events over four minutes | 12 beats, none missed |
| The interval holds | gaps between events | 20.0s, drift under 30ms |
| Uptime counts up | `uptime_seconds` per beat | 0, 20, 40 through 220 |
| The kill switch state rides along | `writes_enabled` | true, matching the boot line |
| Importing the agent sends nothing | verifiers import `main` | no beats during their runs |

The last row is the one that would have gone wrong quietly. Three verifiers
import `main` to exercise decision logic, and a heartbeat started at import
rather than at application startup would have written to the real index every
time one ran.

The alert is the other half and is verified separately, because a heartbeat
nothing watches is not detection, and an alert nobody receives is not much
better. Its search was first run by hand over two windows:

| Window | Beats | Condition `beats=0` |
|---|---|---|
| The last ten minutes, agent running | 28 | false, stays quiet |
| A window predating the heartbeat | 0 | true, would fire |

Then against a real outage. The agent was stopped at 02:33 and left
down. The scheduled search evaluated true from then on, and the alert invoked
its email action:

```
sendemail:292 - Sending email. subject="Triage agent is not reporting",
recipients="['...']", server="smtp.gmail.com:587"
```

with no error line following it, against the failed attempt earlier the same
day which logged three:

```
sendemail_auth:56 - Unable to create SMTP Object. Error=[Errno 111]
Connection refused ... server="localhost"
```

Both runs logged `Sending email` at INFO, because that line is written before
the transaction rather than after it, so the INFO line alone proves nothing.
Neither does the absence of an error. Six of those sends reached nobody with
nothing logged at all: `sendemail` reports a connection failure loudly, as the
`localhost` attempt above shows, and reports an authentication rejection not at
all. It connected to Gmail with no credentials, was refused with `530
Authentication Required`, and recorded success.

The cause was where the password lived. Splunk's Settings UI writes in the
launcher app context, so the credential landed in
`apps/launcher/local/alert_actions.conf` while `sendemail` reads the global
configuration and found none there. Copying the encrypted value into
`etc/system/local/alert_actions.conf` and restarting fixed it, and
`auth_password` then read as set through the REST API where it had read empty.

Delivery is confirmed as of 2026-08-22, in two overlapping halves rather than
one continuous run. The scheduled search fired against a real outage and
invoked the email action at 20:15, and a send through that same `sendemail`
path arrived in the recipient's inbox at 00:29. Both halves run through
`sendemail`, so together they cover the path from the agent dying to a person
being told.

Splunk's `fired_alerts` endpoint is worth a separate warning. It reported zero
triggers throughout, including for runs that provably invoked the email action,
so it does not answer whether an alert fired. `scheduler.log` and `python.log`
do.

## Delivery failure alert verification

Measured 2026-08-22 against `docker/splunk-provisioning/triage_alerts`. Two
alerts, one for pages and one for Slack posts. Exercised with synthetic events
written to the audit index and tagged `synthetic: true`, because producing real
failures means breaking a live credential.

| Property | How it was checked | Result |
|---|---|---|
| A broken destination is detected | 3 failures, nothing succeeding after | selected |
| Below the threshold stays quiet | 2 page failures against 3 Slack | only Slack selected |
| Destinations stay independent | both kinds failing at once | grouped separately, not pooled |
| A recovered destination clears | one success written after the failures | not selected, no timer involved |
| The subject names the destination | fired with actions enabled | `Action needed: triage Slack posts failing to incidents` |
| The body names the failure type | the same email | `The Slack posts are failing with auth_failure.` |

The last two rows are the ones that needed a real send. Every earlier attempt
rendered as `Splunk Alert: Triage paging is failing`, Splunk's default template,
because the custom text was set as `action.email.subject.alert` while Splunk
reads `action.email.subject`. Both keys were present and the API reported the
custom one, so the configuration looked correct and the email was not. Only
firing it with actions enabled showed the difference.

Two alerts did not fire during that run, both correctly. The heartbeat alert
declined because the agent was up and beating. The paging alert was inside its
one hour suppression window from a firing nine minutes earlier.

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

