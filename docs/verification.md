# Verification

What the built system was checked to do, and how. How accurately the classifier
labels tickets is measured separately, in [evaluation.md](evaluation.md).

This file holds two kinds of evidence:

- **Live runs:** a real ticket submitted through osTicket and followed through
  the stack, recorded once with its date.
- **Verifiers:** scripts in `agent/verification/` that anyone can re-run. The
  nine offline verifiers need nothing running, and CI runs them on every push.
  The five live verifiers are run by hand, because they need the running stack,
  post to Slack, or page PagerDuty.

What each section proves, and how:

| What is proven | Section | How |
|---|---|---|
| A ticket submitted on the osTicket form reaches every action its row selects | [End-to-end runs](#end-to-end-runs) | live run |
| A Splunk outage delays the ticket writes and stops none of them | [End-to-end runs](#end-to-end-runs) | live run |
| Only a signed, fresh, well-formed request for a real ticket is accepted | [Webhook gate](#webhook-gate) | live verifier |
| The requester's email is searched only for an authenticated session | [Authentication gate](#authentication-gate) | live run |
| A ticket the agent never accepted is retried, then marked as never triaged | [Retry queue](#retry-queue) | live run |
| Ticket text cannot close the delimiter around it in Claude's prompt | [Prompt isolation](#prompt-isolation) | offline |
| Each classification produces exactly its action table row | [Action table](#action-table) | offline |
| A ticket cannot choose what Splunk is searched for | [Enrichment query](#enrichment-query) | offline |
| A ticket is claimed once and each action recorded once, across restarts | [Idempotency store](#idempotency-store) | offline |
| A repeat delivery is refused, or does only the work left undone | [Resume](#resume) | offline |
| An interrupted ticket is finished, or handed to review, on the next start | [Recovery](#recovery) | offline, plus a live run |
| Only the write secret can change a ticket | [Write-back endpoints](#write-back-endpoints) | live verifier, plus live runs |
| Values copied from the logs cannot become links in a note | [Note links](#note-links) | offline, plus a live run |
| Every action obeys the kill switch, and a retry repeats none of them | [Action wiring](#action-wiring) | live verifier, plus a live run |
| A Slack alert states what happened, carries nothing the submitter wrote, and never leaks its webhook | [Slack alerts](#slack-alerts) | live verifier |
| A PagerDuty page carries nothing the submitter wrote, PagerDuty accepts it, and the routing key never leaks | [PagerDuty pages](#pagerduty-pages) | live verifier |
| An accepted page is checked for an incident, and one that reached nobody is reported | [Page confirmation](#page-confirmation) | offline, plus live runs |
| A Slack alert says whether the page reached an incident, including after a restart | [Page reporting](#page-reporting) | offline |
| A dead routing key is found within five minutes, and a check that cannot run is reported | [Routing key check](#routing-key-check) | offline, plus live runs |
| A stopped or restart-looping agent, a failing Slack channel or PagerDuty service, or a dead routing key, triggers an email | [Monitoring](#monitoring) | live run |

## End-to-end runs

A live run submits a ticket on osTicket's own form, so it exercises the
plugin's HMAC signing and the PHP-to-Python payload, then follows it through
classification, write-back and alerting. Every ticket this file submits through
the form was filed as `bgist@froth.ly`, a fictional user from the BOTSv3
dataset, so enrichment finds its 2018 events. Tickets 9 to 36 arrived from
`172.21.0.1` and tickets 37 to 42 from `172.22.0.1`, the lab's Docker gateway
before and after its networks were split. known-limitations.md covers the
[dataset](known-limitations.md#enrichment-searches-a-frozen-fictional-dataset)
and the [gateway](known-limitations.md#the-submitter-ip-is-the-docker-gateway).

### The full path, 2026-10-14, ticket 42

**Method:** Submitted as a verified user, reporting an intruder still in their
account. A high-confidence critical writes a note, sets priority, posts to the
urgent Slack channel with `@here`, and pages WAKE.

**Result:** In Splunk's audit index, in UTC:

| Time | Event | Value |
|---|---|---|
| 03:35:01.872 | paged | WAKE, confirmed |
| 03:35:01.889 | classification_complete | security_incident / critical / high_confidence, `requester_verified` true |
| 03:35:06.923 | enrichment_complete | 20 events |
| 03:35:07.133 | note_written | |
| 03:35:07.311 | priority_set | normal to emergency |
| 03:35:07.499 | slack_posted | urgent, mentioned true |

In osTicket:

| On the ticket | Value |
|---|---|
| Number | 283973 |
| Priority | Emergency |
| Note | one internal note, type N, posted as `Triage Agent` |
| Note's events | 20, from 2018-08-20 13:05:10 to 15:07:39 |
| Note's search line | `index=botsv3 ("bgist@froth.ly" OR "172.22.0.1") earliest=0` |

Type N is osTicket's code for an internal note, which only staff can see.

**What it shows:** The page goes out first, 17 milliseconds ahead of the
classification audit write and 5 seconds ahead of enrichment. Its audit entry
is timestamped when PagerDuty accepted it. The three screenshots in
[the README](../README.md#a-triaged-ticket) are this run.

### Acting through a Splunk outage, 2026-08-18, ticket 18

**Method:** Splunk was stopped with `docker stop`, then a ticket was submitted.
Ticket 17 had been submitted with identical text 38 minutes earlier and got an
identical classification, so the two runs differ only in whether Splunk was up.

**Result:** Every audit write failed after three attempts. The note was still
written, the priority was still set, and the alert still reached the incidents
Slack channel, confirmed in the osTicket database.

| | Webhook accepted | Note written | Elapsed |
|---|---|---|---|
| Ticket 17, Splunk up | 23:31:38.365 | 23:31:39 | about 0.6s |
| Ticket 18, Splunk down | 00:09:12.341 | 00:09:22 | about 9.7s |

**What it shows:** A Splunk outage delays the ticket writes and stops none of
them. osTicket stores thread entries to the second, so each figure carries up to
a second of error. Two audit writes fail before the note, and each failed write
waits one and then three seconds between its three attempts, which accounts for
eight of the nine seconds. The run predates the page moving ahead of the audit
writes, and its row did not page.

### Acting through a hanging Splunk, 2026-10-17

**Method:** The audit log was pointed at a local port that accepts connections
and never answers, so every write to Splunk waited out its timeouts. A critical
ticket then ran through the agent's full path, with Claude's answer stubbed to a
confident critical, since the test is about timing. The page went to the test
PagerDuty service and the alert to the test Slack channel. The ticket ID did not
exist in osTicket, so the note and priority writes failed. Each step after the
classification is timed when its call to PagerDuty, osTicket or Slack answered.

| Step | Time after the ticket started |
|---|---|
| Classification | 0.0 s |
| Page | accepted at 0.5 s, confirmed at 3.8 s |
| Each audit write | 19 s, three timed-out attempts |
| Note and priority | failed at 38.8 s and 58.0 s |
| Urgent Slack alert | 77.2 s |

**What it shows:** A hanging Splunk does not delay a new ticket's page, and the
page's own audit write runs beside the rest of the work. Every action after the
page waits behind an audit write, so the urgent Slack alert went out about 77
seconds late. A Splunk that refuses connections at once, as in the run above,
costs about ten seconds.
[known-limitations.md](known-limitations.md#a-hanging-splunk-delays-everything-after-the-page)
covers why this is not fixed.

### Acting through a hanging osTicket

**Method:** osTicket's write endpoint was pointed at a local port that accepts
connections and never answers, so every note and priority write waited out its
timeouts. Splunk, Slack and PagerDuty ran normally. A critical ticket then ran
through the agent's full path, with Claude's answer stubbed to a confident
critical, since the test is about timing. The page went to the test PagerDuty
service and the alert to the test Slack channel.

**Result:** Measured 2026-10-11.

| Step | Time after the ticket started |
|---|---|
| Classification | 0.8 s |
| Page | accepted at 1.3 s, confirmed at 2.6 s |
| Each ticket write | 37 s, three timed-out attempts |
| Note and priority | failed at 38.5 s and 75.5 s |
| Urgent Slack alert | 75.8 s |

**What it shows:** A hanging osTicket never delays the page or its confirmation,
but the urgent Slack alert waits behind the note and priority writes and went
out about 75 seconds late.
[known-limitations.md](known-limitations.md#a-hanging-osticket-delays-the-slack-alert)
covers why this is not changed.

### What the live runs found that the verifiers did not

Four faults no verifier could catch, because none is in the code a verifier
calls:

- **The agent was bound to `127.0.0.1`**, which the osTicket container cannot
  reach. The plugin logged the refused connection to `ost_syslog`, and the
  ticket was never triaged.
- **Console output was block-buffered** when redirected to a file, so a log
  tail showed nothing. A verifier reads subprocess output, which flushes on
  exit.
- **The first attempt at the ticket 20 run was handled by an agent started
  seven hours earlier**, before the paging code existed, because `uvicorn` ran
  without `--reload`. It classified, enriched, wrote and alerted, and never
  paged.
- **The plugin could not see its own note** on the first attempt at ticket 29,
  so it wrote a second one. Earlier in the same request, osTicket had narrowed
  its cached list of the ticket's entries to user messages only. The plugin now
  looks for the note in the database directly.

### Superseded runs

Four earlier runs no longer describe the agent.

**Ticket 9, 2026-08-09:** A guest submission that enriched on the requester
email and stored whole raw events. The authentication gate now leaves a guest's
email out of the query, and enrichment now returns named fields only. It also
showed an extracted hostname, `BGIST-L`, recorded on the classification and not
used in the query. All 20 stored events contained `bgist@froth.ly`, and none
contained `BGIST-L`, which on its own matches 10,327 events.

**Ticket 20, 2026-08-19:** Every action reached its destination on a
high-confidence critical, but the page ran after enrichment and two audit
writes. Ticket 42 records the order that replaced it.

**Ticket 23, 2026-08-20:** The ticket's Slack alert was cleared in the store to
stand in for a run that died before it. A signed repeat delivery picked the
ticket up and posted only the alert, and the audit index held one
classification for it. The agent now resumes only on the request it first
stored, which a finished run deletes, so the same staging is now refused as a
duplicate. [Recovery](#recovery) covers the current behavior.

**Hanging Splunk, 2026-10-08:** The page's audit write still ran ahead of the
note. Its note, priority and Slack times match the console lines printed after
each step's own audit write, and it put the urgent Slack alert at 116 s.
[Acting through a hanging Splunk](#acting-through-a-hanging-splunk-2026-10-17)
records the current timing.

## Webhook gate

**Method:** `verify_webhook.py` sends twenty-three requests to the endpoint
osTicket calls, each refused for exactly one reason. The gate runs its checks in
a fixed order, so each case reaches only the check it tests.

**Result:** Measured 2026-10-15 on ticket 42, twenty-four checks, all passing.
The first duplicate request counts twice, once for its `200` and once for its
`duplicate` reason, which is why twenty-three requests give twenty-four checks.

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
| Ticket number that does not match osTicket's | 403 |
| Ticket osTicket does not have | 403 |
| Ticket number missing | 400 |
| Right number for a ticket past the retry window the agent never processed | 403 |
| Ticket ID already processed | 200, `status: duplicate` |
| The same request again | 200, `status: duplicate` |

**What it shows:** Every refusal happens before the agent does any work,
including these less obvious ones:

- A timestamp five minutes ahead is refused, because the freshness window
  allows only 60 seconds of clock skew.
- A boolean ticket ID is refused explicitly, because Python treats `True` as the
  integer 1, so it would otherwise pass as ticket 1.
- A request that fails the ticket number check never touches the store, so a
  forged request cannot mark a ticket ID as taken.

The verifier does not exercise the accepted path, since a `202` queues real work
against a real ticket. The end-to-end runs cover that.

**Reproduce:** From `agent/`, with the agent and osTicket running:

```bash
TRIAGE_WEBHOOK_URL=http://172.17.0.1:8000/webhook/ticket \
  ./venv/bin/python verification/verify_webhook.py <ticket_id>
```

The verifier needs two things:

- **A ticket the agent has finished:** passed as `<ticket_id>`. A ticket the
  agent was interrupted on would be resumed, with real writes.
- **Ticket 1 at least 65 minutes old:** ticket 1 is the one osTicket's installer
  creates, and the verifier refuses to run until it is past the plugin's retry
  window plus five minutes.

### A forged claim does not block the real ticket, 2026-09-27, ticket 38

Run by hand with writes off. A signed request claimed ticket 38 with a made-up
number before the ticket existed. The agent refused it with 403, and the store
gained no row. A ticket then filed through the osTicket form was given ID 38,
and osTicket's own request for it was accepted with 202 and classified. The
ticket number lookup ran while osTicket was still waiting on that request, so
the check works inside a live submission.

## Authentication gate

**Method:** Two tickets were filed through the osTicket form with the same
requester address and identical text. The only difference was whether the
submitter held an authenticated session.

**Result:** Measured 2026-08-11.

| | Ticket 10 | Ticket 11 |
|---|---|---|
| Submitted as | guest, private window | signed in as `bgist@froth.ly` |
| Requester address | `bgist@froth.ly` | `bgist@froth.ly` |
| Attached to user record | 3, Bill Gist | 3, Bill Gist |
| Recorded submitter IP | `172.21.0.1` | `172.21.0.1` |
| Classification | security_incident / critical / high_confidence | identical |
| `requester_verified` | `false` | `true` |
| Events returned | 0 | 20 |

**What it shows:** osTicket attaches an address typed into the guest form to the
user who already owns it, so ticket 10 is an impersonation of a known user. A
gate that read the ticket owner's account status would have searched Bill Gist's
address for an anonymous submitter. The agent checks the submitter's session
instead, so only ticket 11 was searched by email. Ticket 10's zero events also
mean its IP matched nothing, since the IP is searched either way.

## Retry queue

**Method:** Run against the live stack to test the plugin's retry while the
agent is down, as described in
[architecture.md, Section 7](architecture.md#when-the-agent-is-unreachable).
The agent was stopped, then tickets were submitted as a verified user. The
plugin tried to send each ticket to the agent, got a refused connection, and
added the ticket to its retry queue. Cron was then fired by sending osTicket's
`cron` signal directly, which runs the plugin's retry handler. For tickets 25
and 30, the queue row was backdated 61 minutes in the database to pass the retry
window.

**Result:** Measured 2026-08-20, 21 and 23.

| What happens | Tickets | Result |
|---|---|---|
| A send fails while the agent is down | 24, 25, 26, 29, 30 | queued, with the session stored as verified |
| Cron runs after the agent restarts | 24, 29 | delivered and classified |
| The retry window passes with the agent still down | 25, 30 | note says triage never ran, queue row deleted |
| Cron hits a send that fails | 26 | stops there, ticket kept for the next run |
| A new ticket's send succeeds while one is queued | 27, with 26 queued | 27 delivered, then 26 sent after it without cron |
| The agent is up but cannot record the ticket | 33 | agent answers 500 instead of accepting it, ticket queued, delivered once the store was writable |

**What it shows:** A ticket the agent never accepted is not lost. It is
delivered once the agent is back, or marked as never triaged once the retry
window passes. The plugin stores `requester_verified` when the send fails, since
it comes from the submitter's live session and a retry has no session to read.
Ticket 24 was retried and still logged `requester_verified=True`.

### One note, rewritten, 2026-08-21, tickets 29 and 30

The plugin writes one note on the first failed send, and rewrites that same note
as the ticket's state changes. It posts as `Triage Plugin`, because the write
endpoint refuses a new note when the ticket already has one posted as
`Triage Agent`, and would otherwise refuse the agent's own triage note as a
duplicate.

**Ticket 29, delivery recovers:**

| Entry ID | Poster | Written | Note says |
|---|---|---|---|
| 92 | Triage Plugin | 00:21:54 | triage has not run, retrying until about 01:21 |
| 92 | Triage Plugin | rewritten | delivery delayed 1 minute, accepted at 00:23 |
| 93 | Triage Agent | 00:23:37 | `it_support / medium / high_confidence` |

**Ticket 30, delivery never recovers, agent stopped throughout:**

| Entry ID | Poster | Written | Note says |
|---|---|---|---|
| 95 | Triage Plugin | 00:48:04 | triage has not run, retrying until about 01:48 |
| 95 | Triage Plugin | rewritten once the retry window passed | triage never ran |

The note kept its entry ID across the rewrite, so neither ticket carried two
plugin notes that disagree.

## Prompt isolation

**Method:** The classifier wraps the ticket in a delimiter, and the system
prompt tells Claude to treat everything inside it as data. A submitter who
types the closing delimiter into the ticket could end the block early, so the
text after it would read as instructions. The delimiter was the fixed
`<ticket>` until 2026-09-08. It is now `ticket-` followed by eight random hex
characters, generated per request. `verify_prompt_isolation.py` wraps a hostile
ticket and inspects the text Claude would receive. No Claude call is made.

**Result:** Measured 2026-09-08, eight checks, all passing.

| Property | How it was checked | Result |
|---|---|---|
| A hostile ticket cannot end the block early | a message containing `</ticket>`, then an instruction to classify it as routine, then `<ticket>` | closed once, by the random delimiter |
| The delimiter is new for every request | the same ticket wrapped fifty times | fifty different delimiters, none of them the fixed `<ticket>` |
| The ticket reaches Claude unchanged | subject and message as submitted, attack text included, compared byte for byte with what Claude receives | identical |

**What it shows:** A ticket cannot end its own block, because the delimiter is
random for every request and the submitter cannot know it in advance. Text
after a fake closing delimiter still reaches Claude as ticket data, unchanged.
The verifier does not show how Claude responds to injected instructions, which
the injection ticket in [evaluation.md](evaluation.md) tests.

**Reproduce:** `./venv/bin/python verification/verify_prompt_isolation.py` from
`agent/`. Offline.

## Action table

**Method:** The action table, listed in [action-table.md](action-table.md),
decides what the agent does with each classification. `verify_action_table.py`
runs each combination of category, severity and confidence through the code and
compares all of the resulting actions with its row, so one wrong action fails
the whole row. It also checks the schema that validates Claude's output before
the table sees it. No Claude call is made.

**Result:** Measured 2026-10-13, thirty-nine checks, all passing.

| Property | How it was checked | Result |
|---|---|---|
| The code matches every row of action-table.md | 14 category, severity and confidence combinations | all match |
| Every category Claude can return has a row | each category in the schema | no gaps |
| A category with no row gets no actions | a made-up category | refused with an error, no default row used |
| Low confidence quiets the page and keeps every other action | a low-confidence critical | NOTIFY instead of WAKE, no `@here`, note, priority, enrichment and urgent Slack channel kept, flagged for human review |
| Only critical security incidents are enriched | security incidents at high, medium and low, and `it_support` at critical | none enriched |
| Priority uses osTicket's names | each severity | critical to emergency, high to high, medium to normal, low to low |
| The schema refuses critical outside a security incident | `it_support` at critical, `unclear` at high confidence, a critical security incident | the first refused, the other two accepted |
| Claude cannot add an action to its output | an extra `action` field | refused |
| Claude cannot name a ticket to act on | a `ticket_id` field, sent as text | refused as an unknown field |
| A hostname or username Claude extracts must match its pattern in full | each with a trailing newline | value left out, ticket still classified, the same values without the newline kept |

**What it shows:** For every classification Claude can return, the code takes
exactly the actions action-table.md lists. The schema refuses a critical
outside a security incident before it reaches the table. An `unclear` ticket at
high confidence is accepted, and the table sends it to review. Every action
goes to the ticket ID from the authenticated webhook,
because a classification cannot carry one, which is the defense [Attack
2](architecture.md#attack-2-confused-deputy) describes.

**Reproduce:** `./venv/bin/python verification/verify_action_table.py` from
`agent/`. Offline.

## Enrichment query

**Method:** For a critical security incident, the agent searches Splunk for the
submitter's email and IP address and adds what it finds to the ticket note. Both
values arrive with the ticket, so each must pass a strict pattern before it
reaches the query. `verify_enrichment_query.py` builds queries from accepted and
hostile values and inspects the query string. Each hostile value is passed
alone, so getting no query back means that value was left out. Nothing is sent
to Splunk.

**Result:** Measured 2026-10-03, eighteen checks, all passing.

| Input | Result |
|---|---|
| A verified email, a valid IPv4 and a valid IPv6 address | each searched |
| An email from an unverified requester | left out |
| `requester_verified` sent as the string `true` or the number 1 | treated as unverified, email left out |
| An email with a quote, a pipe, a space or a trailing newline | left out |
| An IP with a quote, an IPv6 zone, or an octet out of range | left out |
| Nothing safe to search on | no search runs |
| Any query | searches only `botsv3`, returns named fields only, never whole events, caps at 20 events |
| A hostname or username from the ticket text | never reaches the query, which takes no such values |

**What it shows:** The only values a ticket can put into the search are the
submitter's verified email and IP address, and each must pass its pattern
first. The query keeps one fixed shape whatever the values, so a ticket cannot
widen it. This is the defense against
[Attack 3](architecture.md#attack-3-indirect-data-exfiltration-via-internal-notes).

**Reproduce:** `./venv/bin/python verification/verify_enrichment_query.py` from
`agent/`. Offline.

## Idempotency store

**Method:** The idempotency store is the agent's SQLite record of each ticket it
has claimed, the webhook body until the ticket completes, the classification it
made, and the actions it has finished. The store prevents a retried or resumed
ticket from being acted on twice. `verify_idempotency.py` runs the store's code
against a temporary SQLite file instead of the agent's own, because test ticket
IDs written there would later refuse the real tickets with those IDs.

**Result:** Measured 2026-10-06, twenty-six checks, all passing.

| What happens | Result |
|---|---|
| Ticket 42 is claimed, then claimed again | the first claim succeeds, the second is refused |
| Ticket 42 is claimed with its ID as text, `"42"` | refused, since it is the same ticket |
| Ticket 43 is claimed while 42 is held | succeeds, since tickets do not block each other |
| A note is recorded as written on ticket 43 | recorded, and no other action on 43 is marked done |
| The same note is recorded again | no change |
| The agent asks about a ticket it has never seen | nothing reported as done |
| An action name is misspelled | refused with an error |
| An action or a classification is stored for a ticket that was never claimed | kept anyway, with a warning, so a retry cannot repeat it |
| A classification is stored and read back | identical, and no action is marked done |
| A stored classification is corrupted | read as missing, so the ticket is classified again |
| The agent restarts | claims, recorded actions and classifications are all still there, and new tickets can still be claimed |
| A store file from an older version, which tracked only notes, is opened | the ticket still claimed, no classification stored, its note kept, the other actions read as not done |

**What it shows:** A ticket is claimed once and each action is recorded once,
and both survive a restart and an upgrade of the store. It does not show the
agent checking the store before it acts, which [Action wiring](#action-wiring)
covers.

**Reproduce:** `./venv/bin/python verification/verify_idempotency.py` from
`agent/`. Offline.

## Resume

**Method:** osTicket can deliver a ticket the agent has already claimed, when
the plugin retries a send or a run was interrupted. The agent reads the store to
decide whether the repeat is a duplicate, unfinished work, or a ticket another
run is still working on. `verify_resume.py` checks that decision against a
temporary SQLite file instead of the agent's own.

**Result:** Measured 2026-10-06, eighteen checks, all passing.

| What happens | Result |
|---|---|
| A repeat arrives for a ticket never seen, or claimed but never classified | classified from the start |
| A repeat arrives for a ticket Claude could not classify | nothing is done, since it has already been sent to the review Slack channel |
| A repeat arrives for a high-confidence critical with nothing done | all five actions left to do: audit log entry, note, priority, Slack post, page |
| A repeat arrives for the same ticket after its page went out | the other four actions left to do |
| A repeat arrives for the same ticket with all five done | nothing left to do, so it is refused as a duplicate |
| A repeat arrives for a routine `it_support` ticket with nothing done | only the audit log entry, note and priority left to do, no alert or page |
| A repeat arrives for a security question with nothing done | the audit log entry, note and priority left to do, plus the move to the security department |
| A repeat arrives for a ticket acted on but never written to the audit log | only the audit log entry left to do |
| A second run tries the same ticket while the first run is still working on it, with the ID sent as a number or as text | refused |
| A run begins for a ticket while another ticket is being worked on | allowed, since each ticket is guarded separately |
| A run ends, or crashes partway | the ticket is released for the next delivery, and a crash is recorded in the audit log by its error type |

**What it shows:** A repeat never redoes an action the store records as done,
and a crash cannot leave a ticket locked or unrecorded. The verifier checks what
the agent decides, not the actions it then takes. [Recovery](#recovery) records
a real interrupted ticket being finished.

**Reproduce:** `./venv/bin/python verification/verify_resume.py` from
`agent/`. Offline.

## Recovery

**Method:** The agent answers osTicket before it does the work, so a crash in
between leaves a ticket osTicket believes was delivered. The agent stores each
ticket's webhook body until the ticket completes, and at startup it finishes any
ticket still holding one. A ticket accepted more than an hour earlier is not
finished, because acting that late could page someone about something stale.
`verify_recovery.py` runs this with Claude and every outbound client replaced by
stubs, so nothing leaves the machine.

**Result:** Measured 2026-10-06, thirty-five checks, all passing.

| What happens | Result |
|---|---|
| The agent accepts a ticket | its body is kept for recovery, and dropped when the run completes |
| The agent restarts after a crash that left only the note written | the priority is set and the Slack alert posted, without writing the note again |
| The agent restarts with a ticket accepted two hours earlier | not triaged, a note says triage did not finish, and the ticket is sent to the review Slack channel |
| A stored body cannot be read | dropped, not acted on |
| Claude cannot classify a recovered ticket | sent to the review Slack channel and not picked up again, or kept for the next start if that Slack post fails |
| The store fails as a delivery is accepted | refused, so the plugin retries it, and the retry is accepted once the store recovers |
| One ticket in a recovery backlog fails | the others still finish, and the failed one is kept for the next start |
| A repeat delivery for an unfinished ticket names a new requester and IP | resumed on the original requester and IP |
| A repeat delivery arrives for an abandoned ticket, a decided ticket with no stored body, or an undecided one past the retry window | refused as a duplicate |

**What it shows:** A crash or a failing store does not lose a ticket the agent
accepted. A repeat delivery cannot change who a resumed ticket is about, or
revive one already given up on. The stubs mean the real writes are not shown
here. Ticket 32 below shows them.

**Reproduce:** `./venv/bin/python verification/verify_recovery.py` from
`agent/`. Offline.

### A real interrupted ticket, 2026-08-22, ticket 32

A ticket was filed through the osTicket form as a verified user. A script
polling the agent's store killed the agent with `SIGKILL` the moment the
ticket's webhook body was stored, before classification. osTicket had its 202
and queued no retry. On restart, with no delivery of any kind, the agent found
classification still to do and finished the ticket:

```
Ticket 32: interrupted, finishing classified
Ticket 32: classified it_support/high/high_confidence, requester_verified=True
Ticket 32: note written
Ticket 32: priority normal to high
Recovery: 1 ticket(s) finished, 0 too old to finish
```

In osTicket, ticket 32 has priority High and a note posted as `Triage Agent`.
There was no Slack post and no page, which is correct for that row.
`requester_verified` survived the kill and the restart.

## Write-back endpoints

**Method:** osTicket's own API cannot change an existing ticket's priority or
department, so the plugin adds signed endpoints the agent uses to write a note,
set priority and move a ticket to the security department.
`verify_writeback.py` sends each endpoint valid and invalid requests against the
running stack.

**Result:** Measured 2026-10-15 on ticket 40, twenty-eight checks, all passing.

| Request | Result |
|---|---|
| Unsigned, on each endpoint | 401 |
| A wrong signature, a wrong secret, or the webhook's secret, on the note endpoint | 401 |
| A timestamp 10 minutes old, on each endpoint | 401 |
| A ticket that does not exist, on each endpoint | 404 |
| The note text or the priority missing | 400 |
| A priority name osTicket does not have, or a priority ID instead of a name | 400 |
| A valid note, then the same note again | 200, then 200 with `note_exists`, so no second note |
| A department named in the body | ignored, the ticket goes to the configured department |
| A valid move, then the same move again | 200, then 200 with `already_routed` |
| A valid priority | 200, naming the new priority |
| A request signed for one endpoint sent to another, or naming no operation | 400 |

**What it shows:** Only the write secret can change a ticket, and a request
signed for one endpoint cannot be replayed at another. The webhook's secret is
refused, so a leak of it does not grant writes. This is the defense against
[Attack 6](architecture.md#attack-6-credential-compromise). If a reply is lost
and the agent sends the same write again, the endpoint answers that it is
already done instead of writing a second time. This run wrote no new note,
because ticket 40 already carried the agent's. Ticket 42 in
[End-to-end runs](#end-to-end-runs) shows one being written.

**Reproduce:** From `agent/`, with osTicket running and `OSTICKET_WRITE_URL`,
`TRIAGE_WRITE_SECRET` and `TRIAGE_HMAC_SECRET` set in `agent/.env`:

```bash
./venv/bin/python verification/verify_writeback.py <ticket_id>
```

It writes a real note if the ticket has none, moves the ticket to the security
department and sets its priority. The endpoints have no undo, so name a ticket
you do not mind marking. Ticket 99999 must not exist, because the 404 checks
rely on it.

### The priority change is recorded, 2026-09-11, ticket 33

osTicket has no priority event, so the endpoint records a change the way
osTicket records any form field change, in the ticket's history.
`verify_writeback.py` cannot read the database, so this was run by hand. Before
these requests, ticket 33's history held only `created` and `overdue`.

| Request | Result |
|---|---|
| `priority: high` | 200, `from: low`, `to: high` |
| `priority: low` | 200, `from: high`, `to: low` |

Each added a row to `ost_thread_event`, in order:

```
76  edited  2026-09-11 16:26:20  {"fields":{"Priority":"high"}}
77  edited  2026-09-11 16:28:30  {"fields":{"Priority":"low"}}
```

### The department move is recorded, 2026-09-27, ticket 37

osTicket's own transfer needs a staff login, which an API request does not
have, so the endpoint writes the `transferred` event itself. The move of ticket
37 to the security department added this row to `ost_thread_event`:

```
80  transferred  2026-09-27 20:45:30  {"dept":"Security"}
```

## Note links

**Method:** Some of the values the agent copies from Splunk into a note can be
chosen by an attacker, such as a username typed at a sign-in page. osTicket
turns text that matches its link pattern into a live link, so the agent defangs
every copied value. `verify_note.py` builds a note from hostile values and
checks it against a copy of that pattern, from `Format::clickableurls` in
osTicket's `include/class.format.php`. It also checks that the note cuts long
values and caps how many each line shows.

**Result:** Measured 2026-10-06, fourteen checks, all passing.

| Value | In the note |
|---|---|
| `https://evil.example/reset` | `https[:]//evil.example/reset` |
| `www.evil.example` | `www[.]evil.example` |
| `WWW.evil.example` | `WWW[.]evil.example` |
| `ftp://files.example/x` | `ftp[:]//files.example/x` |
| `alice@example.com` | `alice[@]example.com` |
| A 180-character sentence | cut to 100 characters, ending `(cut)` |
| 20 events, each with two account fields | the first 20 of 40, marked `(first 20 of 40)` |
| `bob.smith`, `192.0.2.7` | unchanged |
| The `Search:` line, built from validated values | unchanged, so an analyst can paste it into Splunk |

**What it shows:** The copied pattern catches every raw value except
`WWW.evil.example`, which proves the test can detect a link. It catches nothing
in the built note, so a log value cannot become a link. This is the defense
against [Attack 8](architecture.md#attack-8-log-injection-via-enrichment).
osTicket's pattern is case-sensitive today, and the uppercase value is defanged
in case a later version is not. The test uses a copy of the pattern, so the note
was also checked in osTicket itself.

**Reproduce:** `./venv/bin/python verification/verify_note.py` from `agent/`.
Offline.

### In osTicket itself, 2026-10-06

A note built from the same values, plus HTML values and a `Search:` line, was
run through osTicket's own `Format::htmlchars` and `Format::clickableurls`
inside the container. That is the path osTicket uses to display a plain-text
note.

| In the note | Displayed as |
|---|---|
| The defanged values | text, no links |
| `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`, `<b>benign</b>` | escaped text |
| The `Search:` line | one mailto link, on the requester's email |

That email is the verified requester's own address, so a submitter can only
point the link at themselves.

## Action wiring

**Method:** `ENABLE_WRITES` is the agent's kill switch. With it off, the agent
still classifies, enriches and audits, but changes nothing in osTicket, Slack or
PagerDuty. `verify_wiring.py` drives the agent's real action code against all
three with the switch off and on. Each case runs in its own process, because the
switch is read once at startup.

**Result:** Measured 2026-10-15 on ticket 40, thirty-nine checks, all passing.
Alerts went to the test Slack channel and pages to the test PagerDuty service.

| What happens | Result |
|---|---|
| Every classification the schema accepts is run through the action table | only the two critical security incidents page, and only the low-confidence one gets a WAKE page if its Slack alert fails |
| A high-severity security incident with writes off | the note, priority and Slack alert are skipped, and none is recorded as done |
| The same with writes on | all three are done and recorded |
| The same ticket run again | all three are refused, and the records stay |
| The classification audit write fails | the note ends with `No audit record.` |
| Claude cannot classify the ticket | posted to the review Slack channel, with no note and no priority, and not posted again on a second run |
| A page with writes off, then on, then again | skipped, then paged, then refused, with the fallback page still available |
| The move to the security department with writes off, then on, then again | skipped, then moved, then refused |
| Splunk's audit endpoint is down during a critical | the page goes out before the failed audit write and before enrichment |

**What it shows:** Every action obeys the kill switch, and a second run repeats
none of them, so a retried delivery cannot repeat a note, a priority change, an
alert, a page or a move. A failed classification audit write still shows on the
ticket, and a Splunk outage cannot hold back a page.

**Reproduce:** From `agent/`, with osTicket running:

```bash
./venv/bin/python verification/verify_wiring.py <ticket_id>
```

It writes a note if the ticket has none, sets priority up to emergency, moves
the ticket to the security department, posts Slack alerts, sends PagerDuty pages
and reads PagerDuty's REST API to confirm each page. Alerts and pages go to
`SLACK_WEBHOOK_TEST` and `PAGERDUTY_ROUTING_KEY_TEST` when those are set, and to
the real Slack channels and PagerDuty services when they are not. Its last lines
report what it did to the ticket and where alerts and pages went.

### Against real failures

**Method:** The agent's own action code was called directly, without osTicket,
against two real failures, with a temporary idempotency store. For a
low-confidence critical, the urgent Slack post went to a Slack webhook URL that
Slack does not recognize. In a separate run, classification was given a Claude
API key Anthropic refuses. The fallback page went to the test PagerDuty service
and the other posts to the test Slack channel, and each outcome was read back
from the store and Splunk.

**Result:** Measured 2026-10-09.

| What happens | Result |
|---|---|
| The urgent Slack post fails, for a low-confidence critical | recorded as `bad_request`, the ticket flagged for human review, and the WAKE fallback page sent and recorded |
| The same post through a working Slack webhook | posted, with no fallback page |
| Claude refuses the API key | recorded as `auth_failure`, posted to the review Slack channel, with no note and no priority |

**What it shows:** A real Slack failure on a low-confidence critical wakes
someone through the fallback page and flags the ticket for review. A real Claude
refusal reaches the review Slack channel without writing anything to the ticket.

## Slack alerts

**Method:** The agent posts each alert to a Slack channel through an incoming
webhook, a URL that lets anyone who has it post to that Slack channel.
`verify_slack.py` builds the alert for each case and checks its text, and starts
the client with settings missing. It also makes posts fail with a marker planted
in the webhook URL, to see whether any error repeats it. One real post goes to
the test Slack channel.

**Result:** Measured 2026-10-14, forty-seven checks, all passing.

| What happens | Result |
|---|---|
| A high-confidence critical alert | mentions `@here`, and carries the severity, category, ticket number, enrichment count and a plain link to the ticket |
| A high-severity incident alert | no `@here` |
| An `unclear` ticket on the review Slack channel | names the category and hides the severity guess |
| A low-confidence ticket on the review Slack channel | says "low confidence" |
| Any alert | states its confidence, high or low |
| A critical that paged | names the destination, `paged WAKE` or `paged NOTIFY` |
| A critical whose page failed | says `WAKE PAGE FAILED` or `NOTIFY PAGE FAILED` and tells the reader to escalate manually, never `paged` |
| A row that does not page | says nothing about paging |
| Each enrichment outcome | its own line (no verified identifier, no related events, 20 related events, enrichment unavailable), and none when the row does not enrich |
| Claude cannot classify the ticket | the notice names the failure type, links the ticket, carries only the review icon and never mentions `@here` |
| An alert on each Slack channel, built from a classification carrying a hostname, username and IP extracted from the ticket | none of the three appears |
| What the three alert builders take | nothing the submitter wrote, and no enrichment detail beyond a count |
| Writes off | the post is skipped |
| A webhook missing with writes on | the agent refuses to start and names which one |
| `OSTICKET_BASE_URL` missing, even with writes off | the agent refuses to start and names it |
| A post fails against a malformed and an unreachable webhook URL, each carrying the marker | the error is raised, and its text never contains the marker |
| One real post to the test Slack channel | accepted |

**What it shows:** Each alert says what triage did and how sure it was,
including whether the page went out. Whether it then reached an incident is
checked in [Page reporting](#page-reporting). Nothing the submitter wrote
reaches an alert, including the values Claude extracts from the ticket. HTTP
client errors often quote the URL they called, and the marker in the webhook URL
shows that the error text, which the console and the audit log both record,
never carries the webhook. The real post is a short test message, so it proves
delivery only. The Slack screenshot in [the
README](../README.md#a-triaged-ticket) shows a full alert as Slack displays it,
from ticket 42.

**Reproduce:** `./venv/bin/python verification/verify_slack.py` from `agent/`.
With `SLACK_WEBHOOK_TEST` set, it posts one message to the test Slack channel.
Without it, delivery is skipped, and the verifier ends with "Delivery was
skipped, so nothing was posted." One case takes about 7 seconds.

## PagerDuty pages

**Method:** The agent pages PagerDuty through the Events API with a routing key,
which lets anyone who has it open an incident on that PagerDuty service. The key
travels in the request body, so the risk is a rejection that quotes the field it
refused. `verify_pagerduty.py` builds both pages and checks their content,
starts the client with settings missing, and sends a page with a marker as the
routing key to see whether any error repeats it. Two real pages go to the test
PagerDuty service.

**Result:** Measured 2026-10-15, thirty-two checks, all passing.

| What happens | Result |
|---|---|
| A page for a critical | leads with severity and category, carries the ticket number, names the osTicket host as the source, and sets PagerDuty's severity to critical |
| The page's content | says nothing about enrichment, which has not run yet, carries no extra details, and links to the ticket with the URL itself as the link text |
| The page's dedup key | not the ticket ID, and the same every time for one ticket |
| The fallback page, sent when a low-confidence critical's Slack alert fails | leads with "alert delivery failed", says the confidence was low, and dedups on the same key |
| Both pages, built from a classification carrying a hostname, username and IP extracted from the ticket | none of the three appears anywhere in the event |
| What the two page builders take | the ticket ID, the ticket number and the classification, nothing the submitter wrote |
| Writes off | the page is skipped |
| A routing key missing with writes on | the agent refuses to start and names which one |
| A destination the action table never produces | refused before anything is sent |
| A page sent with the marker as its routing key | rejected, and the error text never contains the marker |
| One real page to each destination, both on the test PagerDuty service | both queued |

**What it shows:** A page says what triage decided, and the fallback page leads
with the delivery failure, so it never reads as a confident critical. Nothing
the submitter wrote reaches a page. The marker shows a rejection never repeats
the routing key, and the agent never records PagerDuty's response body. Queued
means the Events API accepted the event. Whether it opened an incident is
checked in [Page confirmation](#page-confirmation), and who was notified depends
on the PagerDuty service's urgency and each responder's rules, which
[known-limitations.md](known-limitations.md) covers.

**Reproduce:** `./venv/bin/python verification/verify_pagerduty.py` from
`agent/`. With `PAGERDUTY_ROUTING_KEY_TEST` set, it queues two pages on the test
PagerDuty service. Without it, delivery is skipped, and the verifier ends with
"Delivery was skipped, so no page was sent."

## Page confirmation

**Method:** PagerDuty's Events API answers `202` to any page it queues. The
agent then asks PagerDuty's REST API for an open incident on the PagerDuty
service the page went to, holding an alert with the page's dedup key.
`verify_routing_keys.py` replaces the REST API with canned answers and controls
the clock, so the twenty-second wait passes at once and nothing leaves the
machine.

**Result:** Measured 2026-10-11, twelve checks, all passing.

| What the REST API answers | Result |
|---|---|
| An incident appears within twenty seconds, on the first lookup or a later one | confirmed |
| None appears by then, or no PagerDuty service holds the routing key | reached nobody |
| The last lookup fails, the REST API key is refused, or the lookup crashes | not confirmed |
| WAKE and NOTIFY pages for one ticket | each looked up on its own PagerDuty service |
| A page an earlier start sent | a resolved incident counts too |

**What it shows:** The lookup tells a page that reached nobody apart from one
PagerDuty could not answer about, so the Slack post never calls an unknown a
failure.

**Reproduce:** `./venv/bin/python verification/verify_routing_keys.py` from
`agent/`. Offline.

### Dead routing keys

**Method:** Test pages were sent by hand to the Events API, each with a routing
key that reaches no live PagerDuty service. Each was then checked for an
incident through the REST API and in PagerDuty's web app.

**Result:** Measured 2026-10-08 to 2026-10-10.

| Routing key | Events API answer | Incident |
|---|---|---|
| Well formed, held by no PagerDuty service | `202` | none |
| The old routing key after its integration was deleted and re-added | `202` | none |
| On a disabled PagerDuty service | `202` | none |
| On a PagerDuty service in a maintenance window | `202` | none |
| 31 characters long | `400` | none |

**What it shows:** A `202` does not mean delivery. PagerDuty queued pages
through four kinds of dead routing key and opened nothing, which is why each
page is confirmed.

### Confirmation against PagerDuty

**Method:** Two test pages were first sent by hand with PagerDuty's alert
grouping on. Grouping was then turned off, and the agent's own send and
confirmation code ran against the test PagerDuty service, then against a routing
key of 32 zeros.

**Result:** Measured 2026-10-10.

| Page | Result |
|---|---|
| Two test pages, with alert grouping on | the second folded into the first's incident, and still confirmed |
| Test routing key, with grouping off | sent in 0.51 s, confirmed after 3.2 s |
| Test routing key again, a new dedup key, the same minute | confirmed after 1.1 s, on a separate incident |
| 32 zeros | `202` in 0.45 s, reached nobody after 0.5 s |

**What it shows:** Against the real service, confirmation takes a few seconds,
well inside its twenty-second wait, and a routing key no PagerDuty service holds
is caught at once. A page grouped into another ticket's incident is still
confirmed, which is why [architecture.md, Section
10](architecture.md#10-deployment-preconditions) requires grouping off.

## Page reporting

**Method:** The Slack alert for a critical says whether its page reached an
incident. `verify_page_reporting.py` runs a critical through the agent with its
classification already stored, so Claude is not called. Every outbound client,
including the lookup that confirms a page, is replaced by a stub, so nothing
leaves the machine. Two cases run on the agent's real thread pool, to check the
order things happen in.

**Result:** Measured 2026-10-14, thirty-eight checks, all passing.

| What happens | The alert says | Recorded |
|---|---|---|
| PagerDuty refuses the page | `WAKE PAGE FAILED, escalate manually` | a failed page, left to retry |
| PagerDuty accepts it and an incident opens | `paged WAKE` | a confirmed page |
| PagerDuty accepts it and no incident opens | `WAKE PAGE REACHED NOBODY, escalate manually` | a failed page of type `no_incident`, not sent again, and the routing key check runs at once |
| The lookup gets no usable answer, crashes, or takes over a minute | `paged WAKE, not confirmed` | an unconfirmed page |
| A ticket resumes after its page, with its alert still owed | the result of a second lookup, which also counts a resolved incident | nothing new, and the page is not sent again |
| A ticket resumes after its alert, or with writes off | (no alert) | no second lookup |
| PagerDuty accepts the page and the lookup takes a moment to confirm it | `paged WAKE` | the page, timestamped when PagerDuty accepted it, not when the lookup finished |
| The Slack post fails and the WAKE fallback is sent | (no alert) | both pages looked up and recorded |

**What it shows:** A Slack alert says whether its page reached an incident, not
just whether PagerDuty took it, so a page through a dead routing key is reported
as reaching nobody. A restarted ticket checks its earlier page again before
posting, and never pages twice. The alert waits for the lookup alone, and at
most a minute.

**Reproduce:** `./venv/bin/python verification/verify_page_reporting.py` from
`agent/`. Offline.

## Routing key check

**Method:** With writes on, the agent asks PagerDuty's REST API every five
minutes whether each routing key still belongs to a live PagerDuty service, and
records alive, dead or unchecked. `verify_routing_keys.py` replaces the REST API
with canned answers and checks the agent's verdict on each, so nothing leaves
the machine.

**Result:** Measured 2026-10-11, twenty checks, all passing.

| What happens | Result |
|---|---|
| The routing key on an active, warning or critical PagerDuty service | alive |
| The routing key on no PagerDuty service, or on one disabled, in maintenance or in a status the agent does not recognize | dead, with that reason |
| A dropped request, a timeout, a 429 or a 503, then an answer | asked again, up to three times in all |
| A refused REST API key, PagerDuty down or unreachable on every try, or an answer that cannot be read | both routing keys unchecked, with the reason |
| Any reason the check gives | never quotes a routing key |

**What it shows:** A dead routing key is found and recorded with its reason. A
check that cannot run is recorded as unchecked, so revoking the REST API key
cannot hide a dead routing key. A dropped request is tried three times before it
counts as unchecked, and no reason carries a routing key into Splunk or the
alert email.

**Reproduce:** `./venv/bin/python verification/verify_routing_keys.py` from
`agent/`. Offline.

### Against PagerDuty

**Method:** The agent ran with writes on against the real PagerDuty account,
with its routing keys or its REST API key changed as each row says, and each
result was read back from Splunk.

**Result:** Measured 2026-10-09 and 2026-10-10.

| Run | Result |
|---|---|
| Real routing keys | both alive |
| WAKE set to 32 zeros | the wake routing key dead, "reaches no PagerDuty service", and the notify routing key alive |
| Real routing keys, with a REST API key PagerDuty refuses | both unchecked, "answered HTTP 401" |
| Real routing keys, during an unplanned network outage at 19:00 GMT on 2026-10-10 | both unchecked, "could not be reached" |

**What it shows:** The check finds a dead routing key against the real PagerDuty
account and reports a refused REST API key as unchecked. The 19:00 outage led to
the retry, because a short outage had marked both routing keys unchecked and
sent an alert.

## Monitoring

### Heartbeat and the agent-down alert

**Method:** The agent writes a heartbeat to the audit index every 60 seconds.
Every other audit event is written only when a ticket arrives, so without beats
an empty index could not tell a quiet helpdesk from a stopped agent. A saved
search runs every five minutes and emails an alert when the last ten minutes
hold no beat. The agent was started with writes off for twelve minutes, and its
beats were read back from Splunk. It was then stopped, three verifiers that load
its code ran, and the search was checked by hand before and after the stop.

**Result:** Measured 2026-10-08, and the outage email 2026-10-06.

| What happens | Result |
|---|---|
| The agent starts and runs for twelve minutes | 13 beats, the first at once with uptime 0, the uptime rising by 60 each time, each recording that writes were off |
| The alert's search over those twelve minutes | 13 beats, so the alert does not fire |
| The agent stopped, then three verifiers that load its code run | no beats, so running a verifier cannot hide a stopped agent |
| The agent stopped for a day | the alert fires about once an hour |
| The recipient's inbox | subject `Action needed: triage agent stopped reporting` |

**What it shows:** An email goes out within fifteen minutes of the agent
stopping, and it reaches a person. While the agent stays down, the alert repeats
about once an hour.

### Restart loop alert

**Method:** An agent that keeps crashing and being restarted still sends beats,
so the agent-down alert stays quiet. Every start sends a first beat with an
uptime of zero, and a saved search counts those every five minutes, emailing an
alert when it counts three or more starts in the last thirty minutes. The agent
was started and stopped three times with writes off.

**Result:** Measured 2026-09-28.

| What happens | Result |
|---|---|
| Thirty minutes with no restarts | 0 starts, does not fire |
| The agent started and stopped three times | 3 starts, and an email goes out at the next scheduled search |
| The recipient's inbox | subject `Action needed: triage agent is restarting repeatedly`, body `The triage agent has started 3 times in the last thirty minutes.` |

**What it shows:** A crash loop is caught even while the agent keeps sending
beats, and the email says how many times it started.

### Delivery failure alerts

**Method:** When a Slack webhook is revoked, or PagerDuty rejects the routing
key or cannot be reached, every post or page fails, and the agent keeps trying
without tracking it. Two saved searches, one for pages and one for Slack posts,
look back seven days and email an alert when a PagerDuty service or Slack
channel has failed at least twice since its last success. The agent's own
sending code was run against a Slack webhook that does not exist and a routing
key PagerDuty rejects.

**Result:** Measured 2026-10-08.

| What happens | Result |
|---|---|
| Two real failures each to a Slack channel and a PagerDuty service | the agent logs `bad_request` each time, and both alerts fire |
| One real success after them | both alerts clear |
| One more real failure to each after it recovered | stays quiet, on both alerts |
| The paging email | subject `Action needed: triage paging failing to wake`, body `The pages are failing with bad_request. Critical incidents are not paging anyone.` |
| The Slack email | subject `Action needed: triage Slack posts failing to incidents`, body `The Slack posts are failing with bad_request.` |

**What it shows:** When a Slack channel or PagerDuty service keeps rejecting the
agent, Splunk emails an alert that names it and the failure type. A single
failure after an outage has been fixed sends nothing, and the alert stops once a
page or post to it succeeds again. Two pages through a dead routing key fire it
too, and the routing key alert below catches one between pages.

### Routing key alert

**Method:** A saved search runs every five minutes and emails an alert when the
latest routing key check for either routing key is dead or unchecked. It sends
the same alert at most once an hour, and a new one at once when the text
changes. The agent ran against the real PagerDuty account with the wake routing
key set to 32 zeros, then with the real routing keys, then with the wake routing
key dead again. The search and its email were refined after the first runs, and
the last row shows the final email.

**Result:** Measured 2026-10-10.

| What happens | Result |
|---|---|
| The wake routing key dead at 21:51 | an email at the next search, 21:55 |
| The real routing keys back | the 22:00 search found nothing, and the alert cleared |
| The wake routing key dead again at 22:23, inside the first email's hour | a second email at 22:25, with the new start time |
| The same failure at the next search | held back, no email |
| The final email, received 23:15 | subject `Action needed: triage paging may reach nobody through wake`, body `The wake routing key reaches no PagerDuty service. The check has reported this since 2026-10-10 23:12 GMT. If a routing key is dead, PagerDuty accepts the pages that use it and drops them, so critical incidents may page nobody.` |

**What it shows:** A dead routing key brings an email within about ten minutes,
naming the routing key, the reason and since when. The same failure is not
repeated within the hour, but a routing key that fails again after recovering is
emailed at once.
