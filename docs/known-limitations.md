# Known Limitations

What this build cannot do, whether a limit the agent cannot fix or one that was
weighed and decided against. How the classifier is scored is in
[evaluation.md](evaluation.md), what the built system was measured doing is in
[verification.md](verification.md), and the
[threat model](architecture.md#4-threat-model), the residual risk each defense
leaves, and the
[deployment preconditions](architecture.md#10-deployment-preconditions) are in
[architecture.md](architecture.md).

## Classifier and evaluation

### The classifier sees only the ticket text

Claude sees only the ticket's subject and message. It has no logs, endpoint
data or history for the user, so an incident that reads like a routine issue
is classified as routine. The rubric in
[Section 5](architecture.md#5-classification-model) sends behavior the user
cannot account for to a person at `low_confidence`. That rule asks whether the
user can explain the cause. A user who describes clearly what happened and
cannot tell whether it mattered can get `high_confidence`. Catching what the
text cannot show is left to endpoint and network monitoring outside this
system.

### Classification is not deterministic

The same ticket can be classified differently on different calls. On the
default model, `claude-haiku-4-5`, the agent sends `temperature=0`, which does
not guarantee identical output. Claude Sonnet 5 and Opus 5 reject sampling
parameters, so on those the agent sends none and they run at the API's default
sampling. The delimiter around each ticket is also random for every request,
so each call sends Claude a different input. A ticket between two severities or
two confidence levels can land on either. A live ticket is classified once, so
a borderline ticket's label is a single draw and nothing flags it. In four
nine-run batches on the current prompt, three tickets changed answer at least
once, as [evaluation.md](evaluation.md#current-results) records. A new ticket
on a boundary can still flip, and one eval run cannot tell a flip from a
regression.

### The evaluation score is a regression check

The eval set is 36 hand-written tickets, none from a real helpdesk, so it does
not reflect a real mix of tickets and the score does not estimate accuracy on
real tickets. The rubric was written and tuned against these same tickets, so a
pass shows that the classifier follows the rubric on the cases it was written
from. The score is meant to catch a change that makes classification worse on
those cases.

## Runtime

### The agent must run as one process

The agent must run as one process. It records each ticket it accepts in a SQLite
file and tracks the tickets it is working on in memory, and sharing those across
hosts would mean adding a database server as a dependency. A second agent
process with its own copy of the file, on another host or in another container,
treats a retried delivery that reaches it as a new ticket, so Claude is called
twice and Slack gets two alerts, which can disagree. A second worker on the same
host shares the file but not the in-memory record, so both can work on a
retried ticket at once.
PagerDuty still opens one incident when both pages reach the same PagerDuty
service and both processes use the same `PAGERDUTY_DEDUP_SECRET`, because the
deduplication key is an HMAC of the ticket ID under that secret. Nothing in the
agent detects a second process.

### A hanging Splunk delays everything after the page

For a new ticket, the page goes out before the first audit write, so a hanging
Splunk cannot delay it. Every action after the page waits instead, because the
agent runs them in order. Each audit write for a ticket gives Splunk three
attempts of 5 seconds, 19 seconds with the waits between them. With Splunk
accepting connections and never answering, the urgent Slack alert went out 116
seconds after the ticket started, as [verification.md](verification.md)
records. That run hung only the audit writes. A critical security incident also
runs an enrichment search, which adds up to 65 seconds more when Splunk's
searches hang too.

Shorter waits would drop records that a busy but working Splunk would have
taken. Sending audit writes from a background queue would keep every record
without holding up the actions, but the note could no longer say whether the
classification reached Splunk. It was decided against because the page, the
alert that matters most in an incident, already goes out ahead of a new
ticket's audit writes.

### A hanging osTicket delays the Slack alert

Once the agent has accepted a ticket, the page goes out before any write to
osTicket, so a hanging osTicket cannot delay it. The Slack alert waits behind
the agent's writes to the ticket, so that whoever follows its link finds the
ticket ready, and with osTicket hanging the Slack alert went out 76 seconds
after the ticket started, as [verification.md](verification.md) records.

## Alerting

### The alerts that watch the agent have one delivery path

A broken mail setup silences all five Splunk alerts, and nothing signals that
they have stopped. On 2026-08-21, six alert emails reported success
in Splunk and reached nobody, because Splunk sent them without authenticating
and the mail server refused them, with nothing logged. A second delivery path
would put a Slack webhook or a PagerDuty routing key in Splunk, one more place
an alerting credential could leak, so the alerts stay on email alone. The
uptime check in precondition 9 of
[Section 10](architecture.md#10-deployment-preconditions) catches Splunk going
down but not mail failing.

### The agent does not learn whether an alert was acted on

The agent records that it posted or paged and never learns whether anyone
worked the ticket. Following up is left to the systems built for it. A
PagerDuty escalation policy can chase an unacknowledged page, and an osTicket
SLA plan can flag a ticket nobody worked as overdue. A Slack alert has no
follow-up of its own, because Slack does not report whether anyone opened its
link, so a ticket announced only in Slack depends on someone working the
osTicket queue.

### A Slack alert can arrive more than once

The agent retries a Slack alert that times out, but a timeout can mean only the
reply was lost, so Slack may already have posted it. One alert can therefore
appear up to three times, and on a high-confidence critical each copy carries
`@here`. The osTicket note and the page avoid this, because the plugin checks
for the agent's note before writing and PagerDuty folds repeats by
deduplication key. Slack's incoming webhooks give no way to ask whether a
message arrived, so there is nothing to check against.

### Slack holds alerts outside the trust zone

A Slack alert stays in Slack after it is posted, for as long as the workspace
keeps messages. The agent cannot delete it, because an incoming webhook can only
post, and anyone who later gains access to the workspace can read it. Alerts
carry no ticket text, requester address, submitter IP or returned log events, as
[Section 8](architecture.md#what-leaves-the-zone) lists.

## This lab

### Enrichment searches a frozen, fictional dataset

Splunk holds BOTSv3, a training dataset built around a fictional company, with
events from 2018-08-20 to 2019-09-19. No real requester appears in it, so
enrichment finds events only for demo tickets filed by a verified requester
whose address is in BOTSv3, such as `bgist@froth.ly`. The search itself is
real, run over TLS as a role that can search one index, so the lab shows the
enrichment path working but not a match against real activity.

BOTSv3 also ships without the add-ons that map fields to the Common Information
Model, so the field list in `splunk_enrichment.py` names the vendor fields this
dataset populates, such as `userPrincipalName` and `ipAddress`, beside
`src_ip`, `dest_ip`, `user` and `action`. Against real log sources the list has
to be re-checked, as Attack 3 in [Section 4](architecture.md#4-threat-model)
notes.

### The submitter IP is the Docker gateway

osTicket records the address it sees on the connection, and browsers reach it
through its Docker network's gateway, `172.22.0.1`. Tickets filed before the
networks were split carry `172.21.0.1`. Neither address is in BOTSv3, so
searching by IP finds nothing, and a guest ticket here runs an enrichment query
that returns zero events. A real deployment records each client's own address,
whether reached directly or through a reverse proxy listed in osTicket's
trusted proxy setting. That setting must list only the proxies themselves,
because a wildcard lets the submitter choose the IP that gets searched, as
Attack 3 in [Section 4](architecture.md#4-threat-model) explains.

### This lab cannot show a page that interrupts

This lab's PagerDuty runs on a developer account, which cannot send SMS or voice
notifications. WAKE, the PagerDuty service meant to interrupt the person on
call, therefore cannot ring a phone here as it would in a real deployment. How
it differs from NOTIFY, the service that wakes no one, rests on each PagerDuty
service's urgency and each responder's notification rules. The agent sends the
same events on a paid account, so nothing in it changes.
