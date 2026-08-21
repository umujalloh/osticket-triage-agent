# Known Limitations

What this build cannot do, in two groups: what the classifier gets wrong and
what the evaluation cannot tell us, then what the lab environment constrains.
Measurements and the method behind them are in [TESTING.md](TESTING.md). Design
rationale, including the threat model and the residual risk left after each
defense, lives in [architecture.md](architecture.md).

## Classifier and evaluation

### Residual non-determinism at temperature 0

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

### Text-only classification

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

### Evaluation set

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

## Environment and enrichment

### Splunk enrichment queries a frozen, fictional dataset

The Splunk instance is loaded with BOTSv3, a static training dataset. Its events
span 2018-08-20 to 2019-09-19 and every entity in it is invented, so no real
ticket will match it. Enrichment returns results only for demo tickets written
to reference known BOTSv3 hosts and accounts.

The pipeline itself is real: validated submitter identifiers, a least-privilege role scoped
to a single index, and read-only searches over TLS against a live Splunk
instance. What is not real is any correspondence between a ticket and the log
data, so this demonstrates the enrichment path rather than live incident
correlation.

### BOTSv3 carries no CIM field extractions

Measured 2026-08-11 across a 20,000 event sample: `src` and `dest` are populated
on 0 events, `user` on 18, and `action` on 2,338, nearly all of them
`osquery:results`. BOTSv3 ships the data without the add-ons that normalize
fields into the Common Information Model, so a generic CIM field list returns
empty columns.

The enrichment allowlist therefore names vendor-specific fields,
`userPrincipalName`, `ipAddress`, `loginStatus`, `signinErrorCode`,
`appDisplayName`, and `email`, alongside the CIM names. Events from sourcetypes
outside that list return only time, host, and sourcetype. The list is shaped to
this dataset and would need revisiting against real log sources.

### Enrichment searches the requester email only for authenticated submitters

The email clause requires osTicket to report an authenticated session for that
address. Guest submissions, staff-created tickets, API tickets, and email-piped
tickets fall back to the IP clause alone. That is the intended security
behavior, and the cost is that enrichment returns less on a helpdesk allowing
guest submission, which is osTicket's default.

### submitter_ip is the container gateway in this lab

osTicket records the address it observes on the connection, and the browser
reaches osTicket through the Docker bridge, so all nine tickets created to date
record `172.21.0.1`. That address appears nowhere in BOTSv3, so the IP clause
matches nothing here. A deployment reached directly, or through a reverse proxy
declared in osTicket's trusted proxy setting, would record real client
addresses.

Together with the limitation above, a guest ticket in this lab produces a query
that returns zero events. The pipeline runs correctly, there is simply nothing
for it to match.

### The idempotency store assumes one agent process

Processed ticket IDs and completed actions live in a SQLite file next to the
agent. That is correct for a single process and wrong for two. Run a second
worker, or a second container, and each has its own store, so the same ticket
can be claimed twice and produce two notes and two pages. Nothing in the agent
detects this.

Fixing it means moving the store to something shared, which is a real
dependency rather than a file, so it is deliberately not done while the agent
runs as one process.

The same assumption is what lets the agent track in-flight tickets in memory
rather than in the store. Two processes would each have their own set, and a
retry reaching the second one would act alongside the first.

### Retries have no jitter and no circuit breaker

Every retry uses the same fixed backoff. If an upstream is down, every ticket
backs off on the same schedule and retries in lockstep, which is the pattern
that turns a recovering service back into an overloaded one. There is also no
breaker: a dead endpoint is retried on every ticket forever, rather than being
marked down.

Neither matters at the ticket volume this is built for. Both would matter at a
volume where the retries themselves become load.

### Secrets live in environment files

Every credential is read from `agent/.env` and the plugin's stored settings.
There is no secrets manager, no rotation, and no expiry. The write-back secret
is the one that matters most, because it grants writing into any ticket, and it
sits in a file on the host in plain text.

That is acceptable for a single-machine lab and is not how a production
deployment should hold it.

## Alerting

### A failed alert can exhaust every delivery path

When a Slack post fails on a critical incident that has not been paged loudly,
the agent pages WAKE as a fallback. Nothing catches the case where both fail. At
that point the agent has no route left, and the only record is an audit event
nobody is watching at the time. No arrangement inside the agent fixes this. It
is the boundary of what the system can promise.

### A Slack post can be delivered more than once

The agent retries a post that times out, and a timeout means the reply was lost
rather than the post failing, so Slack may already have it. On a critical that
lands up to three identical `@here` messages in the urgent channel, which is the
alert fatigue the design is otherwise careful about.

The osTicket note has the same shape and is fixed, because the endpoint it
writes to is this project's own plugin and can check whether the note is already
there. Slack's incoming webhook is not ours and offers no way to ask, so there
is nothing to check against and no deduplication to lean on. PagerDuty avoids it
a third way, with a deduplication key the Events API honours.

Setting a priority twice is harmless, since the second write produces the same
value as the first.

### This lab cannot demonstrate an interrupting page

PagerDuty is on a developer account, which cannot deliver SMS or voice
notifications. There is no setting for it and no way to request it, so the only
route to either is a paid plan.

The design needs WAKE to reach a responder who is not looking. Here the only
method available for that is a mobile push, so WAKE arrives as a push and an
email while NOTIFY arrives as an email alone, and the push is the whole of the
difference. That is enough to show the two destinations behaving differently,
and it is not what a real deployment would use, where a critical page is
normally a phone call.

Nothing in the agent changes on a paid plan. The routing key, the payload and
the service are identical, and what a person receives is decided by their
notification rules and their plan.

### Routing can hide a ticket, and the agent cannot tell

Moving a ticket to the security department is the one action that changes who
can see it. osTicket shows an agent only the departments they have access to, so
a ticket routed into a department nobody is granted disappears from every view.
The agent gets a 200, the audit log records the move, and nothing anywhere
reports a problem.

That is why the target lives in the plugin's configuration rather than in a
request body: a leaked write secret can push tickets into security, which is
noise, but cannot move a critical incident into a department where nobody would
find it. What it does not protect against is the deployment granting access to
nobody in the first place, which is a precondition rather than something code
can check.

### A quiet page can sit unacknowledged

A critical security incident the classifier could not place pages the NOTIFY
service, which raises an incident without interrupting anyone. Someone owns it
and has to acknowledge it, which is more than the channel post alone gave it,
but nothing forces that to happen quickly. PagerDuty escalation policies can be
configured to chase an unacknowledged incident and this deployment does not do
so, because the whole point of the destination is that it does not chase at
three in the morning. The result is that a real incident the classifier was
unsure about can wait as long as the person on call takes to look.

### An unclassified ticket has one delivery path and no fallback

When Claude fails, the agent posts to the review channel because that is all it
can correctly do: there is no classification, so no action table row, no note
content, and no severity. Severity is what qualifies a ticket for the fallback
page, so an unclassified ticket cannot have one. If that single post fails, the
ticket is left untouched in the normal queue and the only record is an audit
event and a console line, neither of which pushes anyone. The window is small,
since it needs Claude and Slack failing together, but nothing inside the agent
closes it.

### The agent does not throttle or batch alerts

A burst of tickets produces a burst of posts. Slack rate-limits, the retries
back off, and the messages land in a channel too busy to read. That is the flood
Attack 5 describes: bury a real incident under noise. The agent cannot solve it,
because throttling only delays the same messages, batching hides the real
incident inside a digest, and duplicate suppression is defeated by varying the
tickets. The defence is CAPTCHA and registration on the ticket form, which is a
deployment precondition rather than code.

### Delivery failures are visible only in Splunk

Every failed post writes an audit event, and nothing acts on those events. The
agent does not count failures or trip a breaker, because a component that
monitors itself is unreliable exactly when it is broken, so noticing a run of
failures is left to a search over the audit index. No such search ships with
this repo, which means a revoked webhook currently fails silently on every
ticket afterwards and the only record is in Splunk for someone who goes
looking.

### Nothing knows whether an alert was acted on

The agent records that it posted or paged. It has no way to learn whether anyone
opened the ticket or worked it. Slack does not report clicks on a plain link
without hosting a redirector, and ticket activity would require polling
osTicket. osTicket's own SLA plans and due dates cover timeliness, and the audit
index can be joined against ticket history after the fact, but the agent raises
nothing when an alert is delivered and then ignored.

### Slack messages are a permanent record outside the trust zone

What crosses to Slack is deliberately small, but it is retained under Slack's
policy rather than yours, reachable by anyone who later gains access to the
workspace, and subject to legal discovery. Notes written into osTicket stay
inside the trust zone. Alerts do not.

### A leaked webhook can post convincing fake alerts

A Slack incoming webhook is a bearer credential: anyone holding one can post to
that channel under the agent's identity, including a message shaped exactly like
a real alert. One webhook per channel bounds the damage to that channel, and
posting the ticket link as a raw URL lets a reader check where it points before
clicking. Neither prevents a plausible fake.
