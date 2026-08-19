# Action Table

This table is the contract between classification and action. Claude
outputs category, severity, and confidence. The agent looks up the
matching row here and runs exactly that action. Claude never decides
the action itself.

**Override rule, applies before any row below:** any ticket classified
`low` confidence routes to human review, regardless of category or
severity. This prevents a real incident that reads as vague from being
missed or silently mishandled.

**Human review is an outcome, not a label.** It means all of the
following: the ticket is posted to the channel its row selects, the
internal note is written so any enrichment is on the ticket when someone
opens it, the priority is set from severity so the queue sorts
correctly, and an audit event records why. On a critical it also pages,
quietly. The override changes how loudly a ticket is escalated and
nothing else about how it is handled.

Confidence gates interruption, not visibility. Gating the channel post
on confidence would mean the less the system understands a ticket, the
quieter it becomes, which is backwards for a security tool. Waking
someone is what needs certainty, which is why a critical the classifier
could not place reaches PagerDuty at low urgency rather than not at all.

## Table

| Category | Severity | Confidence | Channel | Page | Ticket actions |
|---|---|---|---|---|---|
| security_incident | critical | high | urgent, `@here` | WAKE | Write enrichment note, set priority critical |
| security_incident | critical | low | urgent | NOTIFY | Write enrichment note, set priority critical |
| security_incident | high | any | incidents | none | Write note, set priority high |
| security_incident | medium | any | incidents | none | Write note, set priority medium |
| security_incident | low | any | incidents | none | Write note, set priority low |
| security_question | any | high | none | none | Write note, route to security queue, set priority from severity |
| security_question | any | low | review | none | Write note, route to security queue, set priority from severity |
| it_support | any | high | none | none | Write note, set priority from severity |
| it_support | any | low | review | none | Write note, set priority from severity |
| unclear | any | any | review | none | Write note, set priority from severity |

Three channels, and the line between the first two is the same line the
severity rubric already draws.

**urgent** carries critical security incidents only, at either
confidence. Critical means someone unauthorized holds access right now,
or destructive action has already been carried out. That is what
justifies interrupting people, which is why it is the only channel that
mentions at all, and only on the row the classifier was confident about.

**incidents** carries high, medium, and low security incidents. In every
one of those, nobody currently holds access: an attempt that failed, a
compromise the ticket suspects but cannot establish, or something
already contained. They need working, not interrupting over. It is the
only channel carrying more than one severity, so a reader has to sort
within it.

**review** carries `unclear` at any confidence, and the tickets the
classifier did categorise but was not sure about. `unclear` and low
confidence are the same signal on two axes: both say nobody has
established what the ticket is. Keeping them together means the channel
can be owned by a rotation or a dedicated analyst, rather than mixed in
with tickets that only need action.

## Design notes

**Why severity only fully branches for `security_incident`.** Severity's
only job in this system is to decide alert level: which channel a ticket
reaches, whether it mentions, and whether it pages at all. Only security
incidents ever justify interrupting a human.
For `security_question` and `it_support`, severity still sets the
osTicket priority field but does not change whether an alert fires.

**Mention and page reach different people.** A page tasks the one person
on call. A mention tells the rest of the team a critical incident is in
progress.

Every critical security incident pages. Confidence decides which of two
PagerDuty services it reaches, not whether it reaches one. WAKE is a high
urgency service and is meant to interrupt. NOTIFY is a low urgency
service and creates an incident somebody owns without waking them.

Only the confident row also mentions. Once a critical at low confidence
pages NOTIFY, an `@here` would be the loudest signal on the
classification the agent is least sure of, and it would shout at the
whole team about something one person already owns. So the confident
case has two independent delivery paths, which is deliberate for the
highest severity class, and the other has one that nobody has to answer
at three in the morning.

**Why alerting and priority both exist.** They serve different readers.
A channel post is push: it reaches whoever is watching, once, and then
scrolls away. Priority is pull: it orders the queue for whoever sits
down to work tickets later and never saw the post. It also means that if
Slack fails completely, the queue is still ordered correctly, so a
delivery failure degrades to nobody being pushed rather than nothing
indicating urgency.

**Assumptions worth revisiting.** Two, with the trigger for each.

The review channel is assumed to be read. If it fills with low-confidence
routine tickets and stops being read, `unclear` moves up to the incidents
channel, because it is the only thing in review that could be an
unreported breach.

`@here` is assumed to stay rare, which holds only while critical
incidents are rare. If the urgent channel feels noisy, the fix is the
severity rubric rather than the notification rule, because a system
producing frequent criticals has a classification problem.

**Order of actions** is not part of this table. A page runs before
everything, including enrichment, and the channel post runs after the
ticket writes, for reasons in
[architecture.md, Section 7](architecture.md#7-action-layer-and-phasing).

**Why `security_question` routes differently from `it_support`.**
Category changes who should review the ticket, not just how urgent it
is. A security question needs someone with security context, even at
low urgency. General helpdesk queues don't guarantee that. The
security-tagged queue this depends on is one of the deployment
preconditions in
[architecture.md, Section 10](architecture.md#10-deployment-preconditions).

**Enrichment scope.** Splunk enrichment triggers on security_incident +
critical, at either confidence. High, medium, and low severity security
incidents are handled without enrichment. Confidence gates how loudly a
ticket escalates, not the query, because the tickets that read as
uncertain are the ones a reviewer most needs context for. Reasoning in
[architecture.md, Section 7](architecture.md#7-action-layer-and-phasing).
