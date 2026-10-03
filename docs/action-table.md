# Action Table

This table is the contract between classification and action. Claude classifies
each ticket by category, severity and confidence. The agent looks up the
matching row in `agent/action_table.py` and takes the actions it names. Claude
never chooses an action, so a manipulated classification can only reach a row
that already exists. Section 5 of
[architecture.md](architecture.md#5-classification-model) defines the three
dimensions,
[Section 6](architecture.md#6-failure-modes-for-the-claude-dependency) covers
what happens when Claude cannot classify a ticket, and
[Section 7](architecture.md#7-action-layer) covers how the agent carries these
actions out.

The columns run in the order the agent acts, and every row writes an internal
note on the ticket and sets its priority.

| Category | Severity | Confidence | Page | Enrich | Route | Channel | Mention |
|---|---|---|---|---|---|---|---|
| security_incident | critical | high | WAKE | yes | no | urgent | yes |
| security_incident | critical | low | NOTIFY | yes | no | urgent | no |
| security_incident | high | any | none | no | no | incidents | no |
| security_incident | medium | any | none | no | no | incidents | no |
| security_incident | low | any | none | no | no | incidents | no |
| security_question | any | high | none | no | yes | none | no |
| security_question | any | low | none | no | yes | review | no |
| it_support | any | high | none | no | no | none | no |
| it_support | any | low | none | no | no | review | no |
| unclear | any | low | none | no | no | review | no |

The agent checks everything Claude returns against a strict schema in
`agent/schemas.py` before acting on it. That schema refuses `critical` on
anything but a security incident, and `unclear` at high confidence, so neither
reaches this table.

## How a row is decided

**Category** decides where the ticket goes. A security incident reaches a Slack
channel. A security question moves to the security department. An `it_support`
ticket stays in the osTicket department it was filed in and reaches no channel,
unless the classifier marked it low confidence.

**Severity** decides how loudly a ticket escalates. Critical means someone
unauthorized holds access right now, or destructive action has already been
carried out, which is what justifies interrupting a person, so those rows page
and reach the urgent channel. A security incident below critical means nobody
holds access and nothing has been destroyed, so those rows reach the incidents
channel and interrupt nobody. For a security question or an `it_support` ticket,
severity still sets the ticket priority but changes no alert.

**Confidence** decides how much interruption a ticket earns. Waking the on-call
and mentioning the channel are the only actions that need a confident label. On
a critical, high confidence pages WAKE and mentions `@here`, and low confidence
pages NOTIFY with no mention. The rubric puts behavior the user cannot explain
at low confidence, which is how many compromises first appear, so every
low-confidence ticket still reaches a channel and is flagged for human review in
the audit log.

## Channels

**urgent** carries only critical security incidents, at either confidence. It is
the only channel holding tickets the agent paged on, and the only one that gets
an `@here`, the Slack mention that notifies whoever is active in the channel at
that moment.

**incidents** carries high, medium and low security incidents. They wait for an
analyst working the queue instead of interrupting someone.

**review** carries every `unclear` ticket and every low-confidence ticket that
is not a security incident. In both, nothing in the ticket settles what it is,
because it is vague, could fit more than one category, or describes something
the user cannot account for. Tickets Claude never classified, and tickets
abandoned past the recovery window, also post there, which Section 6 covers.
They are sent to one channel so a person can triage them. That channel needs an
analyst actively working it, because an unread review channel is where an
unreported breach sits unseen.

## Pages

PagerDuty sets urgency per service, so the agent uses two.

**WAKE** must be the high urgency service, the one that interrupts whoever is on
call. Only critical security incidents at high confidence reach it, and those at
low confidence whose Slack post failed.

**NOTIFY** must be the low urgency service, which notifies the on-call without
waking them and leaves a PagerDuty incident they have to acknowledge. Only
critical security incidents at low confidence reach it.

## Enrichment

Only critical security incidents are enriched, at either confidence. A critical
needs someone acting now, and the search saves the responder the time it would
take to pull the same context out of Splunk by hand. Confidence does not gate
it, because the tickets at low confidence are where a reviewer most needs
context. Lower severities do not get it because nobody is acting immediately,
and because enrichment is the one path that brings Splunk data back onto a
ticket, which
[Attack 3](architecture.md#attack-3-indirect-data-exfiltration-via-internal-notes)
and [Attack 8](architecture.md#attack-8-log-injection-via-enrichment) cover. An
eligible ticket still runs no search when nothing can safely be queried, which
Section 7 covers.

## Priority

Priority comes from severity, using osTicket's own names. Critical sets
`emergency`, high sets `high`, medium sets `normal`, and low sets `low`.
Priority keeps urgency on the ticket for whoever works the queue after the Slack
channel post has scrolled away or failed to send.

## Route

Only a security question routes, at either confidence. It moves to the security
department named in the plugin's configuration, because a security question
needs someone with security context and a general helpdesk queue does not
guarantee that. Security incidents are not routed, because routing is the one
action that can hide a ticket, since osTicket shows a staff member only the
departments they can access. They reach the security team through their Slack
channel, and a critical also pages, while helpdesk staff in their original
department can still see them.
