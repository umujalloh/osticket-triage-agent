# Action Table

This table is the contract between classification and action. Claude
outputs category, severity, and confidence. The agent looks up the
matching row here and runs exactly that action. Claude never decides
the action itself.

**Override rule, applies before any row below:** any ticket classified
`low` confidence routes to human review, regardless of category or
severity. This prevents a real incident that reads as vague from being
missed or silently mishandled.

## Table

| Category | Severity | Confidence | Action |
|---|---|---|---|
| security_incident | critical | high | Page on-call, post to Slack, write enrichment note, set priority critical |
| security_incident | high | high | Post to Slack, write enrichment note, set priority high, no page |
| security_incident | medium | high | Post to Slack, write enrichment note, set priority medium, no page |
| security_incident | low | high | Write note, set priority low, no alert |
| security_incident | any | low | Route to human review |
| security_question | any | high | Write note, tag/route to security queue, set priority from severity, no alert |
| security_question | any | low | Route to human review |
| it_support | any | high | Write note, set priority from severity, no alert |
| it_support | any | low | Route to human review |
| unclear | any | any | Route to human review |

## Design notes

**Why severity only fully branches for `security_incident`.** Severity's
only job in this system is to decide alert level: page, Slack post, or
silent log. Only security incidents ever justify interrupting a human.
For `security_question` and `it_support`, severity still sets the
osTicket priority field but does not change whether an alert fires.

**Why `security_question` routes differently from `it_support`.**
Category changes who should review the ticket, not just how urgent it
is. A security question needs someone with security context, even at
low urgency. General helpdesk queues don't guarantee that. This requires a
security-tagged queue configured in osTicket before Phase 3 ships.

**Why `unclear` always routes to human.** The category itself is a
signal that classification failed to produce a confident read. No
severity or confidence value overrides that.
