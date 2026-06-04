# osTicket AI Triage Agent

An AI triage layer for osTicket helpdesk tickets. Classifies incoming
tickets for security relevance, enriches them with Splunk data, and
routes them to the right place. Real security incidents stop getting
buried in helpdesk noise.

## Status

Architecture and design phase. See [docs/architecture.md](docs/architecture.md).

## Why this exists

Helpdesk queues mix routine IT requests with early signals of real
security incidents. A compromised account or a phishing report can sit
unread behind printer tickets. This agent triages every ticket as it
arrives, flags the security-relevant ones, and enriches them with
context from the SIEM before a human ever looks.

## Architecture

See the full design doc: [docs/architecture.md](docs/architecture.md).
