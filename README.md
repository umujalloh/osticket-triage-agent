# osTicket AI Triage Agent

An AI triage layer for osTicket helpdesk tickets. It classifies incoming tickets for security relevance, enriches the security-relevant ones with Splunk data, and routes them.

## Why this exists

Helpdesk queues mix routine IT requests with early signals of real security incidents. A compromised account or a phishing report can sit unread behind printer tickets. This agent triages every ticket as it arrives, flags the security-relevant ones, and attaches Splunk context before a responder ever opens it.

## Status

Architecture and design phase, written before any code. The design doc covers the data flow, a seven-attack threat model on the agent, least-privilege credential scoping, and a phased build:
[docs/architecture.md](docs/architecture.md)
