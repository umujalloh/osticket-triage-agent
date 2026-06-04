# osTicket AI Triage Agent: Architecture

Status: Draft
Author: Umu Jalloh
Last updated: June 2026

## 1. Purpose and problem

_What this system does and the problem it solves._

## 2. Architecture overview

_Components, data flow, and the diagram._

## 3. Phasing plan

_What gets built in Phase 1, 2, and 3. Read before write._

## 4. Threat model

_The attacks this agent must withstand and how each is mitigated._

### 4.1 Prompt injection from ticket bodies
### 4.2 Confused deputy
### 4.3 Data exfiltration via internal notes
### 4.4 False negative on severity
### 4.5 False positive on severity
### 4.6 API key compromise
### 4.7 Replay or duplicate processing

## 5. Trust boundaries

_Where the agent's authority stops. What it can and cannot touch._

## 6. Least privilege spec

_Scoped permissions for each of the three credentials._

## 7. Idempotency and observability

_Duplicate processing protection and audit logging to Splunk._

## 8. Kill switch

_One environment variable disables all writes._
