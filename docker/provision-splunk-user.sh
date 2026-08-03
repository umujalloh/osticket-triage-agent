#!/usr/bin/env bash
# Creates the read-only Splunk user the triage agent uses for enrichment
# queries, assigned to the least-privilege 'triage_enrichment' role defined
# in splunk-provisioning/triage_agent_role/default/authorize.conf.
#
# Splunk doesn't support declaring non-admin users with a password in a
# config file, so this has to run against the REST API. Safe to re-run;
# it detects an existing user and skips.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"

if [ ! -f "$ENV_FILE" ]; then
  echo "docker/.env not found. Copy .env.example to .env and fill in real values first." >&2
  exit 1
fi

SPLUNK_PASSWORD=$(grep -m1 '^SPLUNK_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)
SPLUNK_AGENT_PASSWORD=$(grep -m1 '^SPLUNK_AGENT_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)

: "${SPLUNK_PASSWORD:?SPLUNK_PASSWORD must be set in docker/.env}"
: "${SPLUNK_AGENT_PASSWORD:?SPLUNK_AGENT_PASSWORD must be set in docker/.env}"

SPLUNK_REST_HOST="${SPLUNK_REST_HOST:-localhost}"
SPLUNK_REST_PORT="${SPLUNK_REST_PORT:-8089}"

echo "Creating Splunk user 'triage_agent' with role 'triage_enrichment'..."

response=$(curl -sk -w '\n%{http_code}' \
  -u "admin:${SPLUNK_PASSWORD}" \
  "https://${SPLUNK_REST_HOST}:${SPLUNK_REST_PORT}/services/authentication/users" \
  -d name=triage_agent \
  -d password="${SPLUNK_AGENT_PASSWORD}" \
  -d roles=triage_enrichment)

http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | sed '$d')

if [[ "$http_code" == 2* ]]; then
  echo "User 'triage_agent' created."
elif echo "$body" | grep -qi "already exists"; then
  echo "User 'triage_agent' already exists, skipping."
else
  echo "Failed to create user (HTTP $http_code):" >&2
  echo "$body" >&2
  exit 1
fi
