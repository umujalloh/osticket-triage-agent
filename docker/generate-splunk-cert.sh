#!/usr/bin/env bash
# Generates a unique CA and server certificate for this Splunk instance.
# Splunk ships the same default certificate and private key in every
# installation, so trusting it proves nothing about which server you're
# actually talking to. Output stays gitignored (*.pem). Run this locally
# instead of committing cert material.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="$SCRIPT_DIR/splunk-provisioning/custom_tls/default/certs"
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

openssl genrsa -out ca-key.pem 2048
openssl req -x509 -new -nodes -key ca-key.pem -sha256 -days 3650 \
  -out cacert.pem -subj "/CN=osticket-triage-agent-lab-CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

openssl genrsa -out server-key.pem 2048
openssl req -new -key server-key.pem -out server.csr -subj "/CN=localhost"
openssl x509 -req -in server.csr -CA cacert.pem -CAkey ca-key.pem -CAcreateserial \
  -out server-cert.pem -days 3650 -sha256 \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1")

cat server-cert.pem server-key.pem cacert.pem > server.pem
rm server.csr server-cert.pem server-key.pem

echo "Generated unique Splunk CA and server cert in $CERT_DIR"
