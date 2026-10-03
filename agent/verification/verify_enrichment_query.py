"""Checks that a ticket cannot steer the Splunk enrichment query.

The query searches on two values that arrive with the ticket. The requester's
email is typed by the submitter on an open form, and counts only when osTicket
authenticated the requester as that address. The submitter's IP is observed by
the server, and is validated anyway in case the webhook itself is forged. Each
must pass a strict pattern before it reaches the query string.
architecture.md, Attack 3.

Each refused value below is passed alone, so the query is None only if that
value was refused. Nothing leaves the machine. This builds the query string the
agent would send and inspects it.
"""
import inspect
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# splunk_enrichment refuses to import without its Splunk settings. CI sets
# placeholders, and a local run reads them from agent/.env.
from dotenv import load_dotenv
load_dotenv()

from splunk_enrichment import build_enrichment_query

failed = []
ran = 0

def check(name, got, expected):
    global ran
    ran += 1
    ok = got == expected
    if not ok:
        failed.append(name)
    print(f"{'PASS' if ok else 'FAIL'}  {name}")
    if not ok:
        print(f"        got {got!r}, expected {expected!r}")

EMAIL = "bgist@froth.ly"
IP = "10.0.0.5"

print("accepted values reach the query")
query = build_enrichment_query(EMAIL, IP, requester_verified=True)
check("  a verified email is searched", f'"{EMAIL}"' in (query or ""), True)
check("  a valid IPv4 address is searched", f'"{IP}"' in (query or ""), True)
check("  a valid IPv6 address is searched",
      '"2001:db8::1"' in (build_enrichment_query(submitter_ip="2001:db8::1") or ""),
      True)

print("the email counts only for an authenticated requester")
check("  an unverified email is left out",
      build_enrichment_query(EMAIL, requester_verified=False), None)
check("  the string 'true' is not a verified requester",
      build_enrichment_query(EMAIL, requester_verified="true"), None)
check("  nor is the number 1",
      build_enrichment_query(EMAIL, requester_verified=1), None)

print("a value that could change the query is refused")
for label, email in [
    ("a quote", 'a"b@froth.ly'),
    ("a pipe", "a|b@froth.ly"),
    ("a space", "a b@froth.ly"),
    ("a trailing newline", EMAIL + "\n"),
]:
    check(f"  an email with {label}",
          build_enrichment_query(email, requester_verified=True), None)
for label, ip in [
    ("a quote", IP + '"'),
    ("an IPv6 zone", "fe80::1%eth0"),
    ("an octet out of range", "999.1.1.1"),
]:
    check(f"  an IP with {label}", build_enrichment_query(submitter_ip=ip), None)

print("the query keeps one fixed shape")
check("  nothing safe to search returns no query",
      build_enrichment_query(None, None), None)
check("  it searches one index", query.startswith("search index=botsv3 ("), True)
check("  it caps the result at twenty events", query.endswith("| head 20"), True)
check("  it returns a fixed field list, never raw events",
      "_raw" not in query and "| table " in query, True)
check("  hostname and username cannot be passed in",
      list(inspect.signature(build_enrichment_query).parameters),
      ["submitter_email", "submitter_ip", "requester_verified"])

print()
if failed:
    print(f"FAILED: {', '.join(failed)}")
    sys.exit(1)
print(f"All {ran} checks passed. Nothing was sent.")
