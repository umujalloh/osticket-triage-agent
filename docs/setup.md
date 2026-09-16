# Setup

Running the whole stack yourself, from an empty directory to a triaged ticket.
The system this sets up is described in [the README](../README.md).

## Prerequisites

- Docker and Docker Compose
- Python 3.11 or newer (developed and tested on 3.14)
- An Anthropic API key

## 1. osTicket environment

```bash
cd docker
cp .env.example .env
chmod 600 .env
```

Edit `docker/.env` and set your own database credentials. These exact values
are used again during the osTicket installer, so keep them to hand.

The Dockerfile removes osTicket's `setup/` directory, which is a live
installer page and a liability once osTicket is installed. That directory has
to exist for the first install, so the first build is done with that line
commented out.

Comment out this two-line instruction in [docker/Dockerfile](../docker/Dockerfile),
the one that removes `setup/` and chowns the plugin directory:

```dockerfile
# RUN rm -rf /var/www/html/setup \
#     && chown -R www-data:www-data /var/www/html/include/plugins/triage-webhook
```

Then build the image and create the config file:

```bash
docker compose build osticket
docker compose run --rm --no-deps --entrypoint cat osticket \
  /var/www/html/include/ost-sampleconfig.php > ost-config.php
chmod 0666 ost-config.php
```

[docker/docker-compose.yml](../docker/docker-compose.yml) mounts `ost-config.php`
into the container so the install survives a rebuild. Docker creates that path
as a directory if the file does not exist yet, which leaves the installer with
nowhere to write, so it has to be copied out of the image first.

Start the stack:

```bash
docker compose up -d --build
```

Open `http://localhost:8080` and run the installer. Use `db` as the MySQL
hostname, since that is the service name on the Docker network. The database
name, user, and password must match what you set in `docker/.env`.

Once the installer finishes, uncomment both lines and rebuild:

```bash
docker compose up -d --build
```

`ost-config.php` holds the database credentials and osTicket's secret salt, so
it is not committed. Each install generates its own. Only the installer needs it
writable, so tighten it back down now that the install is finished:

```bash
chmod 0644 ost-config.php
```

## 2. Plugin configuration

The plugin files are copied into the image by the Dockerfile, so osTicket will
already see the plugin. The instance still has to be created by hand.

Generate a shared secret. Python's standard library covers this, no project
setup needed yet:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Save the output, this value goes into `agent/.env` in Section 4 as well.

Log into the staff panel at `http://localhost:8080/scp`, then Manage →
Plugins. Open AI Triage Webhook and set it to Active. Add an instance, give it
a name, set its status to Active, and on the Config tab set:

- FastAPI Webhook URL: `http://host.docker.internal:8000/webhook/ticket`
- HMAC Shared Secret: the value you just generated
- HMAC Write-Back Secret: a second value from the same command, not the same
  one. This authenticates the agent writing into tickets, so a leak of one
  secret does not grant the other.
- Security Department: the osTicket department that owns security questions.
  It must already exist and somebody must have access to it, or routed tickets
  land where nobody can see them. Leave blank to disable routing.
- Retry Window (minutes): how long a ticket the agent never accepted keeps
  being retried before the plugin gives up and notes that on the ticket.
  Defaults to 60 when blank.

The container reaches the agent through `host.docker.internal`, which resolves
via the `extra_hosts` entry in
[docker-compose.yml](../docker/docker-compose.yml). The agent must be listening
on port 8000 on the host.

Finally, give osTicket a real cron schedule. The retry queue drains on cron and
on the next ticket created, and during an outage only cron happens, since an
agent accepting nothing gives nobody a reason to file the ticket that would
trigger the other. On the host:

```bash
crontab -e
```

```
*/5 * * * * docker exec osticket-triage-osticket-1 php /var/www/html/api/cron.php
```

osTicket's autocron setting is not a substitute. It fires from a 1x1 image on
staff pages, so it only runs while an agent is browsing, which is not the hour
a queue most needs draining.

Note that this also starts osTicket's own maintenance cycle, which has been
dormant. If the helpdesk has tickets older than the SLA grace period, the first
run marks them overdue and tries to alert on them. Turn off overdue alerts
under Admin Panel → Settings → Alerts and Notices first if that is not wanted.

Those notices, along with staff alerts and auto-replies, send from the address
in `default_email_id`. Configure SMTP on it unless the deployment has no real
submitters. Unconfigured, they fail silently into the container log, and
nothing in the interface says so.

## 3. Splunk

Splunk runs as part of the same Docker Compose stack and already started in
Section 1. Set `SPLUNK_PASSWORD` in `docker/.env` (8 or more characters,
mixing letters and numbers, Splunk rejects overly simple passwords even at
8 characters).

The agent verifies its TLS connection to Splunk against a certificate
generated for this deployment, not Splunk's shipped default (the same
certificate and private key ship in every default Splunk install, so
trusting it wouldn't prove anything). Run `docker/generate-splunk-cert.sh`
now, before starting Splunk - docker-compose.yml points Splunk at this
certificate from its first boot, so it needs to exist beforehand. The
output is gitignored and not committed. See
[`splunk_logger.py`](../agent/splunk_logger.py).

Enrichment searches the BOTSv3 dataset, which is not committed. Download the
BOTSv3 data set app and unpack it to `docker/splunk-apps/botsv3_data_set`, which
[docker-compose.yml](../docker/docker-compose.yml) mounts into the container as a
Splunk app. Skipping this leaves the rest of the pipeline working; enrichment
simply returns no results.

Then run `docker compose up -d --build`.

Splunk's web UI is at `http://localhost:8010`, mapped from the container's
internal port 8000 since port 8000 is already used by the agent. Log in with
`admin` and the password you set.

Create an index named `osticket_triage`.

Confirm HEC is enabled globally: Settings → Data Inputs → HTTP Event Collector
→ Global Settings, All Tokens should show Enabled. This is usually already on
by default, but worth checking before creating a token.

Create an HEC token with the `osticket_triage` index in its allowed list. The
agent sends events with sourcetype `osticket:triage:audit`. Splunk shows the
token value once, at creation, save it now, this value goes into `agent/.env`
in Section 4.

Give Splunk a way to send mail, or the alert that tells you the agent has died
will fire into an empty room. Under Settings → Server settings → Email
settings, set the mail host, TLS, an account and its password, and the address
to send as. With Gmail that is `smtp.gmail.com:587`, TLS on, and an app
password rather than the account password.

Use the Server settings page rather than the alert-actions page reached from
Settings → Alert actions. The latter saves into whichever app you happened to
be in, and settings written there may not resolve for an alert owned by a
different app.

Then set who receives the alerts. Add `SPLUNK_ALERT_EMAIL` to `docker/.env` and
run `docker/provision-splunk-alerts.sh`. It writes the recipient into the app's
`local/savedsearches.conf`, which this repo does not track, then loads it into
the running Splunk.

The searches, their schedules and their wording all ship in `default/`. Only the
address is deployment-specific, and it lives in `.env` alongside the other
credentials rather than in the Splunk config.

Enrichment queries run as a separate read-only user, not as admin. Set
`SPLUNK_AGENT_PASSWORD` in `docker/.env`, then run
`docker/provision-splunk-user.sh`. It creates a `triage_agent` user in a
least-privilege role scoped to the `botsv3` index, with no admin, write, or
real-time search capability. The script is safe to re-run and skips a user that
already exists. This value goes into `agent/.env` in Section 4 as well.

Splunk must be running when the agent processes a ticket. If it is not, the
audit write fails and the agent prints a "needs human review" line for that
ticket, since a decision with no audit trail can't be trusted to have been
recorded correctly.

## 4. Agent environment

```bash
cd agent
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Create `agent/.env`. [`agent/.env.example`](../agent/.env.example) lists every
variable the agent reads, with the optional ones and their defaults:

```
ANTHROPIC_API_KEY=your-key
TRIAGE_HMAC_SECRET=the-secret-you-generated-in-section-2
SPLUNK_HEC_URL=https://localhost:8088/services/collector/event
SPLUNK_HEC_TOKEN=the-token-you-created-in-section-3
SPLUNK_SEARCH_URL=https://localhost:8089
SPLUNK_AGENT_PASSWORD=the-password-you-set-in-section-3
OSTICKET_WRITE_URL=http://localhost:8080/api/triage
TRIAGE_WRITE_SECRET=the-write-back-secret-you-generated-in-section-2
OSTICKET_BASE_URL=http://localhost:8080
PAGERDUTY_DEDUP_SECRET=a-random-value-you-generate
ENABLE_WRITES=false
```

All eleven are asserted at import time. A missing one refuses to boot rather
than starting in a degraded state.

Generate the dedup secret with `python3 -c "import secrets;
print(secrets.token_hex(32))"`. It keys the PagerDuty deduplication key, so
changing it later changes every one.

Both `.env` files hold credentials in plain text, so `chmod 600` them. The
agent's own state file is already created that way.

`ENABLE_WRITES` has no default and must be exactly `true` or `false`. Both
defaults would be wrong. One writes to real tickets by accident, the other
silently does nothing.

Leave it `false` for a first run. The agent still classifies, enriches and
audits. Notes, priority changes, routing, Slack posts and pages are skipped, and
the console says so at boot. Turning it on requires all three Slack webhooks and
both PagerDuty routing keys, listed in
[`agent/.env.example`](../agent/.env.example), and the agent refuses to boot
without them.

`SPLUNK_ENRICHMENT_EARLIEST` defaults to `-7d`, which is the sensible window
against live telemetry. BOTSv3 is frozen in 2018 and 2019, so a relative window
can never reach it. Set `SPLUNK_ENRICHMENT_EARLIEST=0` to search all time
against the demo dataset.

## 5. Run the agent

```bash
cd agent
source venv/bin/activate
uvicorn main:app --reload --host "$(ip -4 addr show docker0 | awk '/inet /{print $2}' | cut -d/ -f1)" --port 8000
```

Bind to the Docker bridge rather than `0.0.0.0` or `127.0.0.1`. Loopback is
unreachable from the osTicket container, which comes in through the host
gateway, and `0.0.0.0` would also expose the agent on every other interface the
machine has. The bridge is the one address the caller actually uses. On this
setup that is `172.17.0.1`, and the command above reads it rather than assuming
it, since another Docker installation may differ.

Keep `--reload`. Without it uvicorn holds whatever code it started with, and a
stale process produces results that look correct while testing a build that no
longer exists.

Submit a ticket at `http://localhost:8080`. The classification appears in the
agent's output and in Splunk under `index=osticket_triage`.
