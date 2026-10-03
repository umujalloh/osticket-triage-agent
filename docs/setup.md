# Setup

These eight stages take the stack from an empty directory to an agent triaging
tickets. The design behind each step is in [architecture.md](architecture.md),
and what the environment must provide is in
[Section 10](architecture.md#10-deployment-preconditions).

## Stage 1: Before you start

**On the host:**

- Docker Engine 28 or later with the Compose plugin, and your user in the
  `docker` group, which is root-equivalent on this host. Earlier versions let
  other machines on the same local network reach ports published on loopback.
  Docker Desktop and rootless Docker have no `docker0` bridge for the agent to
  bind to.
- `git`, `openssl`, `curl`, `iproute2`, and a running cron daemon.
- Python 3.14 with its venv module, `python3.14-venv` on Debian and Ubuntu.
  3.14 is the version CI tests.

**Accounts:**

- An Anthropic API key from the [Claude Console](https://platform.claude.com/),
  with a spend limit set there. The agent calls Claude to classify each ticket.
- A Splunk Enterprise license, or a
  [Developer license](https://dev.splunk.com/enterprise/dev_license/). The
  60-day trial falls back to Splunk Free, which has no alerting and no user
  accounts, and this stack needs both.
- An SMTP account for alert mail, used by both Splunk and osTicket. With Gmail,
  that takes 2-Step Verification and an
  [app password](https://support.google.com/accounts/answer/185833).
- A Slack workspace where you can add an app. Slack's guide covers
  [creating a workspace](https://slack.com/help/articles/206845317-Create-a-Slack-workspace).
- A PagerDuty account. A free
  [developer account](https://docs.pagerduty.com/developer/signup) is enough,
  though it cannot send SMS or voice.

**Get the code:**

```bash
git clone https://github.com/umujalloh/osticket-triage-agent.git
cd osticket-triage-agent
```

## Stage 2: Prepare the host

Do all of this before the stack first starts. The first boot fixes Splunk's
admin password and osTicket's install, and Splunk needs its certificate and
BOTSv3 in place when it starts. From `docker/`.

1. Create the environment file, readable only by you:

   ```bash
   install -m 600 .env.example .env
   ```

2. Give `MYSQL_ROOT_PASSWORD`, `MYSQL_PASSWORD`, `SPLUNK_PASSWORD` and
   `SPLUNK_AGENT_PASSWORD` in `.env` each a separate value, running this once
   for each:

   ```bash
   python3 -c "import secrets; print(secrets.token_urlsafe(24))"
   ```

3. Set `SPLUNK_ALERT_EMAIL` to the address that should hear when the agent
   stops reporting. Leave `MYSQL_DATABASE` and `MYSQL_USER` as they are.

4. Generate the Splunk certificate the agent pins, and give its key to Splunk,
   which reads it as uid 41812 inside its container:

   ```bash
   ./generate-splunk-cert.sh
   sudo chown 41812:41812 splunk-provisioning/custom_tls/default/certs/server.pem
   ```

5. Download the [BOTSv3](https://github.com/splunk/botsv3) dataset that
   enrichment searches, about 320 MB, and give it to Splunk, which writes its
   index inside the app. Without it the pipeline still runs and enrichment
   finds no events.

   ```bash
   curl -LO https://botsdataset.s3.amazonaws.com/botsv3/botsv3_data_set.tgz
   echo "d7ccca99a01cff070dff3c139cdc10eb  botsv3_data_set.tgz" | md5sum -c
   ```

   If it prints `OK`, unpack it:

   ```bash
   mkdir -p splunk-apps
   tar -xzf botsv3_data_set.tgz -C splunk-apps
   rm botsv3_data_set.tgz
   sudo chown -R 41812:41812 splunk-apps/botsv3_data_set
   ```

6. In [Dockerfile](../docker/Dockerfile), comment out both lines of the
   instruction that deletes osTicket's `setup/` directory, which the first
   install needs:

   ```dockerfile
   # RUN rm -rf /var/www/html/setup \
   #     && chown -R www-data:www-data /var/www/html/include/plugins/triage-webhook
   ```

7. Copy osTicket's config file out of the image. Compose mounts it into the
   container, and creates a directory in its place if the file does not exist
   yet. The installer writes to it as www-data (uid 33).

   ```bash
   docker compose build osticket
   docker compose run --rm --no-deps --entrypoint cat osticket \
     /var/www/html/include/ost-sampleconfig.php > ost-config.php
   chmod 660 ost-config.php
   sudo chown 33 ost-config.php
   ```

**Checkpoint:** `md5sum -c` printed `OK`, and
`ls -ln ost-config.php splunk-provisioning/custom_tls/default/certs/server.pem`
shows `ost-config.php` owned by `33` at `-rw-rw----` and `server.pem` owned by
`41812` at `-rw-------`.

## Stage 3: Start the stack and install osTicket

From `docker/`.

1. Start the stack and check its ports:

   ```bash
   docker compose up -d --build
   docker compose ps
   ss -ltn | grep -E ':(8080|8010|8088|8089) '
   ```

   `docker compose ps` lists `db`, `osticket` and `splunk` as running, and
   `splunk` reports healthy within a few minutes. Each line `ss` prints shows
   `127.0.0.1`.

2. Open `http://localhost:8080` and run the installer. The MySQL hostname is
   `db`, and the database name, user and password are the ones in `.env`. The
   installer also creates the admin account you sign in with in Stage 4.

3. Uncomment the two Dockerfile lines from step 6 of
   [Stage 2](#stage-2-prepare-the-host).

4. Rebuild to remove the installer, and make `ost-config.php` readable only by
   osTicket and your group, since it holds the database password and
   osTicket's `SECRET_SALT`.

   ```bash
   docker compose up -d --build
   sudo chmod 640 ost-config.php
   curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8080/setup/
   ```

**Checkpoint:** The `curl` command prints `404`.

## Stage 4: Configure osTicket

Work in the staff panel at `http://localhost:8080/scp`, under Admin Panel.

1. Under Agents → Departments, add the department that owns security
   questions, and give at least one staff member access to it, as their primary
   department or through extended access. A ticket routed into a department
   nobody can access disappears from every view.
2. Generate two secrets, running this twice, and keep both for
   [Stage 6](#stage-6-run-the-agent-with-writes-off):

   ```bash
   python3 -c "import secrets; print(secrets.token_hex(32))"
   ```

3. Under Manage → Plugins → Add New Plugin, install AI Triage Webhook and set
   it to Active. Add an instance with any name, set its status to Enabled, and
   on its Config tab set:
   - FastAPI Webhook URL: `http://host.docker.internal:8000/webhook/ticket`
   - HMAC Shared Secret: the first value, which is also `TRIAGE_HMAC_SECRET`
   - HMAC Write-Back Secret: the second value, which is also
     `TRIAGE_WRITE_SECRET`
   - Retry Window (minutes): 60
   - Security Department: the exact name from step 1. A blank or unmatched name
     makes every routing write fail.
4. Turn on Settings → Tickets → Human Verification. That page also requires
   Maximum Open Tickets, where `0` means no limit. Under Settings → Users, turn
   on Registration Required and set Registration Method to Private, so only
   staff can create accounts. Without these, anyone can flood the form.
5. Set Settings → System → Default Log Level to anything but None.
6. Under Emails → Settings, set Admin's Email Address, and note which address
   is the Default Alert Email. Under Emails → Emails, open that address and
   fill in its Outgoing (SMTP) tab. osTicket's log and alert mail are the only
   warning that osTicket cannot reach the triage agent.
7. To skip alerts on tickets already past their SLA, turn off Overdue Ticket
   Alert under Settings → Tickets → Alerts and Notices. Cron's first run marks
   them overdue.
8. Add the cron job with `crontab -e`. The plugin's retry queue drains on it.

   ```
   */5 * * * * docker exec -u www-data osticket-triage-osticket-1 php /var/www/html/api/cron.php
   ```

**Checkpoint:** Manage → Plugins shows AI Triage Webhook as Enabled, with 1
instance.

## Stage 5: Configure Splunk

From `docker/`. Sign in to Splunk at `http://localhost:8010` as `admin`, with
`SPLUNK_PASSWORD`.

1. Under Settings → Licensing, add your license, and restart Splunk when it
   asks.
2. Under Settings → Indexes → New Index, create `osticket_triage`.
3. Under Settings → Data Inputs → HTTP Event Collector → Global Settings, set
   All Tokens to Enabled.
4. Under Settings → Data Inputs → HTTP Event Collector → New Token, create a
   token with `osticket_triage` as its only allowed index and its default
   index. Keep its value for Stage 6, where it is `SPLUNK_HEC_TOKEN`.
5. Under Settings → Server settings → Email settings, set the mail host, TLS,
   an account and its password, and the sender address. For Gmail that is
   `smtp.gmail.com:587` with TLS and the app password from Stage 1.
6. Load the alerts and create the read-only enrichment user:

   ```bash
   ./provision-splunk-alerts.sh
   ./provision-splunk-user.sh
   ```

7. Test Splunk's mail by running this in Splunk's search bar, with your own
   address in place of `you@example.com`:

   ```
   | makeresults | sendemail to="you@example.com" subject="Splunk mail test"
   ```

**Checkpoint:** The alerts script lists four alerts and ends
`Loaded into Splunk.` The user script prints `User 'triage_agent' created.` The
test message arrives within a minute.

## Stage 6: Run the agent with writes off

From `agent/`.

1. Create the virtual environment and the environment file:

   ```bash
   python3.14 -m venv venv
   ./venv/bin/pip install -r requirements.txt
   install -m 600 .env.example .env
   ```

2. In `.env`, set these values. The agent refuses to start if a required one is
   missing, and the other URLs already point at this stack.
   - `ANTHROPIC_API_KEY`, the key from Stage 1. The agent uses
     `claude-haiku-4-5` unless `TRIAGE_MODEL` names another.
   - `TRIAGE_HMAC_SECRET` and `TRIAGE_WRITE_SECRET`, the two secrets from
     Stage 4
   - `SPLUNK_HEC_TOKEN`, the token from Stage 5
   - `SPLUNK_AGENT_PASSWORD`, the same value as in `docker/.env`
   - `PAGERDUTY_DEDUP_SECRET`, a third value from the same command as Stage 4's
     secrets
   - `SPLUNK_ENRICHMENT_EARLIEST=0`, since BOTSv3 is from 2018 and 2019
   - `ENABLE_WRITES=false`
   - `TRIAGE_WEBHOOK_URL`, with the `docker0` address the agent binds to in
     step 4, usually `http://172.17.0.1:8000/webhook/ticket`.
     `verify_webhook.py` sends here.
3. Run the offline verifiers, the same seven CI runs. Each prints a last line
   starting `All N checks passed`, 143 in total, and anything else is a
   failure.

   ```bash
   for v in verify_action_table verify_idempotency verify_resume verify_recovery \
            verify_page_reporting verify_prompt_isolation verify_note; do
     ./venv/bin/python verification/$v.py | tail -1
   done
   ```

4. Start the agent on the Docker bridge, the one address the osTicket container
   can reach without listening on the machine's network address, as
   [architecture.md, Section 8](architecture.md#network-exposure) explains. The
   `:?` stops the command if `docker0` has no address.

   ```bash
   BRIDGE=$(ip -4 addr show docker0 | awk '/inet /{print $2}' | cut -d/ -f1)
   ./venv/bin/uvicorn main:app --reload --host "${BRIDGE:?docker0 has no IPv4 address}" --port 8000
   ```

   It runs in the foreground, so leave this terminal open and use another for
   the rest.

5. Create a test user, since Registration Required turns guests away. In the
   staff panel's Agent Panel, under Users → User Directory → Add User, add a
   user, then open it, choose Register, and set a temporary password.
6. Submit a ticket as that user at `http://localhost:8080`. Write it as a
   security question, so it pages nothing when writes are turned on.

**Checkpoint:** The console prints `Effectful writes are DISABLED`. In Splunk,
`index=osticket_triage status=heartbeat` returns an event within a minute of
the start, and `index=osticket_triage status=classification_complete` returns
the test ticket, which also proves the Claude key works.

## Stage 7: Connect Slack and PagerDuty

These are needed only for writes. Keep each value for Stage 8.

### Slack

Slack's [incoming webhooks guide](https://api.slack.com/messaging/webhooks)
covers creating the app and its webhooks.

1. Create four Slack channels, one for each row below.
2. Create a Slack app with Incoming Webhooks turned on, and add one webhook for
   each Slack channel. A webhook posts only to its own Slack channel.

   | Variable | Slack channel |
   |---|---|
   | `SLACK_WEBHOOK_URGENT` | Critical security incidents |
   | `SLACK_WEBHOOK_INCIDENTS` | Other security incidents |
   | `SLACK_WEBHOOK_REVIEW` | Tickets that need a person to place them |
   | `SLACK_WEBHOOK_TEST` | Test posts from `verify_slack.py` and `verify_wiring.py` |

3. Have everyone who should see a critical alert turn on notifications for the
   urgent Slack channel. Slack sets them per member, and the agent cannot see
   them.

### PagerDuty

PagerDuty's
[services and integrations guide](https://support.pagerduty.com/main/docs/services-and-integrations)
covers creating a PagerDuty service and its integration key.

1. Create an escalation policy that reaches a real person.
2. Create three PagerDuty services on that policy, each with an Events API v2
   integration and the urgency below. The integration key is the routing key.

   | Variable | PagerDuty service | Urgency |
   |---|---|---|
   | `PAGERDUTY_ROUTING_KEY_WAKE` | Interrupts the person on call | High |
   | `PAGERDUTY_ROUTING_KEY_NOTIFY` | Opens an incident without waking anyone | Low |
   | `PAGERDUTY_ROUTING_KEY_TEST` | Test pages from `verify_pagerduty.py` and `verify_wiring.py` | Any |

   The agent cannot read a PagerDuty service's urgency, so a NOTIFY service at
   high urgency, or set to follow event severity, wakes someone for every
   low-confidence critical.
3. For an account in PagerDuty's EU region, also set
   `PAGERDUTY_EVENTS_URL=https://events.eu.pagerduty.com/v2/enqueue`.

**Checkpoint:** You have four Slack webhook URLs and three PagerDuty routing
keys.

## Stage 8: Turn writes on

On its first start with writes on, the agent finishes every ticket it accepted
in the last hour and did not complete, now with real notes, priorities, posts
and pages, including a page for any critical incident among them. That
includes the test ticket from [Stage 6](#stage-6-run-the-agent-with-writes-off)
if it arrived within the last hour. Older unfinished tickets get a note and a
review post, unless a writes-off start already gave up on them.

From `agent/`.

1. Add the Slack and PagerDuty values to `.env`, including both test values.
   Without them, `verify_wiring.py` posts to the real Slack channels and pages
   the real PagerDuty services.
2. Test the destinations. These post to the test Slack channel and open
   incidents on the test PagerDuty service:

   ```bash
   ./venv/bin/python verification/verify_slack.py
   ./venv/bin/python verification/verify_pagerduty.py
   ```

3. Set `ENABLE_WRITES=true`, then restart the agent. `--reload` watches only
   Python files, so it does not pick up a changed `.env`. Press Ctrl+C in the
   agent's terminal and start it again:

   ```bash
   BRIDGE=$(ip -4 addr show docker0 | awk '/inet /{print $2}' | cut -d/ -f1)
   ./venv/bin/uvicorn main:app --reload --host "${BRIDGE:?docker0 has no IPv4 address}" --port 8000
   ```

4. Run the live verifiers on the test ticket from Stage 6. `<ticket_id>` is the
   `id=` value in its staff URL, not its number. `verify_writeback.py` writes a
   note unless the agent already has, sets the priority and moves the ticket to
   the security department. `verify_wiring.py` does the same, then posts to the
   test Slack channel and pages the test PagerDuty service. `verify_webhook.py`
   checks the webhook's refusals. It waits until osTicket has been installed
   for 65 minutes, the Retry Window plus five. It also needs a ticket the agent
   has finished. One still unfinished would be resumed, with real writes.

   ```bash
   ./venv/bin/python verification/verify_writeback.py <ticket_id>
   ./venv/bin/python verification/verify_wiring.py <ticket_id>
   ./venv/bin/python verification/verify_webhook.py <ticket_id>
   ```

**Checkpoint:** Each verifier ends `All N checks passed`. The test Slack
channel shows the verifier posts, and the test PagerDuty service shows the
pages.

## Operating the stack

### Restarting and starting over

From `docker/`:

- **`docker compose down`, then `up -d`:** Keeps everything. The volumes
  `db_data`, `splunk_data` and `splunk_etc` survive, and so do `ost-config.php`,
  both `.env` files, the certificate, BOTSv3 and the agent's store.
- **`docker compose down -v`:** Deletes the volumes, which hold every ticket,
  every osTicket setting, the audit index, the HEC token and the Splunk users.

A fresh osTicket then reuses ticket IDs the agent's store has already claimed,
so starting over after `down -v` takes these steps:

1. Stop the agent and delete its store, `agent/triage_state.db` with its `-wal`
   and `-shm` files.
2. Delete `ost-config.php` with `rm -f`.
3. Repeat steps 6 and 7 of [Stage 2](#stage-2-prepare-the-host), then
   Stages 3 to 5, skipping the crontab step in Stage 4.
4. In `agent/.env`, update both plugin secrets and `SPLUNK_HEC_TOKEN`.
5. Start the agent with the command below.

After changing `agent/.env`, restart the agent. Press Ctrl+C in its terminal
and, from `agent/`, run:

```bash
BRIDGE=$(ip -4 addr show docker0 | awk '/inet /{print $2}' | cut -d/ -f1)
./venv/bin/uvicorn main:app --reload --host "${BRIDGE:?docker0 has no IPv4 address}" --port 8000
```

On every start it finishes unfinished tickets as
[Stage 8](#stage-8-turn-writes-on) describes.

### Changing an alert

Edit `splunk-provisioning/triage_alerts/default/` and re-run
`provision-splunk-alerts.sh` from `docker/`. Splunk mounts the app read-only,
so it cannot save edits made in its UI.

### Rotating secrets

Change each secret where it is used, then restart whatever reads it.

| Secret | Where it lives | Order and effect |
|---|---|---|
| `TRIAGE_HMAC_SECRET` | osTicket plugin, `agent/.env` | Change the osTicket plugin's setting, then `agent/.env`, then restart the agent. The agent refuses tickets in between, and the plugin queues them for cron to retry. Keep the gap inside the Retry Window. |
| `TRIAGE_WRITE_SECRET` | osTicket plugin, `agent/.env` | Same order. In between, the agent cannot confirm ticket numbers with osTicket and answers 503, so tickets queue the same way. |
| `PAGERDUTY_DEDUP_SECRET` | `agent/.env` | Change it only with no PagerDuty incident open. It keys every deduplication key, so a retry for an open incident would open a second one. |
| Slack webhooks, PagerDuty keys | `agent/.env` | Create the new one, restart the agent, then revoke the old one. |
| `ANTHROPIC_API_KEY` | `agent/.env` | Create the new key, restart the agent, then revoke the old one. |
| `SPLUNK_HEC_TOKEN` | Splunk, `agent/.env` | Create a new token like the first, restart the agent, then delete the old one. |
| `SPLUNK_AGENT_PASSWORD` | Splunk, both `.env` files | Change `triage_agent`'s password under Settings → Users, then both files, then restart the agent. `provision-splunk-user.sh` skips an existing user, so it cannot change it. |
| `SPLUNK_PASSWORD` | Splunk, `docker/.env` | Change it under Settings → Users, then the file, then run `docker compose up -d splunk` so the container's environment matches the live password. The provisioning scripts read it every run. |
| MySQL passwords | MySQL, `docker/.env`, `ost-config.php` | Change them in MySQL with `ALTER USER`, from `docker compose exec db mysql -uroot -p` with the password entered at the prompt, then in `.env`, and for `MYSQL_PASSWORD` also `DBPASS` in `ost-config.php`, with `sudo` since osTicket owns it. MySQL reads `.env` only when its volume is first created. |
| Splunk TLS certificate | `splunk-provisioning/custom_tls/default/certs/`, and the CA key in `ca/` | `server.pem` belongs to uid 41812, so delete it with `rm -f` before re-running the script, give the new one to 41812, then restart Splunk. |
| `SECRET_SALT` | `ost-config.php` | Do not rotate it in place. osTicket encrypts the plugin's two secrets with it. |

## What this lab does not set up

[Section 10](architecture.md#10-deployment-preconditions) lists what a
deployment must provide. This lab skips three:

- **Item 8, an uptime check on Splunk from outside it:** All four alerts run
  inside Splunk, so a Splunk outage silences them.
- **Item 9, an outbound allowlist for the agent:** Nothing stops the agent
  connecting anywhere, so stolen credentials can leave the host through it.
- **Item 10, keeping the agent's console output:** Here the agent runs in a
  terminal, and its console output, the only record of some failures, is lost
  when the terminal closes.
