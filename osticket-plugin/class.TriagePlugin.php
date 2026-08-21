<?php
require_once(INCLUDE_DIR . 'class.signal.php');
require_once(INCLUDE_DIR . 'class.plugin.php');
require_once(INCLUDE_DIR . 'class.ticket.php');
require_once(INCLUDE_DIR . 'class.osticket.php');
require_once(INCLUDE_DIR . 'class.config.php');
require_once(INCLUDE_DIR . 'class.format.php');
require_once(INCLUDE_DIR . 'class.user.php');
require_once('config.php');

class TriagePlugin extends Plugin {

    var $config_class = "TriagePluginConfig";
    static $pluginInstance = null;

    private function getPluginInstance(?int $id) {
        if ($id && ($i = $this->getInstance($id)))
            return $i;
        return $this->getInstances()->first();
    }

    /**
     * Who the plugin's own note is posted as. Must differ from the write
     * endpoint's poster, which decides a note is a repeat by looking for its
     * own name: share it and the agent's triage note bounces as already
     * present and is recorded as written.
     */
    const STATUS_POSTER = 'Triage Plugin';

    /** Minutes of retrying before the plugin gives up, if none is configured. */
    const DEFAULT_RETRY_WINDOW = 60;

    /** A failure retrying cannot fix, so it gives up at once rather than waiting. */
    const UNREADABLE = 'The plugin could not read the ticket, so nothing was ever sent to the triage agent.';

    /** Sent per ticket.created, where a submitter is waiting, and per cron,
     *  where nobody is. architecture.md, Section 7. */
    const DRAIN_ON_CREATE = 1;
    const DRAIN_ON_CRON = 25;

    private static function queueTable() {
        return TABLE_PREFIX . 'triage_retry_queue';
    }

    /**
     * Entrypoint, runs once when osTicket loads the plugin.
     * Connects our listeners and makes sure the retry queue exists.
     */
    function bootstrap() {
        self::$pluginInstance = self::getPluginInstance(null);
        $this->ensureQueueTable();
        Signal::connect('ticket.created', array($this, 'onTicketCreated'));
        Signal::connect('api', array($this, 'onApiSignal'));
        // Fired by api/cron.php and by the autocron image on staff pages. It is
        // what drains the queue when no new ticket is arriving, which is the
        // case an outage produces: the agent is down, so nothing is being
        // accepted, so nothing else would ever run.
        Signal::connect('cron', array($this, 'onCron'));
    }

    /**
     * Creates the retry queue if it is not there. osTicket gives a plugin no
     * schema hook, so this runs on bootstrap.
     *
     * Keyed on ticket_id so a second failure updates the row rather than adding
     * one, which keeps first_failed_at meaning the first failure.
     */
    private function ensureQueueTable() {
        $table = self::queueTable();
        db_query(
            "CREATE TABLE IF NOT EXISTS $table ("
            . "ticket_id INT UNSIGNED NOT NULL PRIMARY KEY,"
            // Stored, never recomputed. It reads the submitter's live session,
            // which no retry has. architecture.md, Section 7.
            . "requester_verified TINYINT NOT NULL DEFAULT 0,"
            . "attempts INT UNSIGNED NOT NULL DEFAULT 1,"
            . "first_failed_at DATETIME NOT NULL,"
            . "last_attempt_at DATETIME NOT NULL,"
            . "INDEX first_failed_at (first_failed_at)"
            . ") DEFAULT CHARSET=utf8",
            false
        );
    }

    /**
     * osTicket hands plugins the API dispatcher before it resolves the URL,
     * which is the supported way to add an endpoint. Registered as a closure
     * rather than a class name so the controller receives this plugin and its
     * instance, and so the dispatcher's own no-argument instantiation and
     * access() convention do not apply.
     */
    function onApiSignal($dispatcher) {
        $plugin = $this;
        $instance = self::$pluginInstance;
        $dispatcher->append(
            url_post('^/triage/note$', function () use ($plugin, $instance) {
                require_once(__DIR__ . '/class.TriageWriteController.php');
                $controller = new TriageWriteController($plugin, $instance);
                return $controller->postNote();
            })
        );
        $dispatcher->append(
            url_post('^/triage/priority$', function () use ($plugin, $instance) {
                require_once(__DIR__ . '/class.TriageWriteController.php');
                $controller = new TriageWriteController($plugin, $instance);
                return $controller->postPriority();
            })
        );
        $dispatcher->append(
            url_post('^/triage/department$', function () use ($plugin, $instance) {
                require_once(__DIR__ . '/class.TriageWriteController.php');
                $controller = new TriageWriteController($plugin, $instance);
                return $controller->postDepartment();
            })
        );
    }

    /**
     * Runs automatically when osTicket fires ticket.created.
     * Pulls the ticket data we need and sends it to the agent.
     */
    function onTicketCreated(Ticket $ticket) {
        global $cfg;

        if (!$cfg instanceof OsticketConfig) {
            error_log("Triage plugin called too early.");
            return;
        }

        $verified = $this->requesterIsVerified($ticket);
        $payload = $this->buildPayload($ticket, $verified);

        if ($payload === null) {
            // Nothing to send, and a retry would rebuild the same nothing, so
            // this gives up now instead of after an hour of attempts that
            // cannot change the outcome.
            $delivered = false;
            $this->setStatusNote($ticket->getId(), $this->gaveUpNote(self::UNREADABLE));
        } else {
            $delivered = $this->sendToAgent($payload);
            if (!$delivered) {
                $this->enqueue($ticket->getId(), $verified);
                // On the first failure, not after a delay. An undelivered
                // ticket has to be readable as a possible critical incident,
                // because classifying it is what just failed. architecture.md,
                // Section 7.
                $this->setStatusNote($ticket->getId(),
                                     $this->pendingNote($this->retryWindowMinutes()));
            }
        }

        // Unconditional. Expiry needs no agent, so it must not be gated on
        // reaching one.
        $this->expireQueued();

        // Gated, because a failed send means the agent is down and the backlog
        // would just prove it again on the submitter's page load.
        if ($delivered)
            $this->drainQueue(self::DRAIN_ON_CREATE);
    }

    /**
     * Runs when osTicket fires cron, from api/cron.php or the autocron image.
     * The trigger that matters during an outage, since nothing is being
     * accepted and so no new ticket arrives to flush the queue.
     */
    function onCron($object = null, $data = null) {
        global $cfg;

        if (!$cfg instanceof OsticketConfig)
            return;

        $this->expireQueued();
        $this->drainQueue(self::DRAIN_ON_CRON);
    }

    /**
     * The webhook body for one ticket, or null if it cannot be built.
     *
     * One place rather than two, so a retry cannot drift from a first send and
     * deliver a differently shaped payload.
     */
    private function buildPayload(Ticket $ticket, $verified) {
        try {
            $message = $ticket->getMessages()[0];
            if (!$message)
                return null;
            $plaintext = Format::html2text($message->getBody()->getClean());
        } catch (\Throwable $e) {
            error_log('Triage plugin could not read ticket ' . $ticket->getId()
                      . ': ' . $e->getMessage());
            return null;
        }

        return array(
            'ticket_id'          => $ticket->getId(),
            'ticket_number'      => $ticket->getNumber(),
            'subject'            => $ticket->getSubject(),
            'message'            => $plaintext,
            'requester'          => (string) $ticket->getEmail(),
            'requester_verified' => (bool) $verified,
            'submitter_ip'       => $ticket->getIP(),
            // Fresh on every attempt, never carried from the first. This is
            // what keeps a retry distinguishable from a replay, since the
            // agent refuses anything older than five minutes.
            'created_at'         => date('c'),
        );
    }

    /** Minutes of retrying before the plugin gives up on a ticket. */
    private function retryWindowMinutes() {
        $config = $this->getConfig(self::$pluginInstance);
        $minutes = $config ? (int) $config->get('triage-retry-window') : 0;
        return $minutes > 0 ? $minutes : self::DEFAULT_RETRY_WINDOW;
    }

    /**
     * Records a ticket the agent did not accept, so something can try again.
     *
     * requester_verified is stored rather than recomputed later. It reads the
     * submitter's live session, which no retry has, so rebuilding it would
     * always produce false and narrow what the agent may search on without
     * anything reporting that it had.
     */
    private function enqueue($ticket_id, $verified) {
        $table = self::queueTable();
        $id = (int) $ticket_id;
        $flag = $verified ? 1 : 0;

        // first_failed_at is left alone on a repeat, since the retry window is
        // measured from the first failure and not from the latest one.
        db_query(
            "INSERT INTO $table "
            . "(ticket_id, requester_verified, attempts, first_failed_at, last_attempt_at) "
            . "VALUES ($id, $flag, 1, NOW(), NOW()) "
            . "ON DUPLICATE KEY UPDATE attempts = attempts + 1, last_attempt_at = NOW()",
            false
        );
        error_log("Triage plugin queued ticket $id for retry");
    }

    /**
     * Gives up on anything past the retry window and says so on the ticket.
     *
     * Local work, so keep it that way. Nothing here talks to the agent, which
     * is what lets it run during the outage that filled the queue, and that is
     * the only time it matters.
     */
    private function expireQueued() {
        $table = self::queueTable();
        $minutes = $this->retryWindowMinutes();

        try {
            $res = db_query(
                "SELECT ticket_id, attempts FROM $table "
                . "WHERE first_failed_at < DATE_SUB(NOW(), INTERVAL $minutes MINUTE)",
                false
            );
            if (!$res)
                return;

            $expired = array();
            while ($row = db_fetch_array($res))
                $expired[] = $row;

            foreach ($expired as $row) {
                $id = (int) $row['ticket_id'];
                $attempts = (int) $row['attempts'];
                $tries = $attempts == 1 ? "1 attempt" : "$attempts attempts";
                $this->setStatusNote($id, $this->gaveUpNote(
                    "The triage agent did not accept it after $tries over "
                    . "$minutes minutes."));
                db_query("DELETE FROM $table WHERE ticket_id = $id", false);
                error_log("Triage plugin gave up on ticket $id after $attempts attempt(s)");
            }
        } catch (\Throwable $e) {
            error_log('Triage plugin could not expire its retry queue: ' . $e->getMessage());
        }
    }

    /**
     * Puts the plugin's status note on a ticket, or rewrites the one already
     * there. One note per ticket, never a second one disagreeing with it.
     * Reasoning in architecture.md, Section 7.
     *
     * alert stays true so osTicket's own note settings decide whether anyone is
     * pushed. Do not set it false to quieten this: it reaches nobody by default
     * already, and hardcoding it takes the choice off the deployment.
     */
    private function setStatusNote($ticket_id, $body) {
        if (!($ticket = Ticket::lookup($ticket_id))) {
            error_log("Triage plugin has no ticket $ticket_id to write a status note on");
            return;
        }

        $text = new TextThreadEntryBody($body);

        if ($entry = $this->statusNote($ticket)) {
            $entry->setBody($text);
            return;
        }

        $errors = array();
        $entry = $ticket->postNote(
            array('title' => 'Automated triage', 'note' => $text),
            $errors,
            self::STATUS_POSTER,
            true
        );
        if (!$entry)
            error_log("Triage plugin could not write its status note on ticket $ticket_id");
    }

    /**
     * The plugin's own note on a ticket, matched on its poster, or null.
     *
     * Queried directly rather than walked through Thread::getEntries(). That
     * set is cached on the thread, and getMessages() clones it shallowly, so
     * its type filter leaks back and narrows the cache to messages for the rest
     * of the request. buildPayload calls getMessages() just before this runs,
     * which made the note invisible and produced a second one.
     */
    private function statusNote($ticket) {
        if (!($thread = $ticket->getThread()))
            return null;

        $res = db_query(
            "SELECT id FROM " . TABLE_PREFIX . "thread_entry "
            . "WHERE thread_id = " . (int) $thread->getId() . " AND type = 'N' "
            . "AND poster = " . db_input(self::STATUS_POSTER) . " ORDER BY id LIMIT 1",
            false
        );
        if (!$res || !($row = db_fetch_array($res)))
            return null;

        return ThreadEntry::lookup((int) $row['id']);
    }

    /** The note a ticket carries while the agent has not accepted it yet. */
    private function pendingNote($minutes) {
        $until = date('H:i', time() + ($minutes * 60));
        return "Automated triage has not run on this ticket.\n\n"
             . "The triage agent could not be reached, so the ticket has no triage "
             . "classification, its priority is not one triage set, and no alert was "
             . "raised for it. Treat the priority as unknown rather than low.\n\n"
             . "Delivery is being retried until about $until. This note is updated "
             . "when that resolves either way.";
    }

    /** The note a ticket carries once the agent finally took it. */
    private function deliveredNote($minutes) {
        $at = date('H:i');
        // TIMESTAMPDIFF gives whole minutes, so anything under one reads as
        // zero. A recovery that fast should not be reported as a delay of no
        // minutes.
        $delay = $minutes < 1
            ? "less than a minute later"
            : ($minutes == 1 ? "a minute later" : "$minutes minutes later");

        return "Automated triage was delayed on this ticket.\n\n"
             . "The triage agent could not be reached when the ticket was filed. It "
             . "accepted the ticket $delay, at $at. Any triage note and priority "
             . "follow this one.\n\n"
             . "Delivery is what was delayed. Whether triage then succeeded is "
             . "recorded separately, by the agent.";
    }

    /** The note a ticket carries once the plugin has stopped trying. */
    private function gaveUpNote($reason) {
        return "Automated triage never ran on this ticket.\n\n"
             . $reason . "\n\n"
             . "The ticket has no triage classification, no priority set from one, "
             . "and no alert was raised for it. Work it as an ordinary ticket.";
    }

    /**
     * Sends up to $limit queued tickets, oldest failure first.
     *
     * Stops at the first one that fails rather than working through the rest.
     * They queued because the agent was unreachable and they will all discover
     * that the same way, one full timeout at a time.
     */
    private function drainQueue($limit) {
        $table = self::queueTable();
        $limit = (int) $limit;

        try {
            $res = db_query(
                "SELECT ticket_id, requester_verified, "
                . "TIMESTAMPDIFF(MINUTE, first_failed_at, NOW()) AS waited "
                . "FROM $table ORDER BY first_failed_at ASC LIMIT $limit",
                false
            );
            if (!$res)
                return;

            // Read out before sending. Each send runs its own queries, and
            // holding an open result set across them is not something to rely
            // on.
            $queued = array();
            while ($row = db_fetch_array($res))
                $queued[] = $row;

            foreach ($queued as $row) {
                $id = (int) $row['ticket_id'];

                if (!($ticket = Ticket::lookup($id))) {
                    db_query("DELETE FROM $table WHERE ticket_id = $id", false);
                    error_log("Triage plugin dropped queued ticket $id, which no longer exists");
                    continue;
                }

                $payload = $this->buildPayload($ticket, (bool) $row['requester_verified']);
                if ($payload === null) {
                    // Permanent, so it leaves the queue with the same note it
                    // would have got had it failed this way on submission.
                    $this->setStatusNote($id, $this->gaveUpNote(self::UNREADABLE));
                    db_query("DELETE FROM $table WHERE ticket_id = $id", false);
                    continue;
                }

                if ($this->sendToAgent($payload)) {
                    db_query("DELETE FROM $table WHERE ticket_id = $id", false);
                    // Rewrites the pending note rather than adding a second
                    // one. It reports the delay only, and says nothing about
                    // triage having succeeded, because a 202 means the agent
                    // took the ticket and not that it finished with it.
                    $this->setStatusNote($id, $this->deliveredNote((int) $row['waited']));
                    error_log("Triage plugin delivered queued ticket $id");
                    continue;
                }

                db_query(
                    "UPDATE $table SET attempts = attempts + 1, last_attempt_at = NOW() "
                    . "WHERE ticket_id = $id",
                    false
                );
                return;
            }
        } catch (\Throwable $e) {
            error_log('Triage plugin could not drain its retry queue: ' . $e->getMessage());
        }
    }

    /**
     * True only when the ticket was filed from an authenticated client session
     * whose user is the ticket owner, and that account is confirmed.
     *
     * The account check alone is not enough: osTicket attaches a guest
     * submission to whatever user already owns the typed address, so an
     * impersonated ticket would inherit that user's confirmed status.
     *
     * Fails closed, and swallows throws so it cannot break ticket creation.
     */
    private function requesterIsVerified(Ticket $ticket): bool {
        global $thisclient;

        try {
            if (!$thisclient || !$thisclient->getId() || !$thisclient->isValid())
                return false;

            if ((int) $thisclient->getId() !== (int) $ticket->getOwnerId())
                return false;

            $account = $thisclient->getAccount();
            if (!$account instanceof UserAccount)
                return false;

            return (bool) $account->isConfirmed();
        } catch (\Throwable $e) {
            error_log('Triage plugin could not verify requester session: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Signs the payload with HMAC and POSTs it to the configured
     * FastAPI webhook URL.
     *
     * Returns whether the agent took the ticket. The caller queues it for
     * retry when it did not, so this reports failure rather than only
     * recording it.
     *
     * An unconfigured plugin returns true. Nothing is wrong with the ticket
     * and no amount of retrying fixes a missing URL, so queueing it would fill
     * the queue with work that cannot succeed and then write give-up notes
     * across every ticket in the helpdesk.
     */
    function sendToAgent($payload) {
        global $ost;

        $url = $this->getConfig(self::$pluginInstance)->get('triage-webhook-url');
        $secret = $this->getConfig(self::$pluginInstance)->get('triage-hmac-secret');

        if (!$url || !$secret) {
            $ost->logError('Triage Plugin not configured', 'You need to set the webhook URL and HMAC secret before using this.');
            return true;
        }

        $data_string = json_encode($payload);
        $signature = hash_hmac('sha256', $data_string, $secret);

        try {
            $ch = curl_init($url);
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
            curl_setopt($ch, CURLOPT_POSTFIELDS, $data_string);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
            curl_setopt($ch, CURLOPT_TIMEOUT, 5);
            curl_setopt($ch, CURLOPT_HTTPHEADER, array(
                'Content-Type: application/json',
                'Content-Length: ' . strlen($data_string),
                'X-Triage-Signature: sha256=' . $signature
            ));

            if (curl_exec($ch) === false) {
                throw new \Exception($url . ' - ' . curl_error($ch));
            } else {
                $statusCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                // The agent answers 202 when it accepts a ticket and 200 when
                // it recognises one it has already seen. Both are successes.
                if ($statusCode < 200 || $statusCode >= 300) {
                    throw new \Exception('Error sending to: ' . $url . ' Http code: ' . $statusCode);
                }
            }
            return true;
        } catch (\Exception $e) {
            $ost->logError('Triage Plugin posting issue!', $e->getMessage(), true);
            error_log('Error posting to triage agent. ' . $e->getMessage());
            return false;
        } finally {
            curl_close($ch);
        }
    }
}
