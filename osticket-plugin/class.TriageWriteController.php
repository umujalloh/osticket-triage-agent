<?php
require_once(INCLUDE_DIR . 'class.ticket.php');
require_once(INCLUDE_DIR . 'class.thread.php');
require_once(INCLUDE_DIR . 'class.priority.php');
require_once(INCLUDE_DIR . 'class.dynamic_forms.php');
require_once(INCLUDE_DIR . 'class.http.php');

/**
 * The agent's only way to write into osTicket.
 *
 * osTicket's own API creates tickets and nothing else, so notes and priority
 * are unreachable through it. This endpoint exists to close that gap, and the
 * scoping the architecture claims is enforced by what it implements: two
 * operations, on one ticket, named in an authenticated request body.
 */
class TriageWriteController {

    const REPLAY_WINDOW_SECONDS = 300;
    const CLOCK_SKEW_SECONDS = 60;

    // The agent names a priority rather than sending an id, so a mistake is a
    // rejected request instead of a silent write to whatever row holds that id.
    const PRIORITIES = array('low', 'normal', 'high', 'emergency');

    private $config;

    function __construct($plugin, $instance) {
        $this->config = $plugin->getConfig($instance);
    }

    function postNote() {
        $payload = $this->authenticatedPayload();
        list($ticket_id, $ticket) = $this->requireTicket($payload);

        $note = isset($payload['note']) ? $payload['note'] : null;
        $title = isset($payload['title']) ? $payload['title'] : 'AI Triage';

        if (!is_string($note) || trim($note) === '')
            Http::response(400, 'note must be a non-empty string');
        if (!is_string($title))
            Http::response(400, 'title must be a string');

        // A text body, not the HTML one logNote() would wrap a string in: line
        // breaks survive, and log values are escaped on output rather than
        // handed to the HTML purifier.
        //
        // alert=false: a note must not email staff. Slack and PagerDuty own
        // alerting, and doubling it teaches people to ignore both.
        $errors = array();
        $entry = $ticket->postNote(
            array('title' => $title, 'note' => new TextThreadEntryBody($note)),
            $errors,
            'Triage Agent',
            false
        );
        if (!$entry)
            Http::response(500, 'Could not write the note');

        $this->respond(array('status' => 'note_written', 'ticket_id' => $ticket_id));
    }

    function postPriority() {
        $payload = $this->authenticatedPayload();
        list($ticket_id, $ticket) = $this->requireTicket($payload);

        $name = isset($payload['priority']) ? $payload['priority'] : null;
        if (!is_string($name) || !in_array($name, self::PRIORITIES, true))
            Http::response(400, 'priority must be one of: ' . implode(', ', self::PRIORITIES));

        if (!($priority = Priority::lookup(array('priority' => $name))))
            Http::response(400, "This osTicket has no priority named '$name'");

        // Reported back so the audit trail shows what the agent replaced. The
        // agent sets priority unconditionally, which is safe because it acts
        // once per ticket seconds after creation, but if that assumption ever
        // breaks this is how it becomes visible.
        $before = $ticket->getPriority();

        // Priority is a dynamic form answer in 1.18, not a column, so it is
        // set the same way Ticket::create() applies a filter's priority.
        $updated = false;
        foreach (DynamicFormEntry::forTicket($ticket_id) as $form) {
            if ($form->getAnswer('priority')) {
                $form->setAnswer('priority', null, $priority->getId());
                $form->save();
                $updated = true;
                break;
            }
        }
        if (!$updated)
            Http::response(500, 'This ticket has no priority field to set');

        $this->respond(array(
            'status' => 'priority_set',
            'ticket_id' => $ticket_id,
            'from' => $before ? $before->getTag() : null,
            'to' => $name,
        ));
    }

    /**
     * Verifies the request and returns its body, or ends the request.
     *
     * Shared by every operation so they cannot drift apart, which is the way
     * a second endpoint usually ends up weaker than the first.
     */
    private function authenticatedPayload() {
        $secret = $this->config->get('triage-write-secret');
        if (!$secret)
            Http::response(500, 'Triage write secret is not configured');

        $body = file_get_contents('php://input');
        $header = isset($_SERVER['HTTP_X_TRIAGE_SIGNATURE'])
            ? $_SERVER['HTTP_X_TRIAGE_SIGNATURE'] : '';

        if (!$this->verifySignature($body, $header, $secret))
            Http::response(401, 'Invalid signature');

        $payload = json_decode($body, true);
        if (!is_array($payload))
            Http::response(400, 'Body is not a JSON object');

        if (!$this->isFresh(isset($payload['created_at']) ? $payload['created_at'] : null))
            Http::response(401, 'Request timestamp is stale or invalid');

        return $payload;
    }

    private function requireTicket($payload) {
        $ticket_id = isset($payload['ticket_id']) ? $payload['ticket_id'] : null;
        if (!is_int($ticket_id) || is_bool($ticket_id))
            Http::response(400, 'ticket_id must be a number');

        if (!($ticket = Ticket::lookup($ticket_id)))
            Http::response(404, 'Ticket not found');

        return array($ticket_id, $ticket);
    }

    private function respond($body) {
        Http::response(200, json_encode($body), 'application/json');
    }

    private function verifySignature($body, $header, $secret) {
        if (strpos($header, 'sha256=') !== 0)
            return false;
        $received = substr($header, 7);
        $expected = hash_hmac('sha256', $body, $secret);
        return hash_equals($expected, $received);
    }

    private function isFresh($created_at) {
        if (!is_string($created_at))
            return false;
        $ts = strtotime($created_at);
        if ($ts === false)
            return false;
        $age = time() - $ts;
        return $age >= -self::CLOCK_SKEW_SECONDS && $age <= self::REPLAY_WINDOW_SECONDS;
    }
}
