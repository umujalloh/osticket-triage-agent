<?php
require_once(INCLUDE_DIR . 'class.ticket.php');
require_once(INCLUDE_DIR . 'class.http.php');

/**
 * The agent's only way to write into osTicket.
 *
 * osTicket's own API creates tickets and nothing else, so notes and priority
 * are unreachable through it. This endpoint exists to close that gap, and the
 * scoping the architecture claims is enforced by what it implements: one
 * operation, on one ticket, named in an authenticated request body.
 */
class TriageWriteController {

    const REPLAY_WINDOW_SECONDS = 300;
    const CLOCK_SKEW_SECONDS = 60;

    private $config;

    function __construct($plugin, $instance) {
        $this->config = $plugin->getConfig($instance);
    }

    function postNote() {
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

        $ticket_id = isset($payload['ticket_id']) ? $payload['ticket_id'] : null;
        $note = isset($payload['note']) ? $payload['note'] : null;
        $title = isset($payload['title']) ? $payload['title'] : 'AI Triage';

        if (!is_int($ticket_id) || is_bool($ticket_id))
            Http::response(400, 'ticket_id must be a number');
        if (!is_string($note) || trim($note) === '')
            Http::response(400, 'note must be a non-empty string');
        if (!is_string($title))
            Http::response(400, 'title must be a string');

        if (!($ticket = Ticket::lookup($ticket_id)))
            Http::response(404, 'Ticket not found');

        // alert=false: a note must not email staff. Slack and PagerDuty own
        // alerting, and doubling it teaches people to ignore both.
        if (!$ticket->logNote($title, $note, 'Triage Agent', false))
            Http::response(500, 'Could not write the note');

        Http::response(200, json_encode(array(
            'status' => 'note_written',
            'ticket_id' => $ticket_id,
        )), 'application/json');
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
