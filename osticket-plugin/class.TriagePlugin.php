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
     * Entrypoint, runs once when osTicket loads the plugin.
     * Connects our listener to the ticket.created signal.
     */
    function bootstrap() {
        self::$pluginInstance = self::getPluginInstance(null);
        Signal::connect('ticket.created', array($this, 'onTicketCreated'));
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

        $message = $ticket->getMessages()[0];
        $plaintext = Format::html2text($message->getBody()->getClean());

        $payload = array(
            'ticket_id'          => $ticket->getId(),
            'ticket_number'      => $ticket->getNumber(),
            'subject'            => $ticket->getSubject(),
            'message'            => $plaintext,
            'requester'          => (string) $ticket->getEmail(),
            'requester_verified' => $this->requesterIsVerified($ticket),
            'submitter_ip'       => $ticket->getIP(),
            'created_at'         => date('c'),
        );

        $this->sendToAgent($payload);
    }

    /**
     * True only when this ticket was filed from an authenticated client
     * session whose logged-in user is the ticket owner, and that owner's
     * account is confirmed.
     *
     * Checking the account by itself is not enough. osTicket resolves an
     * address typed into the open guest form to whatever user record already
     * owns it, so a ticket filed as ceo@company.com becomes owned by the real
     * CEO's user and would inherit that account's confirmed status. The
     * session check is the part that proves the submitter is the person named,
     * rather than proving the address exists.
     *
     * Fails closed. Guest submissions carry no session, and staff-created,
     * API, and email-piped tickets carry no client session either, so none of
     * them are treated as verified. A throw here would break ticket creation,
     * so nothing escapes.
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
     */
    function sendToAgent($payload) {
        global $ost;

        $url = $this->getConfig(self::$pluginInstance)->get('triage-webhook-url');
        $secret = $this->getConfig(self::$pluginInstance)->get('triage-hmac-secret');

        if (!$url || !$secret) {
            $ost->logError('Triage Plugin not configured', 'You need to set the webhook URL and HMAC secret before using this.');
            return;
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
                if ($statusCode != '202') {
                    throw new \Exception('Error sending to: ' . $url . ' Http code: ' . $statusCode);
                }
            }
        } catch (\Exception $e) {
            $ost->logError('Triage Plugin posting issue!', $e->getMessage(), true);
            error_log('Error posting to triage agent. ' . $e->getMessage());
        } finally {
            curl_close($ch);
        }
    }
}
