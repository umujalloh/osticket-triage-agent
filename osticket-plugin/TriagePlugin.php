<?php
require_once(INCLUDE_DIR . 'class.signal.php');
require_once(INCLUDE_DIR . 'class.plugin.php');
require_once(INCLUDE_DIR . 'class.ticket.php');
require_once(INCLUDE_DIR . 'class.osticket.php');
require_once(INCLUDE_DIR . 'class.config.php');
require_once(INCLUDE_DIR . 'class.format.php');
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
            'ticket_id'     => $ticket->getId(),
            'ticket_number' => $ticket->getNumber(),
            'subject'       => $ticket->getSubject(),
            'message'       => $plaintext,
            'requester'     => $ticket->getEmail(),
            'created_at'    => date('c'),
        );

        $this->sendToAgent($payload);
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
            curl_setopt($ch, CURLOPT_HTTPHEADER, array(
                'Content-Type: application/json',
                'Content-Length: ' . strlen($data_string),
                'X-Triage-Signature: sha256=' . $signature
            ));

            if (curl_exec($ch) === false) {
                throw new \Exception($url . ' - ' . curl_error($ch));
            } else {
                $statusCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                if ($statusCode != '200') {
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
