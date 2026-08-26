<?php
require_once(INCLUDE_DIR . 'class.plugin.php');
require_once(INCLUDE_DIR . 'class.forms.php');
class TriagePluginConfig extends PluginConfig {
    function getOptions() {
        return array(
            'triage-section' => new SectionBreakField(array(
                'label' => __('AI Triage Webhook'),
            )),
            'triage-webhook-url' => new TextboxField(array(
                'label' => __('FastAPI Webhook URL'),
                'configuration' => array(
                    'size' => 100,
                    'length' => 200
                )
            )),
            'triage-hmac-secret' => new PasswordField(array(
                'label' => __('HMAC Shared Secret'),
                'configuration' => array(
                    'size' => 60,
                    'length' => 100
                )
            )),
            'triage-write-secret' => new PasswordField(array(
                'label' => __('HMAC Write-Back Secret'),
                'hint' => __('Separate from the secret above. Authenticates the agent writing notes into tickets, so a leak of one does not grant the other.'),
                'configuration' => array(
                    'size' => 60,
                    'length' => 100
                )
            )),
            'triage-retry-window' => new TextboxField(array(
                'label' => __('Retry Window (minutes)'),
                'default' => '60',
                'hint' => __('How long a ticket the agent never accepted keeps being retried. After this the plugin gives up and writes a note on the ticket saying triage never ran, so it is worked as an ordinary ticket rather than waiting on something that is not coming. Bounded by how long a page is still the right response, not by how long delivery might succeed.'),
                'configuration' => array(
                    'size' => 10,
                    'length' => 6
                )
            )),
            'triage-security-department' => new TextboxField(array(
                'label' => __('Security Department'),
                'hint' => __('Where security questions are routed. Named here rather than sent by the agent, so the write endpoint can only ever move a ticket to this one department and a leaked write secret cannot move a ticket somewhere nobody watches. Leave blank to disable routing.'),
                'configuration' => array(
                    'size' => 40,
                    'length' => 100
                )
            )),
        );
    }
}
