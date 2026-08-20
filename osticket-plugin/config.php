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
