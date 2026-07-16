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
        );
    }
}
