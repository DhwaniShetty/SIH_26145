import os
import json
import logging
import requests
from typing import Optional
from alerting.schema import AlertRecord

logger = logging.getLogger(__name__)

class WebhookNotifier:
    def __init__(self, webhook_url: Optional[str] = None):
        # Allow passing explicitly or falling back to env var
        self.webhook_url = webhook_url or os.environ.get("ALERT_WEBHOOK_URL")
        
    def notify(self, alert: AlertRecord):
        """
        Sends the alert payload to the configured webhook URL.
        Only triggers for HIGH or CRITICAL severities to avoid spam, 
        but can be configured.
        """
        if not self.webhook_url:
            return
            
        if alert.severity not in ["HIGH", "CRITICAL"]:
            return
            
        payload = {
            "text": f"🚨 *{alert.severity} Alert*: {alert.threat_class}",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Detector:* {alert.detector}\n*Flow:* {alert.flow_id.src_ip}:{alert.flow_id.src_port} -> {alert.flow_id.dst_ip}:{alert.flow_id.dst_port}\n*Confidence:* {alert.confidence_score:.2f}"
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Explanation:* {alert.evidence.explanation}"
                    }
                }
            ]
        }
        
        try:
            # We use a short timeout so as not to block the ingestion pipeline
            requests.post(self.webhook_url, json=payload, timeout=2.0)
        except Exception as e:
            logger.error(f"Failed to push alert to webhook: {e}")
