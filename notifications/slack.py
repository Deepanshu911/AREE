"""
notifications/slack.py — Slack alert dispatcher for high-risk threshold breaches.
"""
import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

SLACK_BOT_TOKEN = os.getenv("SLACK_BOT_TOKEN", "")
SLACK_CHANNEL = os.getenv("SLACK_CHANNEL", "#aree-alerts")
RE_ALERT_THRESHOLD = float(os.getenv("RE_ALERT_THRESHOLD", "75.0"))

def send_alert(
    re_score: float,
    entity_name: str,
    entity_id: str,
    channel: Optional[str] = None,
    extra_context: Optional[Dict[str, Any]] = None
) -> bool:
    """Dispatches Block Kit formatted alert if re_score exceeds the alert threshold."""
    if re_score < RE_ALERT_THRESHOLD:
        return False

    token = os.getenv("SLACK_BOT_TOKEN", SLACK_BOT_TOKEN)
    target_channel = channel or os.getenv("SLACK_CHANNEL", SLACK_CHANNEL)

    if not token or token.startswith("xoxb-your"):
        logger.debug("Slack alert skipped: No valid SLACK_BOT_TOKEN configured.")
        return False

    try:
        from slack_sdk import WebClient
        from slack_sdk.errors import SlackApiError

        client = WebClient(token=token)
        text_fallback = f"⚠️ [AREE ALERT] {entity_name} ({entity_id}) RE reached {re_score:.1f}% (Threshold: {RE_ALERT_THRESHOLD}%)"

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "⚡ AREE — Critical Risk Exposure Alert", "emoji": True}
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Resource:* `{entity_name}`\n*Entity ID:* `{entity_id}`\n*Risk Energy (RE):* *{re_score:.1f} / 100*\n*Alert Threshold:* `{RE_ALERT_THRESHOLD}%`"
                }
            }
        ]

        if extra_context:
            context_elements = []
            for k, v in list(extra_context.items())[:5]:
                context_elements.append({"type": "mrkdwn", "text": f"*{k}:* {v}"})
            blocks.append({"type": "context", "elements": context_elements})

        resp = client.chat_postMessage(channel=target_channel, text=text_fallback, blocks=blocks)
        logger.info("Slack alert delivered to %s (ts=%s)", target_channel, resp.get("ts"))
        return True

    except ImportError:
        logger.warning("slack_sdk library not installed.")
        return False
    except Exception as e:
        logger.error("Failed to transmit Slack alert: %s", e)
        return False
