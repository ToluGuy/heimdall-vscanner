# backend/app/plugins/hooks/webhook/run.py
#
# Built-in reference hook plugin — posts a JSON payload to a configured
# webhook URL. Ships pre-installed so the common notification case works
# with just a URL and no separate deployment step, while remaining a
# regular plugin so nothing about it is special-cased in core app code.

import datetime

import requests


def on_event(event: str, payload: dict, config: dict):
    events_enabled = config.get("events", ["job.failed", "host.new"])
    if event not in events_enabled:
        return  # configured to not notify on this particular event

    webhook_url = config.get("webhook_url")
    if not webhook_url:
        return  # not configured yet — nothing to send to

    body = {
        "event": event,
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "source": "Heimdall V-Scanner",
        **payload,
    }

    try:
        requests.post(webhook_url, json=body, timeout=10)
    except requests.RequestException:
        # Best-effort — a failed notification should never surface as an
        # error anywhere else in the app. fire_hook() already logs this.
        raise
