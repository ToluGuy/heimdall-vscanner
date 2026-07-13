# backend/app/services/hooks.py
#
# Dispatches server-side events (job completed, host discovered, ...) to any
# enabled plugin subscribed to them. Same safety boundary as scan plugins'
# run_plugin() in scanner.py/agent.py: this only ever imports code already
# sitting on THIS server's disk at plugins/hooks/<plugin_name>/run.py,
# placed there manually. Nothing here fetches or receives code from
# anywhere — a plugin's manifest (installed via the dashboard) only ever
# declares which events it WANTS, never the code that runs when they fire.
#
# Call sites should fire this in a background thread (see routes/agents.py,
# routes/jobs.py) so a slow or broken hook plugin never blocks the request
# that triggered it. fire_hook() opens its own DB session for exactly that
# reason — sessions aren't safe to share across threads.

import os
import json
import importlib.util

from ..db import SessionLocal
from ..core import logger
from ..models import Plugin

HOOK_PLUGIN_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "plugins", "hooks")

# Events core code is allowed to fire. A plugin manifest can only subscribe
# to names in this set — validated at install time in routes/plugins.py.
KNOWN_HOOK_EVENTS = {"job.completed", "job.failed", "host.new"}


def fire_hook(event: str, payload: dict):
    """
    Calls on_event(event, payload) for every enabled plugin subscribed to
    this event. Best-effort and fully isolated per plugin — one broken or
    slow hook plugin never affects another, and never raises back into
    whatever triggered the event.
    """
    if event not in KNOWN_HOOK_EVENTS:
        logger.warning(f"fire_hook called with unrecognised event '{event}' — ignoring")
        return

    db = SessionLocal()
    try:
        subscribed = []
        for plugin in db.query(Plugin).filter(Plugin.enabled == True).all():
            try:
                manifest = json.loads(plugin.manifest)
            except (ValueError, TypeError):
                continue
            if event in manifest.get("hooks", []):
                try:
                    config = json.loads(plugin.config) if plugin.config else {}
                except (ValueError, TypeError):
                    config = {}
                subscribed.append((plugin.name, config))
    finally:
        db.close()

    for plugin_name, config in subscribed:
        entry_point = os.path.join(HOOK_PLUGIN_DIR, plugin_name, "run.py")
        if not os.path.isfile(entry_point):
            logger.warning(
                f"Hook plugin '{plugin_name}' subscribed to '{event}' but has no code at "
                f"{entry_point} — skipping (metadata registered, code not deployed here yet)"
            )
            continue
        try:
            spec = importlib.util.spec_from_file_location(f"heimdall_hook_{plugin_name}", entry_point)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            if not hasattr(module, "on_event"):
                logger.warning(f"Hook plugin '{plugin_name}' has no on_event(event, payload, config) function")
                continue
            module.on_event(event, payload, config)
        except Exception as e:
            logger.error(f"Hook plugin '{plugin_name}' raised on event '{event}': {e}")
