# backend/app/core.py
#
# Shared config, auth, and helpers used by 2+ route modules. Route-specific
# helpers (used by only one routes/*.py file) live in that file instead —
# this stays limited to genuinely cross-cutting concerns so it doesn't turn
# into a second monolith.

import os
import sys as _sys
import secrets
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from .logger import get_logger
from .ai_analysis import AI_AUTO_ANALYSE

logger = get_logger("vapt.server", "server.log")

# --- TIMING / MISC CONFIG ---
JOB_TIMEOUT_SECONDS = 120
STALE_AGENT_HOURS = int(os.environ.get("STALE_AGENT_HOURS", "24"))
SCHEDULE_TICK_SECONDS = 60   # how often the scheduler wakes up to check

# ── Scanner auto-spawn settings ───────────────────────────────────────────────
# INSTALL_DIR: the project root (two levels up from this file: backend/app/core.py)
INSTALL_DIR  = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PYTHON_BIN   = _sys.executable
ENV_FILE     = os.path.join(INSTALL_DIR, ".env")
SCANNER_PY   = os.path.join(INSTALL_DIR, "backend", "app", "scanner.py")
# Set SCANNER_AUTOSTART=true in .env to allow the dashboard to spawn scanner
# instances via systemctl. Requires the sudoers rule added by install.sh.
SCANNER_AUTOSTART = os.environ.get("SCANNER_AUTOSTART", "false").lower() == "true"

# --- AUTH ---
security = HTTPBasic()

DASHBOARD_USERNAME = os.environ.get("DASHBOARD_USERNAME", "admin")
DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "vapt-admin")

if DASHBOARD_PASSWORD == "vapt-admin":
    logger.warning(
        "DASHBOARD_PASSWORD is not set (or is still the default 'vapt-admin'). "
        "Set a strong DASHBOARD_PASSWORD in .env — this dashboard controls a "
        "network scanner and should not be left on the default credential."
    )

# Optional shared secret for /agents/register. Registration is otherwise
# unauthenticated by design (a new scanner/agent has no API key yet), which
# means anyone who can reach this server can register as an agent and start
# receiving job targets. Set VAPT_REGISTRATION_TOKEN in .env (and the matching
# value on each agent/scanner) to close that off. Left unset by default so
# existing installs aren't broken by an update.
AGENT_REGISTRATION_TOKEN = os.environ.get("VAPT_REGISTRATION_TOKEN")
if not AGENT_REGISTRATION_TOKEN:
    logger.warning(
        "VAPT_REGISTRATION_TOKEN is not set — /agents/register is open to anyone who can "
        "reach this server. Set VAPT_REGISTRATION_TOKEN in .env to require a shared secret "
        "for new agent/scanner registration."
    )


def require_auth(credentials: HTTPBasicCredentials = Depends(security)):
    correct_username = secrets.compare_digest(
        credentials.username.encode("utf8"),
        DASHBOARD_USERNAME.encode("utf8")
    )
    correct_password = secrets.compare_digest(
        credentials.password.encode("utf8"),
        DASHBOARD_PASSWORD.encode("utf8")
    )
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


# --- VALIDATION ---

# Web ports are Nikto's domain — NSE and standalone jobs validate against this
WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888}

VALID_JOB_TYPES = {"nmap_scan", "nikto_scan", "nse_scan"}


def validate_target(value: str, field_name: str = "target") -> str:
    """
    Defensive validation for any user-supplied value that ends up as a bare
    argv token passed to nmap/nikto (target, subnet, etc). These tools parse
    tokens starting with '-' as flags rather than targets, so an unvalidated
    value could inject options such as -oG (write a file) or -iL (read a file
    as a target list). Commands are invoked as argv lists, never through a
    shell, so this is scoped to the one thing that actually matters at that
    boundary — it deliberately does not restrict character sets, since the
    target field legitimately accepts hostnames, IPv6 addresses, CIDR ranges,
    and full URLs (for Web Scan).
    """
    value = (value or "").strip()
    if not value:
        raise HTTPException(status_code=400, detail=f"{field_name} is required")
    if len(value) > 512:
        raise HTTPException(status_code=400, detail=f"{field_name} is too long")
    if any(ord(c) < 32 for c in value):
        raise HTTPException(status_code=400, detail=f"{field_name} contains invalid control characters")
    if value[0] == "-":
        raise HTTPException(
            status_code=400,
            detail=f"{field_name} cannot start with '-' — this would be interpreted as a "
                   "command-line flag by nmap/nikto rather than a target"
        )
    return value


# --- SETTINGS ---

SETTING_DEFAULTS = {
    "ai_auto_analyse":    "true",
    "stale_agent_hours":  "24",
    "auto_nikto":         "true",   # automatically run Nikto after nmap_scan when web ports are found
}


def get_setting(db, key: str) -> str:
    """Get a setting value, falling back to env var then hardcoded default."""
    from .models import Setting  # local import: avoids a core<->models import-order edge case
    row = db.query(Setting).filter(Setting.key == key).first()
    if row:
        return row.value
    # Fall back to env / hardcoded defaults
    if key == "stale_agent_hours":
        return os.environ.get("STALE_AGENT_HOURS", "24")
    if key == "ai_auto_analyse":
        return "true" if AI_AUTO_ANALYSE else "false"
    if key == "auto_nikto":
        return os.environ.get("AUTO_NIKTO", "true")
    return SETTING_DEFAULTS.get(key, "")
