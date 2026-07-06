#!/usr/bin/env bash
# uninstall_agent.sh — Heimdall V-Scanner agent uninstaller (Linux)
# Stops the agent service, removes it from systemd, and cleans up files.
#
# Usage: ./uninstall_agent.sh [--yes]

set -euo pipefail

YES_ALL=false
for arg in "$@"; do [[ "$arg" == "--yes" ]] && YES_ALL=true; done

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "  ${GREEN}✓${NC}  $*"; }
warn() { echo -e "  ${YELLOW}⚠${NC}  $*"; }
info() { echo -e "  ${CYAN}→${NC}  $*"; }

confirm() {
    if $YES_ALL; then return 0; fi
    read -rp "  $1 [y/N]: " ans
    [[ "${ans,,}" == "y" ]]
}

echo ""
echo "  Heimdall V-Scanner — Agent Uninstaller"
echo "  ────────────────────────────────────────"
echo ""

SERVICE="heimdall-agent"
AGENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Stop and remove systemd service if present ────────────────────────────────
if systemctl list-unit-files 2>/dev/null | grep -q "^${SERVICE}.service"; then
    info "Stopping and removing systemd service..."
    sudo systemctl stop    "$SERVICE" 2>/dev/null || warn "Service was not running"
    sudo systemctl disable "$SERVICE" 2>/dev/null || true
    sudo rm -f "/etc/systemd/system/${SERVICE}.service"
    sudo systemctl daemon-reload
    log "Service removed"
else
    warn "No systemd service named '$SERVICE' found — may have been started manually"
fi

# Kill any running agent.py process for this user
if pgrep -u "$(whoami)" -f "agent.py" >/dev/null 2>&1; then
    if confirm "Kill running agent.py processes?"; then
        pkill -u "$(whoami)" -f "agent.py" && log "Processes killed" || warn "Could not kill processes"
    fi
fi

# ── Remove key file ───────────────────────────────────────────────────────────
for keyfile in "$AGENT_DIR"/*_key.txt; do
    [[ -f "$keyfile" ]] || continue
    rm -f "$keyfile" && log "Removed key file: $keyfile"
done

# ── Remove venv ───────────────────────────────────────────────────────────────
VENV_CANDIDATES=("$HOME/vapt-agent/venv" "$AGENT_DIR/../venv" "$AGENT_DIR/venv")
for venv in "${VENV_CANDIDATES[@]}"; do
    if [[ -d "$venv" ]]; then
        if confirm "Remove virtual environment at '$venv'?"; then
            rm -rf "$venv" && log "Removed $venv"
        fi
    fi
done

echo ""
log "Agent uninstall complete."
echo "  The agent files remain at $AGENT_DIR — remove them manually if needed."
echo ""
