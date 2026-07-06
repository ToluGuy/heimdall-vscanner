#!/usr/bin/env bash
# uninstall.sh — Heimdall V-Scanner server uninstaller
# Stops and removes all services, drops the database, removes the sudoers rule,
# and optionally deletes the project directory.
#
# Run as the same user that ran install.sh (not root).
# Usage: ./uninstall.sh [--yes]   (--yes skips all confirmation prompts)

set -euo pipefail

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CURRENT_USER="$(whoami)"
YES_ALL=false

for arg in "$@"; do
    [[ "$arg" == "--yes" ]] && YES_ALL=true
done

# ── helpers ───────────────────────────────────────────────────────────────────

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "  ${GREEN}✓${NC}  $*"; }
warn() { echo -e "  ${YELLOW}⚠${NC}  $*"; }
info() { echo -e "  ${CYAN}→${NC}  $*"; }
err()  { echo -e "  ${RED}✗${NC}  $*"; }

confirm() {
    # $1 = prompt, $2 = default (y/n)
    if $YES_ALL; then return 0; fi
    local default="${2:-n}"
    local prompt="$1 [$([ "$default" = "y" ] && echo "Y/n" || echo "y/N")]: "
    read -rp "  $prompt" ans
    ans="${ans:-$default}"
    [[ "${ans,,}" == "y" ]]
}

echo ""
echo -e "  ${RED}Heimdall V-Scanner — Uninstaller${NC}"
echo "  ─────────────────────────────────────────────────────"
echo "  This will stop all services and remove Heimdall from this machine."
echo "  Install directory: $INSTALL_DIR"
echo ""

if ! confirm "Continue with uninstall?" "n"; then
    echo "  Aborted."; exit 0
fi

# ── 1. Stop and disable all services ─────────────────────────────────────────
echo ""
info "Stopping services..."

stop_service() {
    local svc="$1"
    if systemctl list-unit-files | grep -q "^${svc}.service"; then
        sudo systemctl stop    "$svc" 2>/dev/null && log "Stopped $svc"    || warn "$svc was not running"
        sudo systemctl disable "$svc" 2>/dev/null && log "Disabled $svc"   || true
        sudo rm -f "/etc/systemd/system/${svc}.service"
        log "Removed /etc/systemd/system/${svc}.service"
    else
        warn "Service $svc not found — skipping"
    fi
}

stop_service vapt-server
stop_service vapt-scanner

# Stop and remove any dynamically registered scanner instances
for svc_file in /etc/systemd/system/vapt-scanner-*.service; do
    [[ -f "$svc_file" ]] || continue
    svc="$(basename "$svc_file" .service)"
    stop_service "$svc"
done

sudo systemctl daemon-reload
log "systemctl daemon-reload done"

# ── 2. Remove sudoers rule ─────────────────────────────────────────────────────
if [[ -f /etc/sudoers.d/vapt-scanner-spawn ]]; then
    sudo rm -f /etc/sudoers.d/vapt-scanner-spawn
    log "Removed sudoers rule"
fi

# ── 3. Drop the database ──────────────────────────────────────────────────────
echo ""
ENV_FILE="$INSTALL_DIR/.env"
DB_NAME="vapt"; DB_USER="vapt_user"
if [[ -f "$ENV_FILE" ]]; then
    source "$ENV_FILE" 2>/dev/null || true
fi

if confirm "Drop the PostgreSQL database '${DB_NAME}' and user '${DB_USER}'? This deletes ALL scan data." "n"; then
    if sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" 2>/dev/null | grep -q 1; then
        sudo -u postgres psql -c "DROP DATABASE IF EXISTS ${DB_NAME};" 2>/dev/null && log "Dropped database ${DB_NAME}" || warn "Could not drop database"
    else
        warn "Database '${DB_NAME}' not found"
    fi
    if sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'" 2>/dev/null | grep -q 1; then
        sudo -u postgres psql -c "DROP USER IF EXISTS ${DB_USER};" 2>/dev/null && log "Dropped user ${DB_USER}" || warn "Could not drop user"
    fi
else
    warn "Database kept — you can drop it manually later:"
    echo "    sudo -u postgres psql -c \"DROP DATABASE ${DB_NAME};\""
    echo "    sudo -u postgres psql -c \"DROP USER ${DB_USER};\""
fi

# ── 4. Remove key files left on disk ─────────────────────────────────────────
for keyfile in "$INSTALL_DIR"/*_key.txt; do
    [[ -f "$keyfile" ]] && rm -f "$keyfile" && log "Removed $keyfile"
done

# ── 5. Remove the project directory ──────────────────────────────────────────
echo ""
if confirm "Delete the project directory '$INSTALL_DIR'? This cannot be undone." "n"; then
    # Can't delete ourselves — move up one level
    PARENT="$(dirname "$INSTALL_DIR")"
    DIR_NAME="$(basename "$INSTALL_DIR")"
    cd "$PARENT"
    rm -rf "$DIR_NAME"
    log "Deleted $INSTALL_DIR"
else
    warn "Project directory kept at $INSTALL_DIR"
    info "To remove it manually: rm -rf $INSTALL_DIR"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "  ${GREEN}Uninstall complete.${NC}"
echo "  Heimdall V-Scanner has been removed from this machine."
echo ""
