#!/bin/bash
# update.sh — Heimdall V-Scanner updater
# Pulls the latest code, updates Python dependencies, runs any new
# database migrations, and restarts services.
#
# Run as the same user who ran install.sh:
#   ./update.sh
#
# Services are restarted automatically. The dashboard will be unavailable
# for a few seconds during the restart.

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$INSTALL_DIR/.env"

log()    { echo -e "${GREEN}[✓]${NC} $1"; }
info()   { echo -e "${CYAN}[→]${NC} $1"; }
warn()   { echo -e "${YELLOW}[!]${NC} $1"; }
error()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }
section(){ echo -e "\n${BOLD}${CYAN}━━━ $1 ━━━${NC}"; }

echo -e "\n${BOLD}${CYAN}Heimdall V-Scanner — Update${NC}\n"

# ─── PREFLIGHT ────────────────────────────────────────────────────────────────

if [ "$EUID" -eq 0 ]; then
    error "Do not run as root. Run as the same user who installed Heimdall."
fi

if [ ! -f "$ENV_FILE" ]; then
    error ".env not found at $ENV_FILE — run install.sh first."
fi

if [ ! -d "$INSTALL_DIR/venv" ]; then
    error "Virtual environment not found — run install.sh first."
fi

# load env vars
set -a
source "$ENV_FILE"
set +a

# ─── PULL LATEST CODE ─────────────────────────────────────────────────────────

section "Code Update"

if [ -d "$INSTALL_DIR/.git" ]; then
    info "Pulling latest code from git..."
    git -C "$INSTALL_DIR" pull --ff-only
    log "Code updated"
else
    warn "Not a git repository — skipping git pull."
    warn "If you downloaded manually, replace the files yourself and re-run this script."
fi

# ─── SELF-UPDATE CHECK ────────────────────────────────────────────────────────

# If update.sh itself was modified by the pull, warn the user to run it again.
# This ensures new migration steps in the updated script actually execute.
if git -C "$INSTALL_DIR" diff HEAD@{1} HEAD -- update.sh 2>/dev/null | grep -q '^+'; then
    warn "update.sh was modified in this pull."
    warn "Running it again now to apply any new migration steps..."
    exec "$INSTALL_DIR/update.sh"
fi

# ─── PYTHON DEPENDENCIES ──────────────────────────────────────────────────────

section "Python Dependencies"

info "Updating Python packages..."
"$INSTALL_DIR/venv/bin/pip" install -q --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install -q -r "$INSTALL_DIR/requirements.txt"
log "Dependencies up to date"

# ─── DATABASE MIGRATIONS ──────────────────────────────────────────────────────

section "Database Migrations"

info "Running schema sync..."
cd "$INSTALL_DIR"
"$INSTALL_DIR/venv/bin/python" -c "
import sys
sys.path.insert(0, '.')
from backend.app.db import engine, Base
from backend.app.models import Agent, Job, Result, DiscoverySweep, Schedule, Host, Setting
Base.metadata.create_all(bind=engine)
print('  Tables verified')
"

info "Applying column migrations..."
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" <<EOF
DO \$\$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='results' AND column_name='cleared'
    ) THEN
        ALTER TABLE results ADD COLUMN cleared BOOLEAN DEFAULT FALSE;
        RAISE NOTICE 'Added results.cleared';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='jobs' AND column_name='cleared'
    ) THEN
        ALTER TABLE jobs ADD COLUMN cleared BOOLEAN DEFAULT FALSE;
        RAISE NOTICE 'Added jobs.cleared';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='jobs' AND column_name='mode'
    ) THEN
        ALTER TABLE jobs ADD COLUMN mode VARCHAR DEFAULT 'remote';
        RAISE NOTICE 'Added jobs.mode';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='jobs' AND column_name='profile'
    ) THEN
        ALTER TABLE jobs ADD COLUMN profile VARCHAR DEFAULT 'standard';
        RAISE NOTICE 'Added jobs.profile';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='jobs' AND column_name='started_at'
    ) THEN
        ALTER TABLE jobs ADD COLUMN started_at TIMESTAMP;
        RAISE NOTICE 'Added jobs.started_at';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='jobs' AND column_name='completed_at'
    ) THEN
        ALTER TABLE jobs ADD COLUMN completed_at TIMESTAMP;
        RAISE NOTICE 'Added jobs.completed_at';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='jobs' AND column_name='next_run_at'
    ) THEN
        ALTER TABLE jobs ADD COLUMN next_run_at TIMESTAMP;
        RAISE NOTICE 'Added jobs.next_run_at';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='jobs' AND column_name='port'
    ) THEN
        ALTER TABLE jobs ADD COLUMN port INTEGER;
        RAISE NOTICE 'Added jobs.port';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='jobs' AND column_name='ports'
    ) THEN
        ALTER TABLE jobs ADD COLUMN ports VARCHAR;
        RAISE NOTICE 'Added jobs.ports';
    END IF;
    
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='jobs' AND column_name='custom_scripts'
    ) THEN
        ALTER TABLE jobs ADD COLUMN custom_scripts VARCHAR;
        RAISE NOTICE 'Added jobs.custom_scripts';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='agents' AND column_name='is_stale'
    ) THEN
        ALTER TABLE agents ADD COLUMN is_stale BOOLEAN DEFAULT FALSE;
        RAISE NOTICE 'Added agents.is_stale';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_name='schedules'
    ) THEN
        CREATE TABLE schedules (
            id SERIAL PRIMARY KEY,
            name VARCHAR NOT NULL,
            type VARCHAR NOT NULL,
            target VARCHAR NOT NULL,
            mode VARCHAR DEFAULT 'remote',
            profile VARCHAR DEFAULT 'standard',
            priority VARCHAR DEFAULT 'medium',
            ports VARCHAR,
            interval_hours INTEGER NOT NULL,
            paused BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT NOW(),
            last_run_at TIMESTAMP,
            next_run_at TIMESTAMP
        );
        RAISE NOTICE 'Created schedules table';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_name='settings'
    ) THEN
        CREATE TABLE settings (
            key   VARCHAR PRIMARY KEY,
            value VARCHAR NOT NULL
        );
        RAISE NOTICE 'Created settings table';
    END IF;
END
\$\$;
EOF

PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
    -c "GRANT ALL ON TABLE schedules TO ${DB_USER};" 2>/dev/null || true
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
    -c "GRANT USAGE, SELECT ON SEQUENCE schedules_id_seq TO ${DB_USER};" 2>/dev/null || true
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
    -c "GRANT ALL ON TABLE settings TO ${DB_USER};" 2>/dev/null || true

log "Migrations complete"

# ─── RESTART SERVICES ─────────────────────────────────────────────────────────

section "Restart Services"

# Only restart services that are actually installed and enabled
for svc in vapt-server vapt-scanner; do
    if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
        info "Restarting $svc..."
        sudo systemctl restart "$svc"
        sleep 2
        if sudo systemctl is-active --quiet "$svc"; then
            log "$svc restarted successfully"
        else
            warn "$svc failed to restart — check: journalctl -u $svc -n 30"
        fi
    else
        info "$svc is not enabled as a service — skipping"
    fi
done

# ─── DONE ─────────────────────────────────────────────────────────────────────

SERVER_IP=$(hostname -I | awk '{print $1}')

echo ""
echo -e "  ${BOLD}${GREEN}Update complete.${NC}"
echo -e "  Dashboard: http://${SERVER_IP}:8000/dashboard"
echo ""
