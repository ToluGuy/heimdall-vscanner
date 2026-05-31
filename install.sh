#!/bin/bash
# install.sh — Heimdall V-Scanner installer
# Run as a user with sudo access, not as root directly

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log()    { echo -e "${GREEN}[✓]${NC} $1"; }
info()   { echo -e "${CYAN}[→]${NC} $1"; }
warn()   { echo -e "${YELLOW}[!]${NC} $1"; }
error()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }
section(){ echo -e "\n${BOLD}${CYAN}━━━ $1 ━━━${NC}"; }

# ─── HEADER ───────────────────────────────────────────────────────────────────

echo -e "${BOLD}${GREEN}"
echo "  ██╗  ██╗███████╗██╗███╗   ███╗██████╗  █████╗ ██╗     ██╗     "
echo "  ██║  ██║██╔════╝██║████╗ ████║██╔══██╗██╔══██╗██║     ██║     "
echo "  ███████║█████╗  ██║██╔████╔██║██║  ██║███████║██║     ██║     "
echo "  ██╔══██║██╔══╝  ██║██║╚██╔╝██║██║  ██║██╔══██║██║     ██║     "
echo "  ██║  ██║███████╗██║██║ ╚═╝ ██║██████╔╝██║  ██║███████╗███████╗"
echo "  ╚═╝  ╚═╝╚══════╝╚═╝╚═╝     ╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝"
echo -e "${NC}${BOLD}  V-Scanner — Installer${NC}"
echo ""

# ─── PREFLIGHT ────────────────────────────────────────────────────────────────

section "Preflight Checks"

if [ "$EUID" -eq 0 ]; then
    error "Do not run this script as root. Run as a normal user with sudo access."
fi

command -v sudo >/dev/null 2>&1 || error "sudo is required but not installed."
command -v python3 >/dev/null 2>&1 || error "Python 3 is required but not installed."

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || { [ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 10 ]; }; then
    error "Python 3.10+ required. Found Python $PYTHON_VERSION."
fi

log "Python $PYTHON_VERSION found"

# ─── SYSTEM DEPENDENCIES ──────────────────────────────────────────────────────

section "System Dependencies"

info "Updating package list..."
sudo apt-get update -qq

PACKAGES=()
for pkg in nmap nikto postgresql postgresql-contrib python3-venv python3-pip; do
    if ! dpkg -s "$pkg" &>/dev/null; then
        PACKAGES+=("$pkg")
    else
        log "$pkg already installed"
    fi
done

if [ ${#PACKAGES[@]} -gt 0 ]; then
    info "Installing: ${PACKAGES[*]}"
    sudo apt-get install -y -qq "${PACKAGES[@]}"
    log "System packages installed"
fi

# ─── PYTHON ENVIRONMENT ───────────────────────────────────────────────────────

section "Python Environment"

if [ ! -d "$INSTALL_DIR/venv" ]; then
    info "Creating virtual environment..."
    python3 -m venv "$INSTALL_DIR/venv"
    log "Virtual environment created"
else
    log "Virtual environment already exists"
fi

info "Installing Python dependencies..."
"$INSTALL_DIR/venv/bin/pip" install -q --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install -q -r "$INSTALL_DIR/requirements.txt"
log "Python dependencies installed"

# ─── ENVIRONMENT CONFIGURATION ────────────────────────────────────────────────

section "Environment Configuration"

ENV_FILE="$INSTALL_DIR/.env"

if [ -f "$ENV_FILE" ]; then
    warn ".env file already exists."
    read -rp "    Overwrite it? [y/N]: " overwrite
    if [[ ! "$overwrite" =~ ^[Yy]$ ]]; then
        info "Keeping existing .env file."
        SKIP_ENV=true
    fi
fi

if [ -z "$SKIP_ENV" ]; then
    echo ""
    info "Configure your environment. Press Enter to accept defaults."
    echo ""

    read -rp "  Dashboard username [admin]: " DASHBOARD_USERNAME
    DASHBOARD_USERNAME="${DASHBOARD_USERNAME:-admin}"

    read -rsp "  Dashboard password [vapt-admin]: " DASHBOARD_PASSWORD
    echo ""
    DASHBOARD_PASSWORD="${DASHBOARD_PASSWORD:-vapt-admin}"

    read -rp "  Database host [localhost]: " DB_HOST
    DB_HOST="${DB_HOST:-localhost}"

    read -rp "  Database port [5432]: " DB_PORT
    DB_PORT="${DB_PORT:-5432}"

    read -rp "  Database name [vapt]: " DB_NAME
    DB_NAME="${DB_NAME:-vapt}"

    read -rp "  Database user [vapt_user]: " DB_USER
    DB_USER="${DB_USER:-vapt_user}"

    read -rsp "  Database password: " DB_PASSWORD
    echo ""

    if [ -z "$DB_PASSWORD" ]; then
        DB_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(16))")
        warn "No password entered. Generated: $DB_PASSWORD"
        warn "Save this — it will be written to .env and used for PostgreSQL."
    fi

    cat > "$ENV_FILE" <<EOF
DASHBOARD_USERNAME=${DASHBOARD_USERNAME}
DASHBOARD_PASSWORD=${DASHBOARD_PASSWORD}
DB_HOST=${DB_HOST}
DB_PORT=${DB_PORT}
DB_NAME=${DB_NAME}
DB_USER=${DB_USER}
DB_PASSWORD=${DB_PASSWORD}
VAPT_SERVER_URL=http://127.0.0.1:8000
EOF

    log ".env file written"
fi

# load env vars for use in this script
set -a
source "$ENV_FILE"
set +a

# ─── POSTGRESQL SETUP ─────────────────────────────────────────────────────────

section "PostgreSQL Setup"

info "Ensuring PostgreSQL is running..."
sudo systemctl start postgresql
sudo systemctl enable postgresql -q

# check if DB already exists
DB_EXISTS=$(sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'")

if [ "$DB_EXISTS" = "1" ]; then
    log "Database '${DB_NAME}' already exists"
else
    info "Creating database '${DB_NAME}'..."
    sudo -u postgres psql -c "CREATE DATABASE ${DB_NAME};" >/dev/null
    log "Database created"
fi

# check if user already exists
USER_EXISTS=$(sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'")

if [ "$USER_EXISTS" = "1" ]; then
    log "User '${DB_USER}' already exists — updating password"
    sudo -u postgres psql -c "ALTER USER ${DB_USER} WITH PASSWORD '${DB_PASSWORD}';" >/dev/null
else
    info "Creating database user '${DB_USER}'..."
    sudo -u postgres psql -c "CREATE USER ${DB_USER} WITH PASSWORD '${DB_PASSWORD}';" >/dev/null
    log "User created"
fi

info "Granting privileges..."
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};" >/dev/null
sudo -u postgres psql -c "ALTER DATABASE ${DB_NAME} OWNER TO ${DB_USER};" >/dev/null
sudo -u postgres psql -d "${DB_NAME}" -c "GRANT ALL ON SCHEMA public TO ${DB_USER};" >/dev/null
log "Privileges granted"

# ─── DATABASE MIGRATIONS ──────────────────────────────────────────────────────

section "Database Migrations"

info "Running schema setup via FastAPI..."
cd "$INSTALL_DIR"
"$INSTALL_DIR/venv/bin/python" -c "
import sys
sys.path.insert(0, '.')
from backend.app.db import engine, Base
from backend.app.models import Agent, Job, Result
Base.metadata.create_all(bind=engine)
print('  Tables created/verified')
"

info "Applying column migrations..."
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" <<EOF
DO \$\$
BEGIN
    -- results.cleared
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='results' AND column_name='cleared'
    ) THEN
        ALTER TABLE results ADD COLUMN cleared BOOLEAN DEFAULT FALSE;
        RAISE NOTICE 'Added results.cleared';
    END IF;

    -- jobs.cleared
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='jobs' AND column_name='cleared'
    ) THEN
        ALTER TABLE jobs ADD COLUMN cleared BOOLEAN DEFAULT FALSE;
        RAISE NOTICE 'Added jobs.cleared';
    END IF;

    -- jobs.mode
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='jobs' AND column_name='mode'
    ) THEN
        ALTER TABLE jobs ADD COLUMN mode VARCHAR DEFAULT 'remote';
        RAISE NOTICE 'Added jobs.mode';
    END IF;

    -- jobs.profile
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='jobs' AND column_name='profile'
    ) THEN
        ALTER TABLE jobs ADD COLUMN profile VARCHAR DEFAULT 'standard';
        RAISE NOTICE 'Added jobs.profile';
    END IF;

    -- jobs.started_at
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='jobs' AND column_name='started_at'
    ) THEN
        ALTER TABLE jobs ADD COLUMN started_at TIMESTAMP;
        RAISE NOTICE 'Added jobs.started_at';
    END IF;

    -- jobs.completed_at
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='jobs' AND column_name='completed_at'
    ) THEN
        ALTER TABLE jobs ADD COLUMN completed_at TIMESTAMP;
        RAISE NOTICE 'Added jobs.completed_at';
    END IF;

    -- jobs.next_run_at
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='jobs' AND column_name='next_run_at'
    ) THEN
        ALTER TABLE jobs ADD COLUMN next_run_at TIMESTAMP;
        RAISE NOTICE 'Added jobs.next_run_at';
    END IF;

    -- jobs.port
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
        WHERE table_name='agents' AND column_name='is_stale'
    ) THEN
        ALTER TABLE agents ADD COLUMN is_stale BOOLEAN DEFAULT FALSE;
        RAISE NOTICE 'Added agents.is_stale';
    END IF;

    -- schedules table (created by SQLAlchemy on fresh installs, manual migration for upgrades)
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
    
    -- settings table
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

# Grant permissions on schedules table — must run outside DO block to access shell variable
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
    -c "GRANT ALL ON TABLE schedules TO ${DB_USER};" 2>/dev/null || true
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
    -c "GRANT USAGE, SELECT ON SEQUENCE schedules_id_seq TO ${DB_USER};" 2>/dev/null || true
PGPASSWORD="$DB_PASSWORD" psql ... -c "GRANT ALL ON TABLE settings TO ${DB_USER};"

log "Migrations complete"

# ─── SYSTEMD SERVICES ─────────────────────────────────────────────────────────

section "Systemd Services"

CURRENT_USER=$(whoami)
PYTHON_BIN="$INSTALL_DIR/venv/bin/python"
UVICORN_BIN="$INSTALL_DIR/venv/bin/uvicorn"

# Server service
cat > /tmp/vapt-server.service <<EOF
[Unit]
Description=Heimdall V-Scanner — Server
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=${CURRENT_USER}
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=${UVICORN_BIN} backend.app.main:app --host 0.0.0.0 --port 8000
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Scanner service
cat > /tmp/vapt-scanner.service <<EOF
[Unit]
Description=Heimdall V-Scanner — Remote Scanner
After=network.target vapt-server.service
Wants=vapt-server.service

[Service]
Type=simple
User=${CURRENT_USER}
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${ENV_FILE}
Environment=VAPT_AGENT_NAME=scanner-1
Environment=VAPT_SERVER_URL=http://127.0.0.1:8000
Environment=VAPT_CAPABILITIES=nmap_scan,nikto_scan,nse_scan
ExecStart=${PYTHON_BIN} ${INSTALL_DIR}/scanner.py
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

sudo mv /tmp/vapt-server.service /etc/systemd/system/vapt-server.service
sudo mv /tmp/vapt-scanner.service /etc/systemd/system/vapt-scanner.service
sudo systemctl daemon-reload

log "Service files installed"

read -rp "  Start and enable services now? [Y/n]: " start_services
if [[ ! "$start_services" =~ ^[Nn]$ ]]; then
    sudo systemctl enable vapt-server vapt-scanner -q
    sudo systemctl start vapt-server

    info "Waiting for server to start..."
    sleep 4

    if sudo systemctl is-active --quiet vapt-server; then
        log "vapt-server is running"
        sudo systemctl start vapt-scanner
        sleep 2
        if sudo systemctl is-active --quiet vapt-scanner; then
            log "vapt-scanner is running"
        else
            warn "vapt-scanner failed to start. Check: journalctl -u vapt-scanner -n 30"
        fi
    else
        warn "vapt-server failed to start. Check: journalctl -u vapt-server -n 30"
    fi
else
    info "Skipped. Start manually with:"
    info "  sudo systemctl start vapt-server vapt-scanner"
fi

# ─── FIREWALL ─────────────────────────────────────────────────────────────────

section "Firewall"

if command -v ufw >/dev/null 2>&1; then
    UFW_STATUS=$(sudo ufw status | head -1)
    if [[ "$UFW_STATUS" == *"active"* ]]; then
        read -rp "  UFW is active. Allow port 8000 for agents on the LAN? [Y/n]: " open_port
        if [[ ! "$open_port" =~ ^[Nn]$ ]]; then
            sudo ufw allow 8000/tcp >/dev/null
            log "Port 8000 allowed"
        fi
    else
        info "UFW is installed but not active — skipping firewall rule"
    fi
else
    info "UFW not found — skipping firewall configuration"
fi

# ─── DONE ─────────────────────────────────────────────────────────────────────

section "Installation Complete"

SERVER_IP=$(hostname -I | awk '{print $1}')

echo ""
echo -e "  ${BOLD}Dashboard:${NC}     http://${SERVER_IP}:8000/dashboard"
echo -e "  ${BOLD}Username:${NC}      ${DASHBOARD_USERNAME}"
echo -e "  ${BOLD}Logs:${NC}          journalctl -u vapt-server -f"
echo ""
echo -e "  ${BOLD}To run an agent on an endpoint:${NC}"
echo -e "  ${CYAN}VAPT_AGENT_NAME=pc-name VAPT_SERVER_URL=http://${SERVER_IP}:8000 python3 agent/agent.py${NC}"
echo ""
echo -e "  ${BOLD}Service commands:${NC}"
echo -e "  sudo systemctl status vapt-server"
echo -e "  sudo systemctl restart vapt-server"
echo -e "  journalctl -u vapt-server -f"
echo ""
