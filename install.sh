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

    # ── DB host: validate it looks like a hostname or IP, not a path or nonsense ──
    while true; do
        read -rp "  Database host [localhost]: " DB_HOST
        DB_HOST="${DB_HOST:-localhost}"
        # Accept: localhost, plain hostnames, IPv4 addresses, IPv6 in brackets
        if [[ "$DB_HOST" =~ ^[a-zA-Z0-9._:-]+$ ]]; then
            break
        else
            warn "  '${DB_HOST}' doesn't look like a valid hostname or IP address."
            warn "  Use 'localhost', a hostname like 'db.local', or an IP like '192.168.1.10'."
        fi
    done

    read -rp "  Database port [5432]: " DB_PORT
    DB_PORT="${DB_PORT:-5432}"
    # Validate port is numeric
    if ! [[ "$DB_PORT" =~ ^[0-9]+$ ]]; then
        warn "Invalid port '${DB_PORT}', defaulting to 5432"
        DB_PORT="5432"
    fi

    read -rp "  Database name [vapt]: " DB_NAME
    DB_NAME="${DB_NAME:-vapt}"

    read -rp "  Database user [vapt_user]: " DB_USER
    DB_USER="${DB_USER:-vapt_user}"

    read -rsp "  Database password: " DB_PASSWORD
    echo ""
    
    if [ -z "$DB_PASSWORD" ]; then
        DB_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(20))")
        warn "No password entered. Generated: $DB_PASSWORD"
        warn "Save this — it will be written to .env and used for PostgreSQL."
    fi

    # Write .env using printf to avoid heredoc bash interpolation of special chars
    {
        printf 'DASHBOARD_USERNAME=%s\n' "$DASHBOARD_USERNAME"
        printf 'DASHBOARD_PASSWORD=%s\n' "$DASHBOARD_PASSWORD"
        printf 'DB_HOST=%s\n'            "$DB_HOST"
        printf 'DB_PORT=%s\n'            "$DB_PORT"
        printf 'DB_NAME=%s\n'            "$DB_NAME"
        printf 'DB_USER=%s\n'            "$DB_USER"
        printf 'DB_PASSWORD=%s\n'        "$DB_PASSWORD"
        printf 'VAPT_SERVER_URL=%s\n'    "http://127.0.0.1:8000"
    } > "$ENV_FILE"

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

info "Running schema setup via SQLAlchemy..."
cd "$INSTALL_DIR"
"$INSTALL_DIR/venv/bin/python" -c "
import sys
sys.path.insert(0, '.')
from backend.app.db import engine, Base
from backend.app.models import Agent, Job, Result, DiscoverySweep, Schedule, Host, Setting
Base.metadata.create_all(bind=engine)
print('  Tables created/verified')
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
        WHERE table_name='jobs' AND column_name='sweep_id'
    ) THEN
        ALTER TABLE jobs ADD COLUMN sweep_id INTEGER REFERENCES discovery_sweeps(id) ON DELETE SET NULL;
        RAISE NOTICE 'Added jobs.sweep_id';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='jobs' AND column_name='nikto_tuning'
    ) THEN
        ALTER TABLE jobs ADD COLUMN nikto_tuning VARCHAR;
        RAISE NOTICE 'Added jobs.nikto_tuning';
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

# Grant permissions on tables and sequences — must run outside DO block
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
    -c "GRANT ALL ON TABLE schedules TO ${DB_USER};" 2>/dev/null || true
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
    -c "GRANT USAGE, SELECT ON SEQUENCE schedules_id_seq TO ${DB_USER};" 2>/dev/null || true
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
    -c "GRANT ALL ON TABLE settings TO ${DB_USER};" 2>/dev/null || true

log "Migrations complete"

# ─── SYSTEMD SERVICES ─────────────────────────────────────────────────────────

section "Systemd Services"

CURRENT_USER=$(whoami)
PYTHON_BIN="$INSTALL_DIR/venv/bin/python"
UVICORN_BIN="$INSTALL_DIR/venv/bin/uvicorn"

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
Environment=VAPT_AGENT_NAME=scanner-default
Environment=VAPT_SERVER_URL=http://127.0.0.1:8000
Environment=VAPT_CAPABILITIES=nmap_scan,nikto_scan,nse_scan
ExecStart=${PYTHON_BIN} ${INSTALL_DIR}/backend/app/scanner.py
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

# ── Sudoers rule for scanner auto-spawn ──────────────────────────────────────
SUDOERS_FILE="/etc/sudoers.d/vapt-scanner-spawn"
cat > /tmp/vapt-sudoers <<EOF
# Heimdall V-Scanner — scanner auto-spawn permissions
${CURRENT_USER} ALL=(ALL) NOPASSWD: /usr/bin/systemctl start vapt-scanner-*
${CURRENT_USER} ALL=(ALL) NOPASSWD: /usr/bin/systemctl stop vapt-scanner-*
${CURRENT_USER} ALL=(ALL) NOPASSWD: /usr/bin/systemctl enable vapt-scanner-*
${CURRENT_USER} ALL=(ALL) NOPASSWD: /usr/bin/systemctl disable vapt-scanner-*
${CURRENT_USER} ALL=(ALL) NOPASSWD: /usr/bin/systemctl daemon-reload
${CURRENT_USER} ALL=(ALL) NOPASSWD: /usr/bin/mv /tmp/vapt-scanner-*.service /etc/systemd/system/
${CURRENT_USER} ALL=(ALL) NOPASSWD: /usr/bin/rm -f /etc/systemd/system/vapt-scanner-*.service
EOF
if visudo -c -f /tmp/vapt-sudoers 2>/dev/null; then
    sudo mv /tmp/vapt-sudoers "$SUDOERS_FILE"
    sudo chmod 440 "$SUDOERS_FILE"
    log "Sudoers rule installed — dashboard can auto-spawn scanner instances"
    if ! grep -q "SCANNER_AUTOSTART" "$ENV_FILE"; then
        echo "SCANNER_AUTOSTART=true" >> "$ENV_FILE"
    fi
else
    warn "Could not install sudoers rule — scanner auto-spawn will require manual setup"
    rm -f /tmp/vapt-sudoers
fi

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

SERVER_IP=$(hostname -I | awk '{print $1}')
DASHBOARD_URL="http://${SERVER_IP}:8000/dashboard"

echo ""
echo -e "${BOLD}${GREEN}"
echo "  ╔══════════════════════════════════════════════════════════╗"
echo "  ║           Heimdall V-Scanner — Setup Complete            ║"
echo "  ╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "  ${BOLD}${GREEN}Your dashboard is ready.${NC}"
echo ""
echo -e "  ${BOLD}${CYAN}  ➜  ${DASHBOARD_URL}${NC}"
echo ""
echo -e "  ${BOLD}Credentials:${NC}"
echo -e "  Username : ${DASHBOARD_USERNAME}"
echo -e "  Password : (the dashboard password you set)"
echo ""
echo -e "  ${BOLD}Quick reference:${NC}"
echo -e "  Logs     : journalctl -u vapt-server -f"
echo -e "  Restart  : sudo systemctl restart vapt-server vapt-scanner"
echo ""
echo -e "  ${BOLD}To update in future:${NC}"
echo -e "  ${CYAN}./update.sh${NC}"
echo ""
echo -e "  ${BOLD}To run an agent on any endpoint:${NC}"
echo -e "  ${CYAN}VAPT_AGENT_NAME=office-pc-1 VAPT_SERVER_URL=http://${SERVER_IP}:8000 python3 agent/agent.py${NC}"
echo ""
echo -e "  ${YELLOW}If the dashboard isn't reachable, check the firewall:${NC}"
echo -e "  sudo ufw allow 8000/tcp"
echo ""


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

    # ── Dashboard password ────────────────────────────────────────────────────
    read -rsp "  Dashboard password [vapt-admin]: " DASHBOARD_PASSWORD
    echo ""
    if [ -z "$DASHBOARD_PASSWORD" ]; then
        # User pressed Enter — offer a generated password instead of the weak default
        echo ""
        read -rp "  $(echo -e "${CYAN}[→]${NC}") Use 'vapt-admin' as your dashboard password, or generate a strong one? [G=generate / Enter=keep default]: " _dash_choice
        if [[ "$_dash_choice" =~ ^[Gg]$ ]]; then
            DASHBOARD_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(20))")
            echo ""
            log "Generated dashboard password: ${BOLD}${DASHBOARD_PASSWORD}${NC}"
            warn "Save this now — it won't be shown again."
            echo ""
        else
            DASHBOARD_PASSWORD="vapt-admin"
            warn "Using default password 'vapt-admin' — change this after setup."
        fi
    fi

    # ── DB host: validate it looks like a hostname or IP ──────────────────────
    while true; do
        read -rp "  Database host [localhost]: " DB_HOST
        DB_HOST="${DB_HOST:-localhost}"
        if [[ "$DB_HOST" =~ ^[a-zA-Z0-9._:-]+$ ]]; then
            break
        else
            warn "  '${DB_HOST}' doesn't look like a valid hostname or IP address."
            warn "  Use 'localhost', a hostname like 'db.local', or an IP like '192.168.1.10'."
        fi
    done

    read -rp "  Database port [5432]: " DB_PORT
    DB_PORT="${DB_PORT:-5432}"
    if ! [[ "$DB_PORT" =~ ^[0-9]+$ ]]; then
        warn "Invalid port '${DB_PORT}', defaulting to 5432"
        DB_PORT="5432"
    fi

    read -rp "  Database name [vapt]: " DB_NAME
    DB_NAME="${DB_NAME:-vapt}"

    read -rp "  Database user [vapt_user]: " DB_USER
    DB_USER="${DB_USER:-vapt_user}"

    # ── Database password ─────────────────────────────────────────────────────
    read -rsp "  Database password (Enter to generate one): " DB_PASSWORD
    echo ""
    if [ -z "$DB_PASSWORD" ]; then
        # User pressed Enter — offer generated or confirm they want to set one manually
        echo ""
        read -rp "  $(echo -e "${CYAN}[→]${NC}") Generate a strong database password automatically? [Y/n]: " _db_choice
        if [[ ! "$_db_choice" =~ ^[Nn]$ ]]; then
            DB_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(20))")
            echo ""
            log "Generated database password: ${BOLD}${DB_PASSWORD}${NC}"
            warn "Save this now — it will be stored in .env but won't be shown again."
            echo ""
        else
            # They said no to generated — ask them to type one
            while [ -z "$DB_PASSWORD" ]; do
                read -rsp "  Enter a database password: " DB_PASSWORD
                echo ""
                if [ -z "$DB_PASSWORD" ]; then
                    warn "Password cannot be empty. Please enter a password."
                fi
            done
        fi
    fi

    # Write .env using printf to avoid heredoc bash interpolation of special chars
    {
        printf 'DASHBOARD_USERNAME=%s\n' "$DASHBOARD_USERNAME"
        printf 'DASHBOARD_PASSWORD=%s\n' "$DASHBOARD_PASSWORD"
        printf 'DB_HOST=%s\n'            "$DB_HOST"
        printf 'DB_PORT=%s\n'            "$DB_PORT"
        printf 'DB_NAME=%s\n'            "$DB_NAME"
        printf 'DB_USER=%s\n'            "$DB_USER"
        printf 'DB_PASSWORD=%s\n'        "$DB_PASSWORD"
        printf 'VAPT_SERVER_URL=%s\n'    "http://127.0.0.1:8000"
    } > "$ENV_FILE"

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

info "Running schema setup via SQLAlchemy..."
cd "$INSTALL_DIR"
"$INSTALL_DIR/venv/bin/python" -c "
import sys
sys.path.insert(0, '.')
from backend.app.db import engine, Base
from backend.app.models import Agent, Job, Result, DiscoverySweep, Schedule, Host, Setting
Base.metadata.create_all(bind=engine)
print('  Tables created/verified')
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

# Grant permissions on tables and sequences — must run outside DO block
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
    -c "GRANT ALL ON TABLE schedules TO ${DB_USER};" 2>/dev/null || true
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
    -c "GRANT USAGE, SELECT ON SEQUENCE schedules_id_seq TO ${DB_USER};" 2>/dev/null || true
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
    -c "GRANT ALL ON TABLE settings TO ${DB_USER};" 2>/dev/null || true

log "Migrations complete"

# ─── SYSTEMD SERVICES ─────────────────────────────────────────────────────────

section "Systemd Services"

CURRENT_USER=$(whoami)
PYTHON_BIN="$INSTALL_DIR/venv/bin/python"
UVICORN_BIN="$INSTALL_DIR/venv/bin/uvicorn"

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
Environment=VAPT_AGENT_NAME=scanner-default
Environment=VAPT_SERVER_URL=http://127.0.0.1:8000
Environment=VAPT_CAPABILITIES=nmap_scan,nikto_scan,nse_scan
ExecStart=${PYTHON_BIN} ${INSTALL_DIR}/backend/app/scanner.py
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

SERVER_IP=$(hostname -I | awk '{print $1}')
DASHBOARD_URL="http://${SERVER_IP}:8000/dashboard"

echo ""
echo -e "${BOLD}${GREEN}"
echo "  ╔══════════════════════════════════════════════════════════╗"
echo "  ║           Heimdall V-Scanner — Setup Complete            ║"
echo "  ╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "  ${BOLD}${GREEN}Your dashboard is ready.${NC}"
echo ""
echo -e "  ${BOLD}${CYAN}  ➜  ${DASHBOARD_URL}${NC}"
echo ""
echo -e "  ${BOLD}Credentials:${NC}"
echo -e "  Username : ${DASHBOARD_USERNAME}"
echo -e "  Password : (the dashboard password you set)"
echo ""
echo -e "  ${BOLD}Quick reference:${NC}"
echo -e "  Logs     : journalctl -u vapt-server -f"
echo -e "  Restart  : sudo systemctl restart vapt-server vapt-scanner"
echo ""
echo -e "  ${BOLD}To update in future:${NC}"
echo -e "  ${CYAN}./update.sh${NC}"
echo ""
echo -e "  ${BOLD}To run an agent on any endpoint:${NC}"
echo -e "  ${CYAN}VAPT_AGENT_NAME=office-pc-1 VAPT_SERVER_URL=http://${SERVER_IP}:8000 python3 agent/agent.py${NC}"
echo ""
echo -e "  ${YELLOW}If the dashboard isn't reachable, check the firewall:${NC}"
echo -e "  sudo ufw allow 8000/tcp"
echo ""
