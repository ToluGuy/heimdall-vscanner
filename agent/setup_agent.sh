#!/usr/bin/env bash
# setup_agent.sh — Heimdall V-Scanner agent setup for Linux endpoints
#
# Run as a normal user with sudo access (not as root).
# Usage: bash setup_agent.sh
#
# What this does:
#   1. Installs Nmap and Nikto via apt (or yum/dnf on RHEL-based systems)
#   2. Creates a Python virtual environment at ~/vapt-agent/venv
#   3. Installs required Python packages (requests, python-dotenv)
#   4. Copies agent.py and local_scanner.py to ~/vapt-agent/
#   5. Prompts for agent name and server URL, writes a .env file
#   6. Optionally installs a systemd service so the agent starts on boot
#   7. Starts the agent

set -euo pipefail

AGENT_DIR="$HOME/vapt-agent"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_NAME="heimdall-agent"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

# ── helpers ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "  ${GREEN}✓${NC}  $*"; }
warn() { echo -e "  ${YELLOW}⚠${NC}  $*"; }
info() { echo -e "  ${CYAN}→${NC}  $*"; }
err()  { echo -e "  ${RED}✗${NC}  $*"; exit 1; }

confirm() {
    read -rp "  $1 [Y/n]: " ans
    ans="${ans:-y}"
    [[ "${ans,,}" == "y" ]]
}

echo ""
echo -e "  ${GREEN}Heimdall V-Scanner — Linux Agent Setup${NC}"
echo "  ─────────────────────────────────────────────────────"
echo ""

# ── 1. Detect package manager ──────────────────────────────────────────────────
if command -v apt-get &>/dev/null; then
    PKG_MGR="apt"
elif command -v dnf &>/dev/null; then
    PKG_MGR="dnf"
elif command -v yum &>/dev/null; then
    PKG_MGR="yum"
else
    warn "Could not detect a supported package manager (apt/dnf/yum)."
    warn "Please install nmap, nikto, python3, and python3-venv manually then re-run."
    PKG_MGR="none"
fi

# ── 2. Install system dependencies ────────────────────────────────────────────
if [[ "$PKG_MGR" != "none" ]]; then
    info "Updating package lists and installing dependencies..."
    case "$PKG_MGR" in
        apt)
            sudo apt-get update -qq
            sudo apt-get install -y -qq nmap nikto python3 python3-venv python3-pip
            ;;
        dnf|yum)
            sudo "$PKG_MGR" install -y -q nmap nikto python3 python3-pip
            ;;
    esac
    log "System packages installed"
else
    # Verify manually installed tools exist
    command -v nmap   &>/dev/null || warn "nmap not found — Open Port Scans will fail"
    command -v python3 &>/dev/null || err "python3 not found — cannot continue"
fi

# ── 3. Create install directory and virtual environment ────────────────────────
info "Setting up agent directory at $AGENT_DIR..."
mkdir -p "$AGENT_DIR"

if [[ ! -d "$AGENT_DIR/venv" ]]; then
    python3 -m venv "$AGENT_DIR/venv"
    log "Virtual environment created"
else
    log "Virtual environment already exists — skipping"
fi

# ── 4. Install Python dependencies ────────────────────────────────────────────
info "Installing Python packages..."
"$AGENT_DIR/venv/bin/pip" install -q --upgrade pip
"$AGENT_DIR/venv/bin/pip" install -q requests python-dotenv
log "Python packages installed"

# ── 5. Copy agent files ────────────────────────────────────────────────────────
info "Copying agent files..."
cp "$SCRIPT_DIR/agent.py"          "$AGENT_DIR/agent.py"
cp "$SCRIPT_DIR/local_scanner.py"  "$AGENT_DIR/local_scanner.py"
log "Files copied to $AGENT_DIR"

# ── 6. Configure the agent ────────────────────────────────────────────────────
echo ""
echo "  Configuration"
echo "  ─────────────"
echo ""

DEFAULT_NAME="${HOSTNAME:-$(hostname)}"
read -rp "  Agent name [${DEFAULT_NAME}]: " AGENT_NAME
AGENT_NAME="${AGENT_NAME:-$DEFAULT_NAME}"

read -rp "  Server URL [http://192.168.1.200:8000]: " SERVER_URL
SERVER_URL="${SERVER_URL:-http://192.168.1.200:8000}"

# Capabilities: skip nikto on systems where it's not installed
if command -v nikto &>/dev/null; then
    CAPABILITIES="nmap_scan,nikto_scan,nse_scan"
else
    CAPABILITIES="nmap_scan,nse_scan"
    warn "Nikto not found — setting capabilities to nmap_scan,nse_scan"
fi

# Write .env
ENV_FILE="$AGENT_DIR/.env"
cat > "$ENV_FILE" <<EOF
VAPT_AGENT_NAME=${AGENT_NAME}
VAPT_SERVER_URL=${SERVER_URL}
VAPT_CAPABILITIES=${CAPABILITIES}
VAPT_KEY_FILE=${AGENT_DIR}/${AGENT_NAME}_key.txt
EOF
log "Configuration written to $ENV_FILE"

# ── 7. Optionally install systemd service ─────────────────────────────────────
echo ""
INSTALL_SERVICE=false
if confirm "Install as a systemd service (starts automatically on boot)?"; then
    INSTALL_SERVICE=true
    PYTHON_BIN="$AGENT_DIR/venv/bin/python"

    sudo tee "$SERVICE_FILE" > /dev/null <<EOF
[Unit]
Description=Heimdall V-Scanner Agent — ${AGENT_NAME}
After=network.target

[Service]
Type=simple
User=${USER}
WorkingDirectory=${AGENT_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=${PYTHON_BIN} ${AGENT_DIR}/agent.py
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable "$SERVICE_NAME"
    sudo systemctl start  "$SERVICE_NAME"
    log "Service '${SERVICE_NAME}' installed, enabled, and started"
fi

# ── 8. Create a local scanner launcher ────────────────────────────────────────
LAUNCHER="$AGENT_DIR/run_local_scanner.sh"
cat > "$LAUNCHER" <<EOF
#!/usr/bin/env bash
# Runs the Heimdall local scanner (no server required)
source "$AGENT_DIR/.env" 2>/dev/null || true
"$AGENT_DIR/venv/bin/python" "$AGENT_DIR/local_scanner.py"
EOF
chmod +x "$LAUNCHER"
log "Local scanner launcher created at $LAUNCHER"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "  ${GREEN}Setup complete.${NC}"
echo ""

if $INSTALL_SERVICE; then
    echo "  The agent is now running as a systemd service."
    echo "  Monitor it with:  journalctl -u ${SERVICE_NAME} -f"
    echo "  Stop it with:     sudo systemctl stop ${SERVICE_NAME}"
else
    echo "  To start the agent manually:"
    echo ""
    echo -e "    ${CYAN}cd $AGENT_DIR && source .env && ./venv/bin/python agent.py${NC}"
    echo ""
fi

echo "  To run the local scanner (no server required):"
echo -e "    ${CYAN}$LAUNCHER${NC}"
echo ""
echo "  The agent will appear in the Heimdall dashboard once it connects."
echo "  If it shows a Setup ⚠ button, the agent has registered but not yet checked in — this is normal on first start."
echo ""
