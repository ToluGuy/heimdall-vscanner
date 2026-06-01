# Heimdall V-Scanner

A distributed vulnerability assessment scanner built for internal office network use. Heimdall coordinates scan jobs across a central server and multiple remote agents, providing a unified dashboard for visibility into network vulnerabilities across the entire LAN.

## Architecture

Heimdall follows a server-agent model:

- **Backend server** — A FastAPI application that manages job queuing, agent registration, scheduling, and scan results. Backed by PostgreSQL.
- **Remote scanner** (`scanner.py`) — Runs on the central server alongside the backend. Handles agentless remote scans against targets that cannot run an agent directly, such as firewalls, switches, and printers.
- **Agent** (`agent/agent.py`) — Runs on any endpoint across the network. Polls the server for jobs and executes scans from that machine's network position.
- **Local scanner** (`agent/local_scanner.py`) — A fully standalone scan tool for any endpoint. Runs its own local web UI, requires no central server, and keeps results in memory for the session.
- **Dashboard** — A web interface served by the backend for creating jobs, monitoring agents, reviewing scan results, managing schedules, and generating reports.

---

## Legal

Heimdall V-Scanner is licensed under the [MIT License](LICENSE).

This tool is for use on networks and systems you own or have **explicit written authorisation** to test. Unauthorised scanning is illegal in most jurisdictions. By using this software you agree to the terms in [DISCLAIMER.md](DISCLAIMER.md).

---

## Scan Tools

Heimdall chains three tools together automatically:

- **Nmap** — Port discovery and service detection. Runs first on every scan.
- **Nikto** — Web vulnerability scanning. Triggered automatically when Nmap finds open web ports.
- **NSE (Nmap Scripting Engine)** — Vulnerability script scanning against non-web services (SSH, SMB, RDP, databases, etc.).

The dashboard uses plain language for scan types. The internal names (used in the API and database) are shown in brackets for reference.

---

## Scan Types

| Dashboard label | Internal name | Description |
|-----------------|---------------|-------------|
| Port Scan | `nmap_scan` | Discovers open ports; automatically runs a Web Scan on any web ports found |
| Web Scan | `nikto_scan` | Standalone web vulnerability scan against a specific port |
| Vulnerability Scan | `nse_scan` | Script-based vulnerability checks against non-web services; web ports are excluded |

## Scan Profiles

| Profile | Nmap flags | Web Scan flags | Vuln scripts | Description |
|---------|-----------|----------------|--------------|-------------|
| Light | `-F` | `-Tuning 1` | `safe` | Top 100 ports, fast, non-intrusive |
| Standard | `-sV` | default | `vuln` | Top 1000 ports with service detection |
| Full | `-sV -O -p-` | `-Tuning x6` | `vuln,exploit` ⚠️ | All ports, deep scan — exploit scripts are intrusive |

---

## Quick Install (Linux Server)

The installer handles everything: dependencies, database, environment config, and systemd services.

```bash
git clone https://github.com/ToluGuy/heimdall-vscanner.git
cd heimdall-vscanner
chmod +x install.sh
./install.sh
```

Run as a normal user with sudo access, not as root.

The installer will:
- Install system packages (nmap, nikto, postgresql, python3-venv)
- Create a Python virtual environment and install dependencies
- Prompt for dashboard credentials and database settings, then write `.env`
- Set up the PostgreSQL database, user, and all required permissions
- Run all schema migrations automatically
- Install and optionally start the `vapt-server` and `vapt-scanner` systemd services
- Open port 8000 in UFW if active

---

## Updating

When a new version is released, run the updater instead of reinstalling:

```bash
git pull
chmod +x update.sh
./update.sh
```

The updater pulls the latest code, updates Python dependencies, runs any new database migrations, and restarts the services. Your `.env`, existing scan data, and agent registrations are all preserved. The dashboard will be unavailable for a few seconds during the service restart.

If you installed without git (manual download), replace the project files manually, then run `./update.sh` to handle deps, migrations, and restarts.

---

## Manual Setup

If you prefer not to use the installer:

### 1. Clone the repository

```bash
git clone https://github.com/ToluGuy/heimdall-vscanner.git
cd heimdall-vscanner
```

### 2. Install system dependencies

```bash
sudo apt install nmap nikto postgresql python3-venv python3-pip
```

### 3. Create and activate a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 4. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 5. Set up PostgreSQL

```bash
sudo -u postgres psql
```

```sql
CREATE DATABASE vapt;
CREATE USER vapt_user WITH PASSWORD 'your-password';
GRANT ALL PRIVILEGES ON DATABASE vapt TO vapt_user;
ALTER DATABASE vapt OWNER TO vapt_user;
GRANT ALL ON SCHEMA public TO vapt_user;
\q
```

### 6. Configure environment variables

Create a `.env` file in the project root:

```
DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD=your-strong-password
DB_HOST=localhost
DB_PORT=5432
DB_NAME=vapt
DB_USER=vapt_user
DB_PASSWORD=your-password
```

### 7. Run database migrations

```bash
python3 -c "
from backend.app.db import engine, Base
from backend.app.models import Agent, Job, Result, DiscoverySweep, Schedule, Host, Setting
Base.metadata.create_all(bind=engine)
"
```

If upgrading from an earlier version, also run these SQL statements:

```sql
ALTER TABLE results ADD COLUMN IF NOT EXISTS cleared BOOLEAN DEFAULT FALSE;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS cleared BOOLEAN DEFAULT FALSE;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS mode VARCHAR DEFAULT 'remote';
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS profile VARCHAR DEFAULT 'standard';
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS started_at TIMESTAMP;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS completed_at TIMESTAMP;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS next_run_at TIMESTAMP;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS port INTEGER;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS ports VARCHAR;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS is_stale BOOLEAN DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS schedules (
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

CREATE TABLE IF NOT EXISTS settings (
    key   VARCHAR PRIMARY KEY,
    value VARCHAR NOT NULL
);

GRANT ALL ON TABLE schedules TO vapt_user;
GRANT ALL ON TABLE settings TO vapt_user;
GRANT USAGE, SELECT ON SEQUENCE schedules_id_seq TO vapt_user;
```

The `discovery_sweeps` and `hosts` tables are created automatically by SQLAlchemy on startup.

### 8. Start the server

```bash
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
```

The dashboard is available at `http://localhost:8000/dashboard`.

---

## Deployment (Production)

### Recommended setup

A dedicated Linux VM on whatever hypervisor you have available (ESXi, Proxmox, VirtualBox, etc.). The backend server and remote scanner both run on this VM. Agents run separately on individual endpoints.

**Minimum VM spec:**
- 2 vCPU, 2 GB RAM, 20 GB disk
- Ubuntu 22.04 or 24.04 LTS
- Static IP on the office LAN

### ESXi setup

1. Download the Ubuntu 24.04 LTS server ISO
2. In ESXi, create a new VM: 2 vCPU, 2 GB RAM, 20 GB thin-provisioned disk
3. Mount the ISO, install Ubuntu with OpenSSH enabled
4. Set a static IP via netplan:

```yaml
# /etc/netplan/00-installer-config.yaml
network:
  version: 2
  ethernets:
    ens160:
      addresses: [192.168.1.200/24]
      gateway4: 192.168.1.1
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
```

```bash
sudo netplan apply
```

5. SSH in and run the installer.

### Systemd services

The installer sets up two services automatically:

```bash
# Status
sudo systemctl status vapt-server
sudo systemctl status vapt-scanner

# Start / stop / restart
sudo systemctl start vapt-server vapt-scanner
sudo systemctl restart vapt-server vapt-scanner

# Enable on boot
sudo systemctl enable vapt-server vapt-scanner

# Live logs
journalctl -u vapt-server -f
journalctl -u vapt-scanner -f
```

### Network requirements

Port 8000 on the server must be reachable from the LAN for agents and browsers:

```bash
sudo ufw allow 8000/tcp
```

| Direction | From | To | Port | Purpose |
|-----------|------|----|------|---------|
| Outbound | Server/Scanner | Scan targets | any | Nmap, Nikto, NSE |
| Outbound | Agents | Server | 8000 | Job polling, heartbeat, results |
| Inbound | Browser | Server | 8000 | Dashboard access |

Agents only need outbound access to port 8000 on the server. They do not need to be reachable inbound.

---

## Dashboard

Access the dashboard at `/dashboard`. You will be prompted for credentials on first load.

From the dashboard you can:

- **Network Discovery** — Sweep a subnet in CIDR notation to find live hosts; review results before assigning scan jobs
- **Schedules** — Set up recurring scans on a configurable interval; pause, resume, or delete schedules at any time
- **Create Jobs** — Submit scan jobs manually for any IP, with control over scan type, profile, mode, and priority
- **Agents** — Monitor registered agents, their online/offline status, and last heartbeat; show or hide stale agents; restore or dismiss them
- **Jobs** — View the job queue with live elapsed timers on running jobs; filter by status; delete pending and failed jobs in bulk
- **Scan Results** — Expand results to view port tables, vulnerability findings, and web scan findings; toggle between active results and history
- **Insights** — Analytics dashboard showing scan activity over time, risk distribution, and per-host drilldowns
- **Topology** — Interactive D3 network map showing all discovered hosts, clustered by subnet, coloured by risk level
- **Reports** — Generate a printable HTML report for any scan result, exportable as PDF via the browser print dialog
- **Export** — Download scan results as structured JSON, individually or in bulk

---

## AI Analysis

Heimdall can automatically generate a risk assessment and remediation plan for each scan result using an AI provider of your choice. Add the following to your `.env`:

```
AI_PROVIDER=anthropic          # anthropic | openai | groq | ollama
AI_API_KEY=your-api-key
AI_MODEL=                      # optional — leave blank for the provider default
AI_BASE_URL=                   # only needed for ollama
AI_AUTO_ANALYSE=true           # set to false to trigger analysis manually per result
```

| Provider | Default model |
|----------|--------------|
| `anthropic` | claude-sonnet-4-5 |
| `openai` | gpt-4o-mini |
| `groq` | llama-3.3-70b-versatile |
| `ollama` | llama3 (local) |

AI analysis can also be toggled on/off at runtime from the Settings panel in the dashboard without restarting the server.

---

## Agents

For full agent setup instructions on both Linux and Windows endpoints, see [`agent/SETUP_GUIDE.md`](agent/SETUP_GUIDE.md).

### Quick start — Linux

```bash
cd agent/
pip install requests python-dotenv

VAPT_AGENT_NAME=office-pc-1 \
VAPT_SERVER_URL=http://192.168.1.200:8000 \
VAPT_CAPABILITIES=nmap_scan,nikto_scan,nse_scan \
python3 agent.py
```

### Quick start — Windows

Run `agent/setup_agent.ps1` as Administrator in PowerShell. It handles Python, Nmap, dependencies, configuration, and desktop shortcuts automatically.

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\agent\setup_agent.ps1
```

### Local scanner (any endpoint, no server required)

```bash
python3 agent/local_scanner.py
```

Opens a browser-based scan UI at `http://127.0.0.1:9731`. Supports Port Scans and Vulnerability Scans. Results live in memory for the session and can be exported as JSON before closing.

---

## Scheduling

Schedules are created from the dashboard and stored in the database. Each schedule defines a scan type, target, profile, mode, priority, and repeat interval in hours. The scheduler checks every 60 seconds for due schedules and creates the corresponding jobs automatically.

Schedules fire immediately on creation, then repeat at the configured interval. Resuming a paused schedule waits one full interval before firing again.

---

## Stale Agent Cleanup

Agents that have not sent a heartbeat within the configurable threshold (default 24 hours) are automatically flagged as stale by a background cleanup thread. Stale agents are hidden from the default agents view but can be shown via the "Show Stale" toggle. From there they can be restored or permanently dismissed.

The threshold can be adjusted from the Settings panel in the dashboard, or by setting `STALE_AGENT_HOURS` in `.env`.

---

## Priority Queue

Jobs support three priority levels: `high`, `medium`, and `low`. The dispatcher always picks the highest-priority eligible job first. Within the same priority, agent-specific jobs are preferred over any-agent jobs, and older jobs are picked before newer ones. Each agent handles at most 2 concurrent jobs.

---

## Project Structure

```
heimdall-vscanner/
├── agent/
│   ├── agent.py              # Endpoint agent — polls server, runs scans locally
│   ├── local_scanner.py      # Standalone scan tool with browser UI (no server needed)
│   ├── setup_agent.ps1       # Windows endpoint setup script
│   └── SETUP_GUIDE.md        # Agent and local scanner setup guide
├── backend/
│   └── app/
│       ├── main.py           # FastAPI server, all endpoints, dashboard HTML
│       ├── models.py         # SQLAlchemy database models
│       ├── schemas.py        # Pydantic request/response schemas
│       ├── db.py             # Database connection and session
│       ├── logger.py         # Logging configuration
│       └── ai_analysis.py    # AI-powered scan analysis (optional)
├── tools/
│   ├── check_db.py           # Database health check
│   ├── reset_stuck_jobs.py   # Unstick jobs that got stuck in 'running'
│   ├── purge_history.py      # Permanently delete archived scan history
│   ├── reset_db.py           # Wipe all scan data (dev/test use only)
│   ├── seed_test_jobs.py     # Create test jobs against localhost
│   ├── test_connection.py    # Verify agent-to-server connectivity
│   └── test_ports.py         # Open netcat listeners for scan testing
├── scanner.py                # Agentless remote scanner (runs on central server)
├── install.sh                # Automated Linux installer
├── update.sh                 # Lightweight updater for new releases
├── vapt-server.service       # Systemd service file — backend server
├── vapt-scanner.service      # Systemd service file — remote scanner
├── requirements.txt
├── .env                      # Not committed — created by installer or manually
└── logs/                     # Not committed — created at runtime
```

---

## Environment Variables

### Server

| Variable | Description | Default |
|----------|-------------|---------|
| `DASHBOARD_USERNAME` | Dashboard login username | `admin` |
| `DASHBOARD_PASSWORD` | Dashboard login password | `vapt-admin` |
| `DB_HOST` | PostgreSQL host | `localhost` |
| `DB_PORT` | PostgreSQL port | `5432` |
| `DB_NAME` | Database name | `vapt` |
| `DB_USER` | Database user | `vapt_user` |
| `DB_PASSWORD` | Database password | — |
| `STALE_AGENT_HOURS` | Hours before an agent is flagged stale | `24` |
| `AI_PROVIDER` | AI provider for scan analysis (`anthropic`, `openai`, `groq`, `ollama`) | — |
| `AI_API_KEY` | API key for the chosen AI provider | — |
| `AI_MODEL` | Model override — leave blank for provider default | — |
| `AI_BASE_URL` | Base URL for Ollama (e.g. `http://localhost:11434`) | — |
| `AI_AUTO_ANALYSE` | Auto-run AI analysis after each scan | `true` |

### Agent

| Variable | Description | Default |
|----------|-------------|---------|
| `VAPT_SERVER_URL` | URL of the backend server | `http://127.0.0.1:8000` |
| `VAPT_AGENT_NAME` | Name for this agent instance | `agent-default` |
| `VAPT_CAPABILITIES` | Comma-separated scan types this agent handles | `nmap_scan,nikto_scan,nse_scan` |
| `VAPT_KEY_FILE` | Path to store the agent API key | `{agent-name}_key.txt` |

---

## Troubleshooting

**Server won't start**
Check the logs: `journalctl -u vapt-server -n 50`. The most common causes are a bad `.env` file or PostgreSQL not running (`sudo systemctl status postgresql`).

**Agent shows offline in dashboard**
The heartbeat timeout is 30 seconds. If the agent hasn't sent a heartbeat within that window it shows offline. Confirm the agent is running and can reach the server on port 8000.

**Schedules fail with a permission error**
The `schedules` table was created without the database user having write access. Run as the postgres superuser:
```sql
GRANT ALL ON TABLE schedules TO vapt_user;
GRANT USAGE, SELECT ON SEQUENCE schedules_id_seq TO vapt_user;
```

**Web Scan (Nikto) hangs**
Caused by a CIRT.net update prompt in Nikto 2.6.x. The scanner suppresses it automatically with `input="n\n"`. If scans still hang, check Nikto is installed correctly with `nikto -Version`.

**Vulnerability Scan returns no findings**
Normal if the target has no non-web services running on discoverable ports. Vulnerability Scans deliberately skip web ports (80, 443, 8080, 8443, 8000, 8888) — use a Web Scan for web surface testing.

**Port 8000 unreachable from agents**
Check the server firewall: `sudo ufw status`. If active, run `sudo ufw allow 8000/tcp`.

**PostgreSQL permission errors on startup**
```sql
GRANT ALL ON SCHEMA public TO vapt_user;
ALTER DATABASE vapt OWNER TO vapt_user;
```

**AI analysis not appearing**
Check that `AI_PROVIDER` and `AI_API_KEY` are set in `.env` and that the server has been restarted. You can also trigger analysis manually from the dashboard by clicking "Analyse" on any result. Verify the setting is enabled in the Settings panel.

**Update broke something**
Each update only adds columns — it never drops or modifies existing ones. If something looks wrong after an update, check `journalctl -u vapt-server -n 50` for startup errors and compare your `.env` against the Environment Variables table above for any new required values.
