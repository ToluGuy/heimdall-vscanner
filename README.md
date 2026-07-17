# Heimdall V-Scanner

A distributed vulnerability assessment scanner built for internal office network use. Heimdall coordinates scan jobs across a central server and multiple remote agents, providing a unified dashboard for visibility into network vulnerabilities across the entire LAN.

## Architecture

Heimdall follows a server-agent model:

- **Backend server** — A FastAPI application that manages job queuing, agent registration, scheduling, and scan results. Backed by PostgreSQL.
- **Remote scanner** (`scanner.py`) — Runs on the central server alongside the backend. Handles agentless remote scans against targets that cannot run an agent directly, such as firewalls, switches, and printers.
- **Agent** (`agent/agent.py`) — Runs on any endpoint across the network. Polls the server for jobs and executes scans from that machine's network position.
- **Local scanner** (`agent/local_scanner.py`) — A fully standalone scan tool for any endpoint. Runs its own local web UI, requires no central server, and keeps results in memory for the session.
- **Dashboard** — A web interface served by the backend for creating jobs, monitoring agents, reviewing scan results, managing schedules, and generating reports.
- **Plugins** — An extension mechanism for adding scan types beyond the built-in three, without modifying Heimdall's own code. See [Plugins](#plugins) below.

---

## Legal

Heimdall V-Scanner is licensed under the [MIT License](LICENSE).

This tool is for use on networks and systems you own or have **explicit written authorisation** to test. Unauthorised scanning is illegal in most jurisdictions. By using this software you agree to the terms in [DISCLAIMER.md](DISCLAIMER.md).

---

## Scan Tools

Heimdall chains three tools together automatically:

- **Nmap** — Port discovery and service detection. Runs first on every scan.
- **Nikto** — Web vulnerability scanning. Triggered automatically when Nmap finds open web ports.
- **NSE (Nmap Scripting Engine)** — Vulnerability script scanning against discovered services.

The dashboard uses plain language for scan types. The internal names (used in the API and database) are shown in brackets for reference.

---

## Scan Types

| Dashboard label | Internal name | Description |
|-----------------|---------------|-------------|
| Open Port Scan | `nmap_scan` | Discovers open ports and services. If web ports (80, 443, 8080, etc.) are found, Nikto runs automatically on each one before the job completes. This can be disabled from the Settings panel if you want faster port scans without the web scan overhead. |
| Web Scan | `nikto_scan` | Standalone web vulnerability scan against a specific port. The target field accepts an IP, hostname, or full URL. |
| Vulnerability Scan | `nse_scan` | Script-based vulnerability checks against discovered services. Web ports are included — a blue advisory is shown in the result if web ports are scanned, suggesting a dedicated Web Scan for deeper coverage. |

## Scan Profiles

| Profile | Nmap flags | Web Scan flags | Vuln scripts | Description |
|---------|-----------|----------------|--------------|-------------|
| Light | `-F` | `-Tuning 1` | `safe` | Top 100 ports, fast, non-intrusive |
| Standard | `-sV` | default | `vuln` | Top 1000 ports with service detection |
| Full | `-sV -O -p-` | `-Tuning x6` | `vuln,exploit` ⚠️ | All ports, deep scan — exploit scripts are intrusive |
| Custom | user-defined | user-defined | user-defined | Select individual NSE scripts (Vulnerability Scan) or Nikto test categories (Web Scan) from the capability cards in the dashboard |

---

## Network Discovery (Sweep)

The Network Discovery tab lets you sweep a subnet in CIDR notation (e.g. `192.168.1.0/24`) to find live hosts before assigning scan jobs.

- **Ping** — Fast host discovery with no job creation. Use it to preview what's on the network before committing to a full sweep.
- **Sweep** — Full discovery that creates an Open Port Scan job for every live host found. Once a sweep is running, a **Cancel Sweep** button appears in the status bar — clicking it stops job creation even if Nmap has already finished scanning.
- **Sweep history** — All completed sweeps are listed with host and job counts. Click **View Results** on any completed sweep to see a host-by-host summary of port findings and vulnerability counts, with a direct link to jump to each individual result card.

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
from backend.app.models import Agent, Job, Result, DiscoverySweep, Schedule, Host, Setting, Plugin, TargetAuthorization
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
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS custom_scripts VARCHAR;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS nikto_tuning VARCHAR;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS extra_params TEXT;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS sweep_id INTEGER REFERENCES discovery_sweeps(id) ON DELETE SET NULL;
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

- **Network Discovery** — Sweep a subnet in CIDR notation to find live hosts; ping first to preview, then sweep to create jobs. Cancel a running sweep at any time from the status bar. View grouped results per sweep showing all hosts, ports, and findings in one place.
- **Schedules** — Set up recurring scans on a configurable interval; pause, resume, or delete schedules at any time
- **Create Jobs** — Submit scan jobs manually for any IP, hostname, or URL; control scan type, profile, mode, and priority. Select the Custom profile to choose individual NSE scripts or Nikto test categories.
- **Agents** — Monitor registered agents and scanners, their online/offline status, capabilities, and last heartbeat. Register new scanner instances directly from the dashboard with the **+ Register Scanner** button — generates an API key and ready-to-use setup commands and systemd service file. Click **Setup** on any existing agent to retrieve its setup commands again. Show or hide stale agents; restore or dismiss them.
- **Jobs** — View the job queue with live elapsed timers on running jobs; filter by status; delete pending and failed jobs in bulk. All tabs are paginated — use the navigation bar at the bottom of each panel to move between pages or change the number of items shown (10 / 20 / 50).
- **Scan Results** — Expand results to view port tables, vulnerability findings, and web scan findings; toggle between active results and history. Results are paginated (10 per page by default).
- **Insights** — Analytics dashboard showing scan activity over time, risk distribution, and per-host drilldowns
- **Topology** — Interactive D3 network map showing all discovered hosts, clustered by subnet, coloured by risk level
- **Loki** — Penetration testing tools (fuzzing, fingerprinting, injection testing, credential attacks), installed as plugins. Only appears once at least one is installed. See [Loki](#loki-penetration-testing-experimental) below.
- **Reports** — Generate a printable HTML report for any scan result, exportable as PDF via the browser print dialog
- **Export** — Download scan results as structured JSON, individually or in bulk
- **Settings** — Toggle AI auto-analysis and the auto-Nikto web scan on/off at runtime; configure the stale agent threshold

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

Opens a browser-based scan UI at `http://127.0.0.1:9731`. Supports Open Port Scans and Vulnerability Scans. Results live in memory for the session and can be exported as JSON before closing.

---

## Scheduling

Schedules are created from the dashboard and stored in the database. Each schedule defines a scan type, target, profile, mode, priority, and repeat interval in hours. The scheduler checks every 60 seconds for due schedules and creates the corresponding jobs automatically.

Schedules fire immediately on creation, then repeat at the configured interval. Resuming a paused schedule waits one full interval before firing again.

---

## Stale Agent Cleanup

Agents that have not sent a heartbeat within the configurable threshold (default 24 hours) are automatically flagged as stale by a background cleanup thread. Stale agents are hidden from the default agents view but can be shown via the "Show Stale" toggle. From there they can be restored or permanently dismissed.

When an agent comes back online and sends a heartbeat, its stale flag is automatically cleared — it returns to the active agents list without any manual intervention.

The threshold can be adjusted from the Settings panel in the dashboard, or by setting `STALE_AGENT_HOURS` in `.env`.

---

## Priority Queue

Jobs support three priority levels: `high`, `medium`, and `low`. The dispatcher always picks the highest-priority eligible job first. Within the same priority, agent-specific jobs are preferred over any-agent jobs, and older jobs are picked before newer ones. Each agent handles at most 2 concurrent jobs.

---

## Plugins

Heimdall's built-in scan types (Open Port Scan, Web Scan, Vulnerability Scan) cover general-purpose scanning. Plugins extend this with additional scan types — without ever modifying Heimdall's own code, and without the server ever transmitting or executing code it didn't already have.

A plugin has two independent parts, and both matter:

1. **Manifest registration** — a `plugin.json` describing the scan type: its name, risk tier, dashboard tab/section, and input fields. Registered through **Settings → Plugins** (paste or upload the file) or `POST /plugins/install`. This is metadata only — it doesn't run anything.
2. **Code deployment** — the plugin's `run.py`, containing the actual scan logic. This has to be placed by hand onto whichever scanner or agent should run it, using `install_plugin.sh`. Nothing on the server side ever pushes this automatically — that's deliberate.

A job type only becomes usable once both steps are done. Registering the manifest without deploying the code makes it visible in the dashboard but any job of that type will fail when it runs (the machine doesn't have the code); deploying the code without registering the manifest means the server never offers it as an option in the first place.

### Risk tiers

| Tier | Meaning |
|------|---------|
| `none` | No real risk — informational only |
| `read_only` | Passive, doesn't send anything unusual to the target |
| `intrusive` | Sends probing/active traffic to the target (can trip WAFs, rate limits, or alerting) — shown with a warning, no extra gate |
| `high` | Actively attacks the target (credential attacks, exploitation) — requires a live, time-boxed **target authorization** before the job can even be created |

A `high`-tier job type is rejected outright at creation unless there's an active authorization for that specific target *and* job type. Authorizations are granted from the dashboard, expire automatically, and are capped at a maximum duration set in Settings.

### Installing and uninstalling

```bash
cd plugins/
./install_plugin.sh <plugin_source_dir> <job_type> <scanner:NAME|agent>
./uninstall_plugin.sh <job_type> <scanner:NAME|agent>
```

`install_plugin.sh` copies the plugin's code onto this machine (`backend/app/installed_plugins/<job_type>/` for a scanner, `agent/installed_plugins/<job_type>/` for an agent), updates that scanner/agent's advertised capabilities, and restarts the relevant systemd service if one exists. `uninstall_plugin.sh` is the reverse — removes the code and drops the capability.

Both scripts locate the repo root relative to their own file location (one level up, since they live in `plugins/`), not your current directory — they work the same whether you run `./install_plugin.sh ...` from inside `plugins/` or `plugins/install_plugin.sh ...` from the repo root. **If you move either script, that assumption is what needs updating.**

Uninstalling is two separate steps, matching the two-part install:

```bash
# 1. Remove the code from this machine
./uninstall_plugin.sh ffuf_scan scanner:scanner-default

# 2. Remove the manifest registration (cancels any pending jobs of that type)
#    — do this from Settings → Plugins, or:
curl -X DELETE http://localhost:8000/plugins/ffuf_scan
```

Doing only the first leaves the job type registered with no code backing it on that particular machine — harmless, but pointless. Doing only the second leaves orphaned code on disk that nothing will ever call.

### Two `plugins/` directories — this is intentional

- **`plugins/`** at the repo root is the *source* — install_plugin.sh, uninstall_plugin.sh, and a ready-to-deploy copy of each first-party plugin (`plugins/ffuf/`, `plugins/whatweb/`, etc). This is what's committed to the repo.
- **`backend/app/installed_plugins/`** and **`agent/installed_plugins/`** are *deployment targets* — where `install_plugin.sh` copies a plugin's code once you actually enable it on a specific machine. These are per-machine artifacts, not source, and shouldn't be committed — see `.gitignore` below.

The one exception is `backend/app/installed_plugins/hooks/`, which ships pre-installed (it's how webhook notifications work out of the box) rather than requiring a manual install step.

```gitignore
# Locally-deployed plugin code — per-machine artifacts, not source.
# Only hooks/ and asset_inventory_scan/ ship pre-installed with the repo.
backend/app/installed_plugins/*
!backend/app/installed_plugins/hooks/
!backend/app/installed_plugins/asset_inventory_scan/
agent/installed_plugins/*
```

If a plugin folder under `backend/app/installed_plugins/` or `agent/installed_plugins/` was already committed before adding this, the `.gitignore` entry alone won't untrack it — you'll also need `git rm -r --cached <path>` once, after which it'll be ignored normally.

### Hooks

Plugins can also register for lifecycle events (`job.completed`, `job.failed`, `host.new`) rather than adding a scan type — the webhook notifications plugin (`backend/app/installed_plugins/hooks/webhook/`) is the built-in example, and ships pre-installed.

---

## Loki (Penetration Testing, Experimental)

Loki is Heimdall's penetration testing suite — a materially more invasive category of tooling than the default scan types, kept in its own dedicated dashboard destination rather than mixed in with routine scanning. It only appears once at least one Loki-tagged plugin is installed.

**This is new and not yet validated against real targets in production use — treat findings as a starting point to verify, not as ground truth, until it's been run against something real for a while.**

| Tool | Job type | Risk tier | What it does |
|------|----------|-----------|---------------|
| ffuf | `ffuf_scan` | `intrusive` | Directory/file fuzzing against a web target |
| WhatWeb | `whatweb_scan` | `intrusive` | Web technology fingerprinting |
| sqlmap | `sqlmap_scan` | `intrusive` | SQL injection **detection only** — never enumerates databases or dumps data |
| Hydra | `hydra_scan` | `high` | Credential brute-force against a live service — requires target authorization |

Each ships as a separate plugin under `plugins/` (`ffuf/`, `whatweb/`, `sqlmap/`, `hydra/`), so you can install only the ones you want. Every plugin folder includes:

- `plugin.json` / `run.py` — the manifest and scan logic
- `setup.sh` — an explicit, admin-run helper to install the underlying tool (e.g. `apt-get install ffuf`) and any dependency like a wordlist. **Never called automatically by `run.py` or anything else** — installing system packages or fetching wordlists is something you run by hand.
- `NOTES.md` — scope decisions and any caveats on how confident the output parsing is

---

## Project Structure

```
heimdall-vscanner/
├── agent/
│   ├── agent.py              # Endpoint agent — polls server, runs scans locally
│   ├── local_scanner.py      # Standalone scan tool with browser UI (no server needed)
│   ├── setup_agent.ps1       # Windows endpoint setup script
│   ├── SETUP_GUIDE.md        # Agent and local scanner setup guide
│   └── installed_plugins/    # Deployed agent-side plugin code, per-machine
├── backend/
│   └── app/
│       ├── main.py           # FastAPI app assembly only — routes live in routes/
│       ├── core.py           # Job type registry, risk tiers, settings defaults
│       ├── models.py         # SQLAlchemy database models
│       ├── schemas.py        # Pydantic request/response schemas
│       ├── db.py             # Database connection and session
│       ├── logger.py         # Logging configuration
│       ├── ai_analysis.py    # AI-powered scan analysis (optional)
│       ├── scanner.py        # Agentless remote scanner (runs alongside the backend)
│       ├── routes/           # One module per resource — agents, jobs, results, hosts,
│       │                     # schedules, discovery, reports, insights, topology,
│       │                     # settings, dashboard, plugins, authorizations
│       ├── services/
│       │   ├── scheduler.py  # Recurring schedule dispatch
│       │   └── hooks.py      # Fires job.completed/job.failed/host.new to plugins
│       ├── installed_plugins/ # Deployed scanner-side plugin code
│       │   ├── hooks/webhook/          # Ships pre-installed (not gitignored)
│       │   ├── asset_inventory_scan/   # Ships pre-installed (not gitignored)
│       │   └── ...                     # Everything else here is gitignored —
│       │                                # per-machine, deployed via install_plugin.sh
│       └── static/
│           ├── index.html    # Dashboard markup
│           ├── app.js        # Dashboard logic
│           ├── app.css       # Theme (dark + light)
│           └── favicon.svg
├── plugins/                   # Plugin SOURCE
│   ├── install_plugin.sh     # Deploys a plugin's code onto a scanner/agent
│   ├── uninstall_plugin.sh   # Removes it again
│   ├── asset_inventory/
│   ├── ffuf/                 # Loki: directory/file fuzzing
│   ├── whatweb/               # Loki: technology fingerprinting
│   ├── sqlmap/                 # Loki: SQL injection detection
│   └── hydra/                   # Loki: credential brute-force (high risk tier)
├── tools/
│   ├── check_db.py           # Database health check
│   ├── reset_stuck_jobs.py   # Unstick jobs that got stuck in 'running'
│   ├── purge_history.py      # Permanently delete archived scan history
│   ├── reset_db.py           # Wipe all scan data (dev/test use only)
│   ├── seed_test_jobs.py     # Create test jobs against localhost
│   ├── test_connection.py    # Verify agent-to-server connectivity
│   └── test_ports.py         # Open netcat listeners for scan testing
├── install.sh                # Automated Linux installer
├── update.sh                 # Lightweight updater for new releases
├── vapt-server.service       # Systemd service file — backend server
├── vapt-scanner.service      # Systemd service file — remote scanner
├── requirements.txt
├── .env                      # created by installer or manually
└── logs/                     # created at runtime
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
| `VAPT_REGISTRATION_TOKEN` | Optional shared secret required from agents/scanners at `/agents/register`. Leave unset to keep registration open (the original behaviour). If set here, the same value must be set on every agent and scanner. | — |
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
| `VAPT_REGISTRATION_TOKEN` | Shared secret sent when registering — only required if the server has `VAPT_REGISTRATION_TOKEN` set | — |

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
Normal if the target has no vulnerable services running on discoverable ports. If you were expecting web findings, note that Vulnerability Scan will include web ports but a dedicated Web Scan will give deeper coverage — this is shown as a blue advisory in the result.

**Port 8000 unreachable from agents**
Check the server firewall: `sudo ufw status`. If active, run `sudo ufw allow 8000/tcp`.

**PostgreSQL permission errors on startup**
```sql
GRANT ALL ON SCHEMA public TO vapt_user;
ALTER DATABASE vapt OWNER TO vapt_user;
```

**AI analysis not appearing**
Check that `AI_PROVIDER` and `AI_API_KEY` are set in `.env` and that the server has been restarted. You can also trigger analysis manually from the dashboard by clicking "Analyse" on any result. Verify the setting is enabled in the Settings panel.

**Job, schedule, or sweep creation returns 400 "cannot start with -"**
Target/subnet values are validated before being handed to Nmap/Nikto, since a value starting with `-` would otherwise be parsed as a command-line flag rather than a target. Remove the leading hyphen — it isn't a valid target/subnet in any case.

**Update broke something**
Each update only adds columns — it never drops or modifies existing ones. If something looks wrong after an update, check `journalctl -u vapt-server -n 50` for startup errors and compare your `.env` against the Environment Variables table above for any new required values.

**`install_plugin.sh` / `uninstall_plugin.sh` — usage reference**
Both live in `plugins/` and take positional arguments in this order:
```bash
./install_plugin.sh <plugin_source_dir> <job_type> <scanner:NAME|agent>
./uninstall_plugin.sh <job_type> <scanner:NAME|agent>
```
Common mistakes:
- `<job_type>` must exactly match the `"type"` field inside that plugin's `plugin.json` — not the folder name. They're often similar but not always identical (e.g. the source folder `plugins/asset_inventory/` deploys as job type `asset_inventory_scan`).
- The last argument is either `scanner:NAME` (where `NAME` is a scanner already registered in the dashboard, e.g. `scanner:scanner-default`) or the literal word `agent` — not a hostname or IP.
- Both scripts figure out the repo root from their own file location, not your current directory — they work fine run from either `plugins/` or the repo root, but **do not move them individually**; if one moves without the other, or either moves outside `plugins/`, path resolution breaks.
- For a `scanner:NAME` target, the script looks for a systemd service named `vapt-scanner-NAME` to restart. If you're running that scanner manually (not via systemd), you'll see a message saying so — that's not an error, just restart it yourself.

**There are two `plugins/` folders — which one do I use?**
`plugins/` at the repo root is where you run `install_plugin.sh` from, and where first-party plugin source lives. `backend/app/installed_plugins/` (and `agent/installed_plugins/`) are deployment targets that `install_plugin.sh` writes to — you shouldn't need to touch those directly, and they shouldn't be committed (see [Plugins](#plugins) above for the `.gitignore` entry). If `backend/app/installed_plugins/` has a folder you don't recognize, it's either something `install_plugin.sh` deployed, or `hooks/`/`asset_inventory_scan/`, which ship pre-installed.
