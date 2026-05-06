# VAPT Scanner Project

A distributed vulnerability assessment and penetration testing (VAPT) scanner built for internal office network use. The system coordinates scan jobs across multiple agents and a central server, providing a unified dashboard for visibility into network vulnerabilities.

## Architecture

The project follows a server-agent model:

- **Backend server** — A FastAPI application that manages job queuing, agent registration, and scan results. Backed by PostgreSQL.
- **Agent** (`agent.py`) — Runs on individual workstations or servers. Polls the server for jobs and executes scans locally.
- **Scanner** (`scanner.py`) — Runs on the central server. Handles agentless remote scans against targets that cannot run an agent directly, such as firewalls, switches, and printers.
- **Dashboard** — A web interface served by the backend for creating jobs, monitoring agents, and reviewing scan results.

## Scan Tools

- **Nmap** — Port discovery and service detection across all scan modes
- **Nikto** — Web vulnerability scanning, triggered automatically when Nmap finds open web ports
- **OpenVAS** — Planned for future integration

## Scan Profiles

| Profile | Nmap | Nikto | Description |
|---------|------|-------|-------------|
| light | `-F` | `-Tuning 1` | Top 100 ports, fast |
| standard | `-sV` | default | Top 1000 ports with service detection |
| full | `-sV -O -p-` | `-Tuning x6` | All ports, deep service and OS detection |

---

## Quick Install (Linux)

The installer handles everything — dependencies, database, environment config, and systemd services.

```bash
git clone https://github.com/ToluGuy/VAPT-Scanner-Project.git
cd VAPT-Scanner-Project
chmod +x install.sh
./install.sh
```

Run as a normal user with sudo access, not as root.

The installer will:
- Install system packages (nmap, nikto, postgresql, python3-venv)
- Create a Python virtual environment and install dependencies
- Prompt for dashboard credentials and database settings, then write `.env`
- Set up the PostgreSQL database, user, and permissions
- Run all schema migrations automatically
- Install and optionally start the `vapt-server` and `vapt-scanner` systemd services
- Open port 8000 in UFW if active

---

## Manual Setup

If you prefer to set things up yourself rather than using the installer:

### 1. Clone the repository

```bash
git clone https://github.com/ToluGuy/VAPT-Scanner-Project.git
cd VAPT-Scanner-Project
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
from backend.app.models import Agent, Job, Result
Base.metadata.create_all(bind=engine)
"
```

If upgrading from an earlier version, also run:

```sql
ALTER TABLE results ADD COLUMN IF NOT EXISTS cleared BOOLEAN DEFAULT FALSE;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS cleared BOOLEAN DEFAULT FALSE;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS mode VARCHAR DEFAULT 'remote';
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS profile VARCHAR DEFAULT 'standard';
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS started_at TIMESTAMP;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS completed_at TIMESTAMP;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS next_run_at TIMESTAMP;
```

### 8. Start the server

```bash
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
```

The dashboard is available at `http://localhost:8000/dashboard`

---

## Deployment (Production)

### Recommended setup

The recommended deployment is a dedicated Linux VM — either on ESXi, Proxmox, VirtualBox, or any hypervisor you have available. The server and remote scanner both run on this VM. Agents run separately on individual workstations across the network.

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

5. SSH in and run the installer:

```bash
git clone https://github.com/ToluGuy/VAPT-Scanner-Project.git
cd VAPT-Scanner-Project
chmod +x install.sh
./install.sh
```

### Systemd services

The installer sets up two services automatically. To manage them manually:

```bash
# Status
sudo systemctl status vapt-server
sudo systemctl status vapt-scanner

# Start / stop / restart
sudo systemctl start vapt-server vapt-scanner
sudo systemctl restart vapt-server

# Enable on boot
sudo systemctl enable vapt-server vapt-scanner

# Logs (live)
journalctl -u vapt-server -f
journalctl -u vapt-scanner -f
```

If you need to install the service files manually, edit `vapt-server.service` and `vapt-scanner.service` to replace `YOUR_USERNAME` and the install path, then:

```bash
sudo cp vapt-server.service vapt-scanner.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable vapt-server vapt-scanner
sudo systemctl start vapt-server vapt-scanner
```

### Network requirements

For agents on workstations to reach the server, port 8000 must be reachable from the LAN:

```bash
sudo ufw allow 8000/tcp
```

The server itself needs outbound access to reach scan targets (standard LAN access is sufficient). Agents only need outbound access to the server on port 8000 — they do not need to be reachable inbound.

| Direction | From | To | Port | Purpose |
|-----------|------|----|------|---------|
| Outbound | Server/Scanner | Scan targets | any | Nmap, Nikto |
| Outbound | Agents | Server | 8000 | Job polling, heartbeat, results |
| Inbound | Agents | Server | 8000 | Must be open on server firewall |
| Inbound | Browser | Server | 8000 | Dashboard access |

---

## Running Agents

### Linux workstation

Copy `agent.py` and `requirements.txt` to the workstation, then:

```bash
python3 -m venv venv
source venv/bin/activate
pip install requests python-dotenv

VAPT_AGENT_NAME=office-pc-1 \
VAPT_SERVER_URL=http://<server-ip>:8000 \
VAPT_CAPABILITIES=nmap_scan,nikto_scan \
python3 agent.py
```

To run as a background service on a Linux workstation, create `/etc/systemd/system/vapt-agent.service`:

```ini
[Unit]
Description=VAPT Agent
After=network.target

[Service]
Type=simple
User=YOUR_USERNAME
WorkingDirectory=/home/YOUR_USERNAME/vapt-scanner-project
Environment=VAPT_AGENT_NAME=office-pc-1
Environment=VAPT_SERVER_URL=http://192.168.1.200:8000
Environment=VAPT_CAPABILITIES=nmap_scan,nikto_scan
ExecStart=/home/YOUR_USERNAME/vapt-scanner-project/venv/bin/python agent.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable vapt-agent
sudo systemctl start vapt-agent
```

### Windows workstation

Install Python 3.10+ from python.org, then in PowerShell:

```powershell
pip install requests python-dotenv
$env:VAPT_AGENT_NAME="office-pc-1"
$env:VAPT_SERVER_URL="http://192.168.1.200:8000"
$env:VAPT_CAPABILITIES="nmap_scan,nikto_scan"
python agent.py
```

Note: Nmap must also be installed on Windows workstations for `nmap_scan` jobs. Download from nmap.org. Nikto on Windows requires Perl — if Nikto is not available, set `VAPT_CAPABILITIES=nmap_scan` to run Nmap-only scans.

Agents register automatically on first run and save their API key to a local file (`{agent-name}_key.txt`). If this file is deleted, the agent re-registers as a new entry.

---

## Dashboard

Access the dashboard at `/dashboard`. You will be prompted for credentials on first load.

From the dashboard you can:

- Create scan jobs targeting any IP on the network
- Monitor agent status in real time (auto-refreshes every 5 seconds)
- Filter jobs by status (pending, running, done, failed)
- Toggle job history to see archived jobs
- View and expand scan results from Nmap and Nikto
- Clear results (soft-archives the result and its job)
- Permanently delete results from the History tab (also removes the associated job)
- Bulk select and delete multiple archived results

---

## Project Structure

```
VAPT-Scanner-Project/
├── agent.py                  # Workstation/server agent
├── scanner.py                # Agentless remote scanner
├── install.sh                # Automated installer
├── vapt-server.service       # Systemd service — server
├── vapt-scanner.service      # Systemd service — scanner
├── backend/
│   └── app/
│       ├── main.py           # FastAPI server, endpoints, dashboard
│       ├── models.py         # Database models
│       ├── schemas.py        # Request/response schemas
│       ├── db.py             # Database connection
│       └── logger.py         # Logging configuration
├── requirements.txt
├── .env                      # Not committed — created by installer or manually
└── logs/                     # Not committed — created at runtime
```

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| VAPT_SERVER_URL | URL of the backend server | http://127.0.0.1:8000 |
| VAPT_AGENT_NAME | Name for this agent instance | agent-default |
| VAPT_CAPABILITIES | Comma-separated scan capabilities | nmap_scan,nikto_scan |
| VAPT_KEY_FILE | Path to store the agent API key | {agent-name}_key.txt |
| DASHBOARD_USERNAME | Dashboard login username | admin |
| DASHBOARD_PASSWORD | Dashboard login password | vapt-admin |
| DB_HOST | PostgreSQL host | localhost |
| DB_PORT | PostgreSQL port | 5432 |
| DB_NAME | Database name | vapt |
| DB_USER | Database user | vapt_user |
| DB_PASSWORD | Database password | — |

---

## Troubleshooting

**Server won't start**
```bash
journalctl -u vapt-server -n 50
```
Most common cause is a bad `.env` file or PostgreSQL not running. Check with `sudo systemctl status postgresql`.

**Agent shows offline in dashboard**
The agent heartbeat timeout is 30 seconds. If the agent hasn't sent a heartbeat in that window it shows offline. Check the agent is running and can reach the server on port 8000.

**Nikto hangs**
This is caused by a CIRT.net update prompt in Nikto 2.6.x. The scanner passes `input="n\n"` to suppress it automatically. If scans still hang, check Nikto is installed correctly with `nikto -Version`.

**Port 8000 unreachable from agents**
Check the firewall on the server: `sudo ufw status`. If active, run `sudo ufw allow 8000/tcp`.

**PostgreSQL permission errors on startup**
Run the following as the postgres user:
```sql
GRANT ALL ON SCHEMA public TO vapt_user;
ALTER DATABASE vapt OWNER TO vapt_user;
```
