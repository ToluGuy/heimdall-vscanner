# Heimdall V-Scanner — Agent & Local Scanner Setup

This guide covers deploying the Heimdall agent and local scanner on any endpoint (Linux or Windows). The agent connects to the central Heimdall server and runs scans from the endpoint's network position. The local scanner is fully standalone — no server connection required.

---

## What's in this folder

| File | Purpose |
|------|---------|
| `agent.py` | Background agent — registers with the server, polls for jobs, executes scans |
| `local_scanner.py` | Standalone scan tool with a browser UI — no server, no database |
| `setup_agent.ps1` | Automated Windows setup script — handles Python, Nmap, and shortcuts |

---

## Linux Setup

### Requirements

- Python 3.10 or later
- Nmap installed and on the system PATH
- Nikto (optional — only needed if you want `nikto_scan` capability)
- Network access to the Heimdall server on port 8000

### Install dependencies

```bash
sudo apt install nmap nikto python3-venv python3-pip
```

### Set up a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install requests python-dotenv
```

### Run the agent

```bash
VAPT_AGENT_NAME=office-pc-1 \
VAPT_SERVER_URL=http://192.168.1.200:8000 \
VAPT_CAPABILITIES=nmap_scan,nikto_scan,nse_scan \
python3 agent.py
```

The agent registers automatically on first run and saves its API key to a local file (`{agent-name}_key.txt`). If this file is deleted, the agent re-registers as a new entry on the server.

### Environment variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VAPT_SERVER_URL` | URL of the Heimdall backend server | `http://127.0.0.1:8000` |
| `VAPT_AGENT_NAME` | Name shown in the dashboard for this agent | `agent-default` |
| `VAPT_CAPABILITIES` | Comma-separated list of scan types this agent can handle | `nmap_scan,nikto_scan,nse_scan` |
| `VAPT_KEY_FILE` | Path to store the agent's API key file | `{agent-name}_key.txt` |

### Run as a systemd service (Linux)

To keep the agent running in the background and start it on boot, create a service file:

```bash
sudo nano /etc/systemd/system/heimdall-agent.service
```

```ini
[Unit]
Description=Heimdall V-Scanner Agent
After=network.target

[Service]
Type=simple
User=YOUR_USERNAME
WorkingDirectory=/home/YOUR_USERNAME/heimdall-vscanner/agent
Environment=VAPT_AGENT_NAME=office-pc-1
Environment=VAPT_SERVER_URL=http://192.168.1.200:8000
Environment=VAPT_CAPABILITIES=nmap_scan,nikto_scan,nse_scan
ExecStart=/home/YOUR_USERNAME/heimdall-vscanner/venv/bin/python agent.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable heimdall-agent
sudo systemctl start heimdall-agent
sudo systemctl status heimdall-agent
```

---

## Windows Setup (Automated)

The `setup_agent.ps1` script handles the full setup in one go.

### What it does

- Installs Python 3.12 (via winget or direct download fallback)
- Installs Nmap (via winget or direct download fallback)
- Creates a Python virtual environment at `%USERPROFILE%\vapt-agent\venv`
- Installs required Python packages (`requests`, `python-dotenv`)
- Copies `agent.py` and `local_scanner.py` to the install directory
- Prompts for agent name and server URL, then writes a `.env` file
- Creates Desktop shortcuts for both the agent and the local scanner
- Optionally installs the agent as a Windows service via NSSM (runs at startup)

Nikto is not included in the Windows agent setup — it requires Perl, which is an unnecessary dependency for most Windows endpoints. The agent is configured with `nmap_scan,nse_scan` capabilities by default.

### How to run it

Open PowerShell as Administrator, then:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\setup_agent.ps1
```

The script will prompt you for:
- **Agent name** — defaults to the machine's hostname
- **Server URL** — defaults to `http://192.168.1.200:8000`

After setup, two Desktop shortcuts are created:
- **VAPT Local Scanner** — opens the standalone browser UI
- **VAPT Agent** — starts the background agent that connects to the central server

### Manual Windows setup

If you prefer not to run the PowerShell script:

1. Install Python 3.10+ from [python.org](https://python.org) — tick "Add to PATH" during install
2. Install Nmap from [nmap.org](https://nmap.org/download.html)
3. Open PowerShell and install dependencies:

```powershell
pip install requests python-dotenv
```

4. Run the agent:

```powershell
$env:VAPT_AGENT_NAME = "office-pc-1"
$env:VAPT_SERVER_URL = "http://192.168.1.200:8000"
$env:VAPT_CAPABILITIES = "nmap_scan,nse_scan"
python agent.py
```

---

## Local Scanner

The local scanner is a fully self-contained tool. It runs a small web server on your machine and opens a browser UI for running scans — no connection to the Heimdall server is needed, and no database is involved.

Results live in memory for the duration of the session and can be exported as JSON before closing the window.

### Supported scan types

- **Nmap Scan** — Port discovery and service detection
- **NSE Scan** — Nmap Scripting Engine vulnerability checks against non-web ports

Nikto is not included in the local scanner — it requires Perl, which is not a dependency we want to impose on endpoints.

### Run it

```bash
python3 local_scanner.py
```

The browser opens automatically at `http://127.0.0.1:9731`.

**Options:**

```bash
python3 local_scanner.py --port 9999      # use a custom port
python3 local_scanner.py --no-browser     # don't open the browser automatically
```

On Windows, use the Desktop shortcut created by `setup_agent.ps1`, or run from PowerShell:

```powershell
python local_scanner.py
```

### Exporting results

The local scanner has no persistent storage. Before closing the window, use the export buttons at the bottom of the results panel to download a JSON file containing all scan results or a selected subset.

---

## Capabilities reference

When registering an agent, the `VAPT_CAPABILITIES` variable controls which job types that agent will accept from the server.

| Capability | Tool | Notes |
|------------|------|-------|
| `nmap_scan` | Nmap + Nikto | Port scan; Nikto auto-runs on any web ports found |
| `nikto_scan` | Nikto | Standalone web scan against a specified port |
| `nse_scan` | Nmap NSE | Script-based vulnerability scan; web ports excluded |

For Windows agents, set `VAPT_CAPABILITIES=nmap_scan,nse_scan` (omit `nikto_scan` unless Perl and Nikto are installed).

---

## Troubleshooting

**Agent shows offline in the dashboard**
The heartbeat timeout is 30 seconds. If the agent has not sent a heartbeat within that window it shows offline. Check that the agent process is running and that port 8000 on the server is reachable from the endpoint.

**`nmap: command not found`**
Install Nmap and ensure it is on the system PATH. On Linux: `sudo apt install nmap`. On Windows: download from nmap.org and tick "Add to PATH" during install, or restart PowerShell after installation.

**Agent re-registers on every restart**
The agent saves its API key to `{agent-name}_key.txt` in the working directory. If this file is missing or the working directory changes between runs, the agent re-registers. Make sure the key file is in the same directory you're running `agent.py` from.

**Local scanner port already in use**
The local scanner tries port 9731 first and automatically finds the next free port if it's taken. The actual URL is printed in the terminal on startup.

**NSE scan takes a very long time**
The `standard` profile runs `--script vuln`, which can be slow depending on the target. Use the `light` profile (`--script safe`) for faster results. The `full` profile (`--script vuln,exploit`) is the slowest and most intrusive — only use it when you have explicit authorisation.
