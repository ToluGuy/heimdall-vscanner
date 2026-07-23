# Heimdall V-Scanner — Agent & Local Scanner Setup

This guide covers deploying the Heimdall agent and local scanner on any endpoint (Linux or Windows). The agent connects to the central Heimdall server and runs scans from the endpoint's network position. The local scanner is fully standalone — no server connection required.

---

## What's in this folder

| File | Purpose |
|------|---------|
| `agent.py` | Background agent — registers with the server, polls for jobs, executes scans |
| `local_scanner.py` | Standalone scan tool with a browser UI — no server, no database |
| `setup_agent.sh` | Automated Linux setup script — handles package install, venv, and optional systemd service |
| `setup_agent.ps1` | Automated Windows setup script — handles Python, Nmap, and shortcuts |
| `uninstall_agent.sh` | Removes the Linux systemd service, kills running processes, cleans up the venv and key file |
| `uninstall_agent.ps1` | Removes the Windows NSSM service, Desktop shortcuts, and install directory |
| `installed_plugins/` | Created once you deploy your first Loki plugin here — see **Installing plugins on an agent** below. Not present on a fresh checkout. |

---

## Linux Setup

### Requirements

- Python 3.10 or later
- Nmap installed and on the system PATH
- Nikto (optional — only needed if you want `nikto_scan` capability)
- Network access to the Heimdall server on port 8000

### Automated (`setup_agent.sh`)

```bash
cd agent/
./setup_agent.sh
```

What it does:
- Detects your package manager (apt, dnf, or yum) and installs Python 3,
  `venv`, Nmap, and Nikto
- Copies `agent.py` and `local_scanner.py` into a fresh install directory
  at `~/vapt-agent/` — **not** wherever you cloned the repo, a separate
  location. This matters for plugin installs, see below.
- Creates the venv and installs `requests`/`python-dotenv` there
- Prompts for an agent name and the server URL, writes `~/vapt-agent/.env`
- Auto-detects whether Nikto is available and sets `VAPT_CAPABILITIES`
  accordingly
- Optionally installs a `heimdall-agent` systemd service
- Creates a `run_local_scanner.sh` launcher alongside it

If the dashboard shows a Setup ⚠ badge right after this finishes, that's
normal — it means the agent registered but hasn't checked in yet.

### Manual

If you'd rather not run the script, or want the agent living somewhere
specific (e.g. so `install_plugin.sh` reaches it directly — see below):

```bash
sudo apt install nmap nikto python3-venv python3-pip
python3 -m venv venv
source venv/bin/activate
pip install requests python-dotenv
```

```bash
VAPT_AGENT_NAME=office-pc-1 \
VAPT_SERVER_URL=http://192.168.1.200:8000 \
VAPT_CAPABILITIES=nmap_scan,nikto_scan,nse_scan \
python3 agent.py
```

The agent registers automatically on first run and saves its API key to a local file (`{agent-name}_key.txt`). If this file is deleted, the agent re-registers as a new entry on the server.

If an agent goes offline and comes back, it automatically clears its own stale flag on the next heartbeat — no manual intervention needed in the dashboard.

### Environment variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VAPT_SERVER_URL` | URL of the Heimdall backend server | `http://127.0.0.1:8000` |
| `VAPT_AGENT_NAME` | Name shown in the dashboard for this agent | `agent-default` |
| `VAPT_CAPABILITIES` | Comma-separated list of scan types this agent can handle | `nmap_scan,nikto_scan,nse_scan` |
| `VAPT_KEY_FILE` | Path to store the agent's API key file | `{agent-name}_key.txt` |
| `VAPT_REGISTRATION_TOKEN` | Shared secret sent when first registering with the server — only required if the server has `VAPT_REGISTRATION_TOKEN` set in its own `.env`. Doesn't affect an agent that's already registered; only matters the next time this agent (re-)registers. |  — |

### Run as a systemd service (Linux)

`setup_agent.sh` offers to set this up for you. To do it by hand instead — for a manually-set-up agent, or to see what the script actually creates — create a service file:

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
- Creates a Python virtual environment at `%USERPROFILE%\heimdall-agent\venv`
- Installs required Python packages (`requests`, `python-dotenv`)
- Copies `agent.py` and `local_scanner.py` to the install directory
- Prompts for agent name and server URL, then writes a `.env` file
- Creates Desktop shortcuts for both the agent and the local scanner
- Optionally installs the agent as a Windows service via NSSM (runs at startup)

Nikto is not included in the Windows agent setup — it requires Perl, which is an unnecessary dependency for most Windows endpoints. The agent is configured with `nmap_scan,nse_scan` capabilities by default. Linux agents with Nikto installed handle `nikto_scan` jobs correctly.

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

## Uninstalling

Both platforms have a script that reverses what the automated setup did:

```bash
./uninstall_agent.sh      # Linux
```
```powershell
.\uninstall_agent.ps1     # Windows
```

Each one stops and removes the systemd/NSSM service if present, kills any
running agent or local-scanner process, removes Desktop shortcuts
(Windows), and cleans up the venv and key file. Neither one removes
`installed_plugins/` — if you'd deployed any Loki tools to this agent,
that code is left behind and needs removing separately (see
**Installing plugins on an agent** below) if you want it fully gone.
Neither script touches the agent's registration on the server either —
that's a dashboard-side cleanup, not a files-on-disk one.

These scripts only work correctly for agents set up via the automated
scripts, or for a manually-set-up agent living at the same path they
expect — check the script itself if you set things up by hand somewhere
else.

---

## Local Scanner

The local scanner is a fully self-contained tool. It runs a small web server on your machine and opens a browser UI for running scans — no connection to the Heimdall server is needed, and no database is involved.

Results live in memory for the duration of the session and can be exported as JSON before closing the window.

### Supported scan types

- **Open Port Scan** — Port discovery and service detection. Automatically runs a Nikto web scan on any web ports found, if Nikto is installed.
- **Vulnerability Scan** — Nmap Scripting Engine checks against discovered services.

Loki plugins aren't available here — `install_plugin.sh` only targets a
registered scanner or agent, and the local scanner has no server
connection for either half of the plugin model (manifest registration or
capability advertising) to apply to.

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

### Built in — always available

| Capability | Tool | Notes |
|------------|------|-------|
| `nmap_scan` | Nmap + Nikto | Open Port Scan; Nikto auto-runs on any web ports found |
| `nikto_scan` | Nikto | Standalone Web Scan against a specified port; target can be an IP, hostname, or URL |
| `nse_scan` | Nmap NSE | Vulnerability Scan; all discovered ports are scanned, with a blue advisory shown if web ports are included |

For Windows agents, set `VAPT_CAPABILITIES=nmap_scan,nse_scan` (omit `nikto_scan` unless Perl and Nikto are installed).

### Loki — installed separately, per agent

These aren't available until you deploy them (see **Installing plugins on an agent** below), and each one has to actually be installed on the underlying OS too (Nmap/Nikto come from the packages above; these don't):

| Capability | Tool | Risk tier |
|------------|------|-----------|
| `ffuf_scan` | ffuf | intrusive |
| `whatweb_scan` | WhatWeb | intrusive |
| `sqlmap_scan` | sqlmap | intrusive |
| `nuclei_scan` | Nuclei | intrusive |
| `hydra_scan` | Hydra | **high** — requires a live target authorization granted from the dashboard before a job of this type will run at all |

## Installing plugins on an agent

Loki tools aren't part of the base agent setup — they're deployed the same way onto an agent as onto a scanner, from the repo's `plugins/` folder:

```bash
cd plugins/
./install_plugin.sh ./ffuf ffuf_scan agent
```

This copies the plugin's code to `agent/installed_plugins/ffuf_scan/` and appends `ffuf_scan` to this agent's `VAPT_CAPABILITIES` in its `.env` — but it doesn't install `ffuf` itself. Each plugin folder has its own `setup.sh` for that (e.g. `plugins/ffuf/setup.sh`), which you run once, by hand, on this same machine. Restart the agent process afterward for the new capability to take effect.

To remove one: `./uninstall_plugin.sh ffuf_scan agent` — this only removes the code and capability on this machine; the plugin's manifest registration on the server (if you want it gone there too) is a separate step done from Settings → Plugins on the dashboard.

**Important if you used the automated setup script:** `install_plugin.sh ... agent` always deploys to `<repo>/agent/installed_plugins/` and edits `<repo>/agent/.env` — paths relative to the repo itself. But `setup_agent.sh`/`setup_agent.ps1` copy `agent.py` out to a separate install directory (`~/vapt-agent/` on Linux, `%USERPROFILE%\heimdall-agent` on Windows) and run *that* copy, not the one in the repo. Since `agent.py` looks for plugins relative to its own file location, a plugin deployed via `install_plugin.sh` will sit in the repo's copy of `agent/installed_plugins/`, which the actually-running agent never looks at.

If you set up an agent with the automated script and want it to run Loki tools, either:
- Copy the plugin folder and edit `.env` by hand in the *actual* install directory instead of using `install_plugin.sh` — e.g. `cp -r plugins/ffuf/* ~/vapt-agent/installed_plugins/ffuf_scan/` (create that folder first), then add `ffuf_scan` to `VAPT_CAPABILITIES` in `~/vapt-agent/.env` yourself, or
- Skip the automated script for that machine and run `agent.py` straight out of the repo's `agent/` folder instead, where `install_plugin.sh` already points.

---



## Troubleshooting

**Agent shows offline in the dashboard**
The heartbeat timeout is 30 seconds. If the agent has not sent a heartbeat within that window it shows offline. Check that the agent process is running and that port 8000 on the server is reachable from the endpoint. When the agent comes back online, it will automatically clear its stale flag on the next heartbeat.

**`nmap: command not found`**
Install Nmap and ensure it is on the system PATH. On Linux: `sudo apt install nmap`. On Windows: download from nmap.org and tick "Add to PATH" during install, or restart PowerShell after installation.

**Agent re-registers on every restart**
The agent saves its API key to `{agent-name}_key.txt` in the working directory. If this file is missing or the working directory changes between runs, the agent re-registers. Make sure the key file is in the same directory you're running `agent.py` from.

**Local scanner port already in use**
The local scanner tries port 9731 first and automatically finds the next free port if it's taken. The actual URL is printed in the terminal on startup.

**NSE scan takes a very long time**
The `standard` profile runs `--script vuln`, which can be slow depending on the target. Use the `light` profile (`--script safe`) for faster results. The `full` profile (`--script vuln,exploit`) is the slowest and most intrusive — only use it when you have explicit authorisation.
