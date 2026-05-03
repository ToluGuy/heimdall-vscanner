# VAPT Scanner Project

A distributed vulnerability assessment and penetration testing (VAPT) scanner built for internal office network use. The system coordinates scan jobs across multiple agents and a central server, providing a unified dashboard for visibility into network vulnerabilities.

## Architecture

The project follows a server-agent model:

- **Backend server** — A FastAPI application that manages job queuing, agent registration, and scan results. Backed by PostgreSQL.
- **Agent** (`agent.py`) — Runs on individual workstations or servers. Polls the server for jobs and executes scans locally.
- **Scanner** (`scanner.py`) — Runs on a central machine. Handles agentless remote scans against targets that cannot run an agent directly, such as firewalls, switches and printers.
- **Dashboard** — A web interface served by the backend for creating jobs, monitoring agents, and reviewing scan results.

## Scan Tools

- **Nmap** — Port discovery and service detection across all scan modes
- **Nikto** — Web vulnerability scanning, triggered automatically when Nmap finds open web ports
- **OpenVAS** — Planned for future integration

## Scan Profiles

| Profile | Description |
|---------|-------------|
| light | Fast scan, top 100 ports |
| standard | Top 1000 ports with service detection |
| full | All ports, deep service and OS detection |

## Prerequisites

The following must be installed on the system before setup:

- Python 3.10+
- PostgreSQL
- Nmap
- Nikto

```bash
sudo apt install nmap nikto postgresql
```

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/ToluGuy/VAPT-Scanner-Project.git
cd VAPT-Scanner-Project
```

### 2. Create and activate a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Set up the PostgreSQL database

```bash
sudo -u postgres psql
```

```sql
CREATE DATABASE vapt;
CREATE USER vapt_user WITH PASSWORD 'your-password';
GRANT ALL PRIVILEGES ON DATABASE vapt TO vapt_user;
GRANT ALL ON SCHEMA public TO vapt_user;
\q
```

### 5. Configure environment variables

Create a `.env` file in the project root:

DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD=your-strong-password
DB_HOST=localhost
DB_PORT=5432
DB_NAME=vapt
DB_USER=vapt_user
DB_PASSWORD=your-password

### 6. Start the server

```bash
uvicorn backend.app.main:app --reload
```

The dashboard is available at `http://localhost:8000/dashboard`

## Running Agents

### On a workstation or server

```bash
VAPT_AGENT_NAME=office-pc-1 VAPT_SERVER_URL=http://<server-ip>:8000 python3 agent.py
```

### On the central scanner (ESXi or equivalent)

```bash
VAPT_AGENT_NAME=scanner-1 VAPT_SERVER_URL=http://<server-ip>:8000 python3 scanner.py
```

Agents register automatically on first run and save their API key locally.

## Dashboard

Access the dashboard at `/dashboard`. You will be prompted for credentials on first load.

From the dashboard you can:

- Create scan jobs targeting any IP on the network
- Monitor agent status in real time
- Filter and review jobs by status
- View structured scan results from Nmap and Nikto
- Archive completed jobs

## Project Structure

VAPT-Scanner-Project/
├── agent.py              # Workstation/server agent
├── scanner.py            # Agentless remote scanner
├── backend/
│   └── app/
│       ├── main.py       # FastAPI server and dashboard
│       ├── models.py     # Database models
│       ├── schemas.py    # Request/response schemas
│       ├── db.py         # Database connection
│       └── logger.py     # Logging configuration
├── requirements.txt
└── .env                  # Not committed — create locally

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| VAPT_SERVER_URL | URL of the backend server | http://127.0.0.1:8000 |
| VAPT_AGENT_NAME | Name for this agent instance | agent-default |
| VAPT_CAPABILITIES | Comma separated scan capabilities | nmap_scan,nikto_scan |
| VAPT_KEY_FILE | Path to store the agent API key | {agent-name}_key.txt |
| DASHBOARD_USERNAME | Dashboard login username | admin |
| DASHBOARD_PASSWORD | Dashboard login password | vapt-admin |
| DB_HOST | PostgreSQL host | localhost |
| DB_PORT | PostgreSQL port | 5432 |
| DB_NAME | Database name | vapt |
| DB_USER | Database user | vapt_user |
| DB_PASSWORD | Database password | — |
