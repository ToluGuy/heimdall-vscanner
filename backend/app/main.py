# backend/app/main.py

import secrets
import os
import json
from fastapi import FastAPI, Depends, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlalchemy.orm import Session
from datetime import datetime, timedelta

from typing import List
from .db import Base, engine, get_db
from .models import Agent, Job, Result
from .schemas import AgentCreate, AgentResponse, JobResponse, ResultCreate, ResultResponse, JobCreate
from dotenv import load_dotenv
from .logger import get_logger

load_dotenv()

logger = get_logger("vapt.server", "server.log")

JOB_TIMEOUT_SECONDS = 120

Base.metadata.create_all(bind=engine)

app = FastAPI()


security = HTTPBasic()

DASHBOARD_USERNAME = os.environ.get("DASHBOARD_USERNAME", "admin")
DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "vapt-admin")

def require_auth(credentials: HTTPBasicCredentials = Depends(security)):
    correct_username = secrets.compare_digest(
        credentials.username.encode("utf8"),
        DASHBOARD_USERNAME.encode("utf8")
    )
    correct_password = secrets.compare_digest(
        credentials.password.encode("utf8"),
        DASHBOARD_PASSWORD.encode("utf8")
    )
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

@app.get("/")
def root():
    return {"message": "VAPT system running"}

    
@app.post("/agents/register", response_model=AgentResponse)
def register_agent(agent: AgentCreate, db: Session = Depends(get_db)):
    new_agent = Agent(
        name=agent.name,
        capabilities=agent.capabilities or "nmap_scan"
    )

    db.add(new_agent)
    db.commit()
    db.refresh(new_agent)

    return {"api_key": new_agent.api_key}


# 🔐 helper
def get_agent_by_api_key(api_key: str, db: Session):
    agent = db.query(Agent).filter(Agent.api_key == api_key).first()
    if not agent:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return agent


@app.post("/agents/results")
def submit_result(
    result: ResultCreate,
    x_api_key: str = Header(...),
    db: Session = Depends(get_db),
):
    agent = get_agent_by_api_key(x_api_key, db)

    new_result = Result(
        job_id=result.job_id,
        output=result.output,
    )

    db.add(new_result)

    # mark job as done
    job = db.query(Job).filter(Job.id == result.job_id).first()
    if job:
        job.status = "done"
        job.completed_at = datetime.utcnow()

    db.commit()

    return {"message": "Result stored"}
    
  
@app.get("/results", response_model=List[ResultResponse])
def get_results(db: Session = Depends(get_db), username: str = Depends(require_auth)):
    results = db.query(Result).all()

    response = []

    for r in results:
        parsed_output = json.loads(r.output)

        response.append({
            "id": r.id,
            "job_id": r.job_id,
            "output": parsed_output
        })

    return response


@app.post("/jobs/create")
def create_job(job: JobCreate, db: Session = Depends(get_db), username: str = Depends(require_auth)):

    new_job = Job(
        type=job.type,
        target=job.target,
        agent_id=job.agent_id,
        status="pending",
        priority=job.priority if job.priority else "medium",
        mode=job.mode if job.mode else "remote",
        profile=job.profile if job.profile else "standard"
    )

    db.add(new_job)
    db.commit()
    db.refresh(new_job)

    return new_job


@app.get("/agents")
def get_agents(db: Session = Depends(get_db), username: str = Depends(require_auth)):
    agents = db.query(Agent).all()

    response = []

    for a in agents:
        status = "offline"

        if a.last_seen and (datetime.utcnow() - a.last_seen) < timedelta(seconds=30):
            status = "online"

        response.append({
            "id": a.id,
            "name": a.name,
            "api_key": a.api_key,
            "status": status,
            "last_seen": a.last_seen
        })

    return response

#Updated Job Line
@app.get("/jobs")
def get_jobs(
    db: Session = Depends(get_db),
    show_history: bool = False
):
    if show_history:
        jobs = db.query(Job).all()
    else:
        jobs = db.query(Job).filter(Job.cleared == False).all()
        
    result = []

    for j in jobs:
        agent_name = None

        if j.agent_id:
            agent = db.query(Agent).filter(Agent.id == j.agent_id).first()
            if agent:
                agent_name = agent.name

        result.append({
            "id": j.id,
            "type": j.type,
            "target": j.target,
            "status": j.status,
            "priority": j.priority,
            "agent": agent_name or "any",
            "mode": j.mode,
            "profile": j.profile,
            "completed_at": j.completed_at,
            "cleared": j.cleared
        })

    return result


def get_agent_load(db, agent_id: int):
    return db.query(Job).filter(
        Job.agent_id == agent_id,
        Job.status == "running"
    ).count()


@app.get("/jobs/next")
def get_next_job(
    db: Session = Depends(get_db),
    x_api_key: str = Header(...),
    x_agent_mode: str = Header(default="agent")
):
    now = datetime.utcnow()

    agent = db.query(Agent).filter(Agent.api_key == x_api_key).first()

    if not agent:
        raise HTTPException(status_code=401, detail="Invalid API key")

    jobs = db.query(Job).filter(
        Job.status == "pending",
        Job.mode == x_agent_mode,
        (Job.next_run_at == None) | (Job.next_run_at <= now)
    ).all()

    if not jobs:
        return None
        
    agent_caps = agent.capabilities.split(",")

    # prioritize jobs assigned to this agent OR unassigned
    eligible_jobs = [
        j for j in jobs
        if (j.agent_id is None or j.agent_id == agent.id)
        and j.type in agent_caps
    ]

    if not eligible_jobs:
        return None

    # sort jobs: assigned first, then unassigned
    eligible_jobs.sort(key=lambda j: j.agent_id is None)

    # simple load check (optional but useful)
    current_load = get_agent_load(db, agent.id)

    # limit: max 2 running jobs per agent (tweakable)
    if current_load >= 2:
        return None

    job = eligible_jobs[0]

    # assign job to this agent
    job.agent_id = agent.id
    job.status = "running"
    job.started_at = datetime.utcnow()

    db.commit()

    return {
        "id": job.id,
        "type": job.type,
        "target": job.target,
        "mode": job.mode,
        "profile": job.profile
    }


@app.post("/agents/heartbeat")
def heartbeat(
    x_api_key: str = Header(...),
    db: Session = Depends(get_db),
):
    agent = get_agent_by_api_key(x_api_key, db)

    agent.last_seen = datetime.utcnow()
    db.commit()

    return {"status": "alive"}


@app.post("/agents/job-status")
def update_job_status(
    data: dict,
    x_api_key: str = Header(...),
    db: Session = Depends(get_db)
):
    agent = get_agent_by_api_key(x_api_key, db)

    job = db.query(Job).filter(Job.id == data["job_id"]).first()

    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    if job.agent_id != agent.id:
        raise HTTPException(status_code=403, detail="This job does not belong to you")

    job.status = data["status"]

    if data["status"] == "running":
        job.started_at = datetime.utcnow()

    db.commit()

    return {"ok": True}


@app.get("/jobs/recover-stuck")
def recover_stuck_jobs(db: Session = Depends(get_db)):
    now = datetime.utcnow()

    stuck_jobs = db.query(Job).filter(Job.status == "running").all()

    recovered = 0

    for job in stuck_jobs:
        if job.started_at is None:
            continue

        elapsed = now - job.started_at

        if elapsed > timedelta(seconds=JOB_TIMEOUT_SECONDS):
            logger.warning(f"Job {job.id} stuck for {elapsed}, resetting")
            
            if job.retries < job.max_retries:
                job.retries += 1
                delay = job.retries * 30 # seconds
                job.next_run_at = datetime.utcnow() + timedelta(seconds=delay)
                job.status = "pending"
                job.started_at = None
                recovered += 1
                logger.info(f"Job {job.id} retrying in {delay}s ({job.retries}/{job.max_retries})")
            else:
                job.status = "failed"
                job.started_at = None
                job.completed_at = datetime.utcnow()
                logger.error(f"Job {job.id} exceeded max retries, marking failed")

    db.commit()

    return {
        "checked": len(stuck_jobs),
        "recovered": recovered
    }


@app.post("/jobs/{job_id}/clear")
def clear_job(job_id: int, db: Session = Depends(get_db)):
    job = db.query(Job).filter(Job.id == job_id).first()

    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    job.cleared = True
    db.commit()

    return {"ok": True}


# New Dashboard
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>VAPT Dashboard</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-gray-950 text-gray-100 min-h-screen">

        <!-- Header -->
        <div class="bg-gray-900 border-b border-gray-800 px-6 py-4 flex items-center justify-between">
            <div class="flex items-center gap-3">
                <div class="w-3 h-3 rounded-full bg-green-400 animate-pulse"></div>
                <h1 class="text-xl font-bold text-green-400 tracking-wider">VAPT Control Dashboard</h1>
            </div>
            <button onclick="loadAll()" class="text-sm bg-gray-800 hover:bg-gray-700 px-4 py-2 rounded-lg transition">
                ↻ Refresh
            </button>
        </div>

        <div class="max-w-screen-xl mx-auto px-6 py-8 space-y-10">

            <!-- Create Job -->
            <div class="bg-gray-900 rounded-xl border border-gray-800 p-6">
                <h2 class="text-lg font-semibold text-green-400 mb-4">Create Job</h2>
                <div class="flex flex-wrap gap-3 items-end">
                    <div class="flex flex-col gap-1">
                        <label class="text-xs text-gray-400">Target IP</label>
                        <input id="target" placeholder="192.168.1.50"
                            class="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-green-500 w-44">
                    </div>
                    <div class="flex flex-col gap-1">
                        <label class="text-xs text-gray-400">Agent ID (optional)</label>
                        <input id="agent_id" placeholder="Leave blank for any"
                            class="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-green-500 w-44">
                    </div>
                    <div class="flex flex-col gap-1">
                        <label class="text-xs text-gray-400">Scan Type</label>
                        <select id="job_type" class="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-green-500">
                            <option value="nmap_scan">Nmap Scan</option>
                            <option value="nikto_scan">Nikto Scan</option>
                        </select>
                    </div>
                    <div class="flex flex-col gap-1">
                        <label class="text-xs text-gray-400">Mode</label>
                        <select id="mode" class="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-green-500">
                            <option value="remote">Remote</option>
                            <option value="agent">Agent</option>
                        </select>
                    </div>
                    <div class="flex flex-col gap-1">
                        <label class="text-xs text-gray-400">Profile</label>
                        <select id="profile" class="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-green-500">
                            <option value="standard">Standard</option>
                            <option value="light">Light</option>
                            <option value="full">Full</option>
                        </select>
                    </div>
                    <button onclick="createJob()"
                        class="bg-green-600 hover:bg-green-500 text-white font-semibold px-5 py-2 rounded-lg transition text-sm">
                        + Create
                    </button>
                </div>
            </div>

            <!-- Agents -->
            <div class="bg-gray-900 rounded-xl border border-gray-800 p-6">
                <h2 class="text-lg font-semibold text-green-400 mb-4">Agents</h2>
                <div id="agents" class="overflow-x-auto"></div>
            </div>

            <!-- Jobs -->
            <div class="bg-gray-900 rounded-xl border border-gray-800 p-6">
                <div class="flex items-center justify-between mb-4">
                    <h2 class="text-lg font-semibold text-green-400">Jobs</h2>
                    <div class="flex gap-2">
                        <button onclick="setJobFilter('all')" id="filter-all"
                            class="filter-btn active-filter text-xs px-3 py-1 rounded-full border border-gray-600 hover:border-green-500 transition">All</button>
                        <button onclick="setJobFilter('pending')" id="filter-pending"
                            class="filter-btn text-xs px-3 py-1 rounded-full border border-gray-600 hover:border-yellow-500 transition">Pending</button>
                        <button onclick="setJobFilter('running')" id="filter-running"
                            class="filter-btn text-xs px-3 py-1 rounded-full border border-gray-600 hover:border-blue-500 transition">Running</button>
                        <button onclick="setJobFilter('done')" id="filter-done"
                            class="filter-btn text-xs px-3 py-1 rounded-full border border-gray-600 hover:border-green-500 transition">Done</button>
                        <button onclick="setJobFilter('failed')" id="filter-failed"
                            class="filter-btn text-xs px-3 py-1 rounded-full border border-gray-600 hover:border-red-500 transition">Failed</button>
                        <button onclick="toggleHistory()" id="historyBtn"
                            class="text-xs px-3 py-1 rounded-full border border-gray-600 hover:border-purple-500 transition">Show History</button>
                    </div>
                </div>
                <div id="jobs" class="overflow-x-auto"></div>
            </div>

            <!-- Results -->
            <div class="bg-gray-900 rounded-xl border border-gray-800 p-6">
                <h2 class="text-lg font-semibold text-green-400 mb-4">Scan Results</h2>
                <div id="results" class="space-y-4"></div>
            </div>

        </div>

        <script>
        let jobFilter = "all";
        let showHistory = false;
        let authCredentials = "";

        function getAuth() {
            if (authCredentials) return authCredentials;
            const username = prompt("Username:");
            const password = prompt("Password:");
            authCredentials = 'Basic ' + btoa(username + ':' + password);
            return authCredentials;
        }

        async function apiFetch(url, options = {}) {
            options.headers = {
                ...options.headers,
                'Authorization': getAuth()
            };
            const res = await fetch(url, options);
            if (res.status === 401) {
                authCredentials = "";
                alert("Invalid credentials. Please refresh and try again.");
                return null;
            }
            return res;
        }

        async function loadAll() {
            loadAgents();
            loadJobs();
            loadResults();
        }

        function setJobFilter(filter) {
            jobFilter = filter;
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active-filter', 'border-green-500', 'text-green-400'));
            const active = document.getElementById('filter-' + filter);
            if (active) active.classList.add('active-filter', 'border-green-500', 'text-green-400');
            loadJobs();
        }

        function toggleHistory() {
            showHistory = !showHistory;
            document.getElementById("historyBtn").innerText = showHistory ? "Hide History" : "Show History";
            document.getElementById("historyBtn").classList.toggle('border-purple-500');
            document.getElementById("historyBtn").classList.toggle('text-purple-400');
            loadJobs();
        }

        async function createJob() {
            let target = document.getElementById("target").value;
            let agent_id = document.getElementById("agent_id").value;
            let type = document.getElementById("job_type").value;
            let mode = document.getElementById("mode").value;
            let profile = document.getElementById("profile").value;

            if (!target) {
                alert("Please enter a target IP.");
                return;
            }

            let payload = { type, target, mode, profile };
            if (agent_id) payload.agent_id = parseInt(agent_id);

            await apiFetch('/jobs/create', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(payload)
            });

            document.getElementById("target").value = "";
            setTimeout(loadAll, 300);
        }

        function statusBadge(status) {
            const map = {
                pending:  'bg-yellow-900 text-yellow-300 border border-yellow-700',
                running:  'bg-blue-900 text-blue-300 border border-blue-700',
                done:     'bg-green-900 text-green-300 border border-green-700',
                failed:   'bg-red-900 text-red-300 border border-red-700',
            };
            return `<span class="text-xs px-2 py-0.5 rounded-full font-medium ${map[status] || 'bg-gray-700 text-gray-300'}">${status}</span>`;
        }

        function priorityBadge(priority) {
            const map = {
                high:   'text-red-400',
                medium: 'text-yellow-400',
                low:    'text-gray-400',
            };
            return `<span class="text-xs font-medium ${map[priority] || 'text-gray-400'}">${priority}</span>`;
        }

        async function loadAgents() {
            let res = await apiFetch('/agents');
            if (!res) return;
            let data = await res.json();

            let html = `<table class="w-full text-sm">
                <thead><tr class="text-left text-gray-400 border-b border-gray-800">
                    <th class="pb-2 pr-4">ID</th>
                    <th class="pb-2 pr-4">Name</th>
                    <th class="pb-2 pr-4">Status</th>
                    <th class="pb-2">Last Seen</th>
                </tr></thead><tbody>`;

            data.forEach(a => {
                const dot = a.status === 'online'
                    ? '<span class="inline-block w-2 h-2 rounded-full bg-green-400 mr-2"></span>'
                    : '<span class="inline-block w-2 h-2 rounded-full bg-red-500 mr-2"></span>';
                html += `<tr class="border-b border-gray-800 hover:bg-gray-800 transition">
                    <td class="py-2 pr-4 text-gray-400">#${a.id}</td>
                    <td class="py-2 pr-4 font-medium">${a.name}</td>
                    <td class="py-2 pr-4">${dot}${a.status}</td>
                    <td class="py-2 text-gray-400 text-xs">${a.last_seen || '—'}</td>
                </tr>`;
            });

            html += '</tbody></table>';
            document.getElementById("agents").innerHTML = html;
        }

        async function loadJobs() {
            let url = showHistory ? '/jobs?show_history=true' : '/jobs';
            let res = await apiFetch(url);
            if (!res) return;
            let data = await res.json();

            if (jobFilter !== "all") {
                data = data.filter(j => j.status === jobFilter);
            }

            if (data.length === 0) {
                document.getElementById("jobs").innerHTML = '<p class="text-gray-500 text-sm">No jobs found.</p>';
                return;
            }

            let html = `<table class="w-full text-sm">
                <thead><tr class="text-left text-gray-400 border-b border-gray-800">
                    <th class="pb-2 pr-3">ID</th>
                    <th class="pb-2 pr-3">Type</th>
                    <th class="pb-2 pr-3">Target</th>
                    <th class="pb-2 pr-3">Status</th>
                    <th class="pb-2 pr-3">Priority</th>
                    <th class="pb-2 pr-3">Mode</th>
                    <th class="pb-2 pr-3">Profile</th>
                    <th class="pb-2 pr-3">Agent</th>
                    <th class="pb-2 pr-3">Completed</th>
                    <th class="pb-2">Action</th>
                </tr></thead><tbody>`;

            data.forEach(j => {
                const action = j.cleared
                    ? '<span class="text-xs text-gray-500 italic">archived</span>'
                    : `<button onclick="clearJob(${j.id})" class="text-xs text-red-400 hover:text-red-300 transition">Clear</button>`;

                html += `<tr class="border-b border-gray-800 hover:bg-gray-800 transition">
                    <td class="py-2 pr-3 text-gray-400">#${j.id}</td>
                    <td class="py-2 pr-3 font-mono text-xs text-blue-300">${j.type}</td>
                    <td class="py-2 pr-3 font-mono text-xs">${j.target}</td>
                    <td class="py-2 pr-3">${statusBadge(j.status)}</td>
                    <td class="py-2 pr-3">${priorityBadge(j.priority)}</td>
                    <td class="py-2 pr-3 text-xs text-gray-300">${j.mode}</td>
                    <td class="py-2 pr-3 text-xs text-gray-300">${j.profile}</td>
                    <td class="py-2 pr-3 text-xs text-gray-300">${j.agent}</td>
                    <td class="py-2 pr-3 text-xs text-gray-400">${j.completed_at ? j.completed_at.replace('T', ' ').split('.')[0] : '—'}</td>
                    <td class="py-2">${action}</td>
                </tr>`;
            });

            html += '</tbody></table>';
            document.getElementById("jobs").innerHTML = html;
        }

        async function clearJob(job_id) {
            await apiFetch(`/jobs/${job_id}/clear`, { method: 'POST' });
            loadJobs();
        }

        function renderNmapResult(nmap) {
            if (!nmap || !nmap.length) return '<p class="text-gray-500 text-xs">No hosts found.</p>';
            return nmap.map(host => {
                const ports = host.ports && host.ports.length
                    ? host.ports.map(p => `
                        <tr class="border-b border-gray-700">
                            <td class="py-1 pr-4 font-mono text-blue-300">${p.port}</td>
                            <td class="py-1 pr-4 text-green-400">${p.state}</td>
                            <td class="py-1 text-gray-300">${p.service}</td>
                        </tr>`).join('')
                    : '<tr><td colspan="3" class="py-2 text-gray-500">No open ports found</td></tr>';

                return `<div class="mb-2">
                    <p class="text-xs text-gray-400 mb-1">Host: <span class="text-white font-mono">${host.host}</span></p>
                    <table class="w-full text-xs">
                        <thead><tr class="text-gray-500">
                            <th class="text-left pb-1 pr-4">Port</th>
                            <th class="text-left pb-1 pr-4">State</th>
                            <th class="text-left pb-1">Service</th>
                        </tr></thead>
                        <tbody>${ports}</tbody>
                    </table>
                </div>`;
            }).join('');
        }

        function renderNiktoResult(nikto) {
            if (!nikto) return '';
            return Object.entries(nikto).map(([port, result]) => {
                if (result.error) {
                    return `<div class="mt-2">
                        <p class="text-xs text-gray-400">Nikto port ${port}:</p>
                        <p class="text-xs text-red-400">${result.error}</p>
                    </div>`;
                }
                if (result.raw) {
                    return `<div class="mt-2">
                        <p class="text-xs text-gray-400 mb-1">Nikto port ${port} (raw output):</p>
                        <pre class="text-xs text-gray-300 bg-gray-950 p-3 rounded-lg overflow-x-auto whitespace-pre-wrap">${result.raw}</pre>
                    </div>`;
                }
                const vulns = result[0]?.vulnerabilities || [];
                if (!vulns.length) return `<p class="text-xs text-gray-500 mt-2">Nikto port ${port}: no vulnerabilities found.</p>`;
                return `<div class="mt-2">
                    <p class="text-xs text-gray-400 mb-1">Nikto port ${port} — ${vulns.length} finding(s):</p>
                    <div class="space-y-1">
                        ${vulns.map(v => `
                            <div class="bg-gray-950 rounded p-2 text-xs">
                                <span class="text-yellow-400 font-mono">[${v.id}]</span>
                                <span class="text-gray-200 ml-2">${v.msg}</span>
                                ${v.url ? `<span class="text-gray-500 ml-2">${v.url}</span>` : ''}
                            </div>`).join('')}
                    </div>
                </div>`;
            }).join('');
        }

        async function loadResults() {
            let res = await apiFetch('/results');
            if (!res) return;
            let data = await res.json();

            if (data.length === 0) {
                document.getElementById("results").innerHTML = '<p class="text-gray-500 text-sm">No results yet.</p>';
                return;
            }

            const html = data.slice().reverse().map(r => {
                const out = r.output;
                return `<div class="bg-gray-800 rounded-xl border border-gray-700 p-5">
                    <div class="flex items-center justify-between mb-3">
                        <span class="text-sm font-semibold text-white">Result #${r.id}</span>
                        <span class="text-xs text-gray-400">Job #${r.job_id}</span>
                    </div>
                    ${out.nmap ? `<div class="mb-3">
                        <p class="text-xs font-semibold text-blue-400 uppercase tracking-wider mb-2">Nmap</p>
                        ${renderNmapResult(out.nmap)}
                    </div>` : ''}
                    ${out.nikto ? `<div>
                        <p class="text-xs font-semibold text-orange-400 uppercase tracking-wider mb-1">Nikto</p>
                        ${renderNiktoResult(out.nikto)}
                    </div>` : ''}
                    ${!out.nmap && !out.nikto ? `<pre class="text-xs text-gray-400 overflow-x-auto">${JSON.stringify(out, null, 2)}</pre>` : ''}
                </div>`;
            }).join('');

            document.getElementById("results").innerHTML = html;
        }

        loadAll();
        setInterval(loadAll, 5000);
        </script>
    </body>
    </html>
    """
