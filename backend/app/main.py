# backend/app/main.py

from fastapi import FastAPI, Depends, Header, HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from datetime import datetime, timedelta

import json
from typing import List
from .db import Base, engine, get_db
from .models import Agent, Job, Result
from .schemas import AgentCreate, AgentResponse, JobResponse, ResultCreate, ResultResponse, JobCreate

JOB_TIMEOUT_SECONDS = 120

Base.metadata.create_all(bind=engine)

app = FastAPI()


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

    db.commit()

    return {"message": "Result stored"}
    
  
@app.get("/results", response_model=List[ResultResponse])
def get_results(db: Session = Depends(get_db)):
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
def create_job(job: JobCreate, db: Session = Depends(get_db)):

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
def get_agents(db: Session = Depends(get_db)):
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
def get_jobs(db: Session = Depends(get_db)):
    jobs = db.query(Job).all()

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
            "profile": j.profile
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
            print(f"[RECOVERY] Job {job.id} stuck for {elapsed}, resetting")
            
            if job.retries < job.max_retries:
                job.retries += 1
                delay = job.retries * 30 # seconds
                job.next_run_at = datetime.utcnow() + timedelta(seconds=delay)
                job.status = "pending"
                job.started_at = None
                recovered += 1
                print(f"[RETRY] Job {job.id} in {delay}s ({job.retries}/{job.max_retries})")
            else:
                job.status = "failed"
                job.started_at = None
                print(f"[FAILED] Job {job.id} exceeded retries")

    db.commit()

    return {
        "checked": len(stuck_jobs),
        "recovered": recovered
    }



# New Dashboard
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>VAPT Dashboard</title>
        <style>
            body { font-family: Arial; margin: 20px; background: #111; color: #eee; }
            h2 { color: #00ff99; }
            table { width: 100%; border-collapse: collapse; margin-bottom: 30px; }
            th, td { border: 1px solid #333; padding: 8px; }
            th { background: #222; }
            input, select, button { padding: 8px; margin: 5px; }
        </style>
    </head>
    <body>

    <h1>VAPT Control Dashboard</h1>

    <button onclick="loadAll()">Refresh</button>

    <h2>Create Job</h2>
    <div>
        <input id="target" placeholder="Target (e.g. 192.168.1.50)">
        <input id="agent_id" placeholder="Agent ID (optional)">
        <select id="job_type">
            <option value="nmap_scan">Nmap Scan</option>
        </select>
        <select id="mode">
            <option value="remote">Remote</option>
            <option value="agent">Agent</option>
        </select>
        <select id="profile">
            <option value="standard">Standard</option>
            <option value="light">Light</option>
            <option value="full">Full</option>
        </select>
        <button onclick="createJob()">Create</button>
    </div>

    <h2>Agents</h2>
    <div id="agents"></div>

    <h2>Jobs</h2>
    <div>
    <button onclick="setJobFilter('all')">ALL</button>
    <button onclick="setJobFilter('pending')">Pending</button>
    <button onclick="setJobFilter('running')">Running</button>
    <button onclick="setJobFilter('done')">Done</button>
    </div>
    
    <div id="jobs"></div>

    <h2>Results</h2>
    <div id="results"></div>
    
    <script>

let jobFilter = "all";

async function loadAll() {
    loadAgents();
    loadJobs();
    loadResults();
}

function setJobFilter(filter) {
    jobFilter = filter;
    console.log("Filter:", filter);
    loadJobs();
}


async function createJob() {
    let target = document.getElementById("target").value;
    let agent_id = document.getElementById("agent_id").value;
    let type = document.getElementById("job_type").value;
    let mode = document.getElementById("mode").value;
    let profile = document.getElementById("profile").value;

    let payload = {
        type: type,
        target: target,
        mode: mode,
        profile: profile
    };

    if (agent_id) {
        payload.agent_id = parseInt(agent_id);
    }

    await fetch('/jobs/create', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload)
    });

    setTimeout(loadAll, 500);
}

async function loadAgents() {
    let res = await fetch('/agents');
    let data = await res.json();

    let html = "<table><tr><th>ID</th><th>Name</th><th>Status</th><th>Last Seen</th></tr>";

    data.forEach(a => {
        html += `<tr>
            <td>${a.id}</td>
            <td>${a.name}</td>
            <td style="color:${a.status === 'online' ? 'lightgreen' : 'red'}">${a.status}</td>
            <td>${a.last_seen || ''}</td>
        </tr>`;
    });

    html += "</table>";
    document.getElementById("agents").innerHTML = html;
}

async function loadJobs() {
    let res = await fetch('/jobs');
    let data = await res.json();

    if (jobFilter !== "all") {
        data = data.filter(j => j.status === jobFilter);
    }
    
    let html = "<table><tr><th>ID</th><th>Type</th><th>Target</th><th>Status</th><th>Priority</th><th>Mode</th><th>Profile</th><th>Agent</th></tr>";

    data.forEach(j => {
        html += `<tr>
            <td>${j.id}</td>
            <td>${j.type}</td>
            <td>${j.target}</td>
            <td>${j.status}</td>
            <td>${j.priority}</td>
            <td>${j.mode}</td>
            <td>${j.profile}</td>
            <td>${j.agent}</td>
        </tr>`;
    });

    html += "</table>";
    document.getElementById("jobs").innerHTML = html;
}

async function loadResults() {
    let res = await fetch('/results');
    let data = await res.json();

    let html = "<table><tr><th>ID</th><th>Job ID</th><th>Output</th></tr>";

    data.forEach(r => {
        html += `<tr>
            <td>${r.id}</td>
            <td>${r.job_id}</td>
            <td><pre>${JSON.stringify(r.output, null, 2)}</pre></td>
        </tr>`;
    });

    html += "</table>";
    document.getElementById("results").innerHTML = html;
}

loadAll();
setInterval(loadAll, 5000);

</script>

    </body>
    </html>
    """
