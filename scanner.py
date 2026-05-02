# scanner.py
# Agentless remote scanner — runs on endpoint server
# Picks up remote jobs and scans targets from the outside

import time
import json
import os
import requests
import subprocess
import xml.etree.ElementTree as ET

# --- CONFIG ---
SERVER_URL = os.environ.get("VAPT_SERVER_URL", "http://127.0.0.1:8000")
AGENT_NAME = os.environ.get("VAPT_AGENT_NAME", "scanner-1")
CAPABILITIES = os.environ.get("VAPT_CAPABILITIES", "nmap_scan")
API_KEY_FILE = os.environ.get("VAPT_KEY_FILE", f"{AGENT_NAME}_key.txt")


# --- AUTH ---

def register():
    payload = {
        "name": AGENT_NAME,
        "capabilities": CAPABILITIES,
    }

    response = requests.post(
        f"{SERVER_URL}/agents/register",
        json=payload,
        timeout=10,
    )

    response.raise_for_status()
    data = response.json()

    api_key = data["api_key"]

    with open(API_KEY_FILE, "w") as f:
        f.write(api_key)

    print(f"[+] Registered as '{AGENT_NAME}'. API Key saved.")
    return api_key


def load_api_key():
    if os.path.exists(API_KEY_FILE):
        with open(API_KEY_FILE, "r") as f:
            return f.read().strip()
    return None


# --- JOB COMMUNICATION ---

def get_job(api_key):
    headers = {
        "x-api-key": api_key,
        "x-agent-mode": "remote"
    }

    response = requests.get(
        f"{SERVER_URL}/jobs/next",
        headers=headers,
        timeout=10,
    )

    if response.status_code == 401:
        raise Exception("Invalid API key")

    response.raise_for_status()
    return response.json()


def send_result(api_key, job_id, output):
    headers = {"x-api-key": api_key}

    response = requests.post(
        f"{SERVER_URL}/agents/results",
        headers=headers,
        json={
            "job_id": job_id,
            "output": output,
        },
        timeout=10,
    )

    response.raise_for_status()


def send_job_status(api_key: str, job_id: int, status: str):
    requests.post(
        f"{SERVER_URL}/agents/job-status",
        headers={"x-api-key": api_key},
        json={
            "job_id": job_id,
            "status": status
        }
    )


# --- AGENT HEALTH ---

def send_heartbeat(api_key):
    headers = {"x-api-key": api_key}

    try:
        requests.post(
            f"{SERVER_URL}/agents/heartbeat",
            headers=headers,
            timeout=5,
        )
    except:
        pass


# --- SCANNERS ---

def get_nmap_flags(profile: str) -> list:
    """Return nmap flags based on scan profile."""
    if profile == "light":
        return ["-F"]                    # top 100 ports, fast
    elif profile == "full":
        return ["-sV", "-O", "-p-"]     # all ports, service + OS detection
    else:                                # standard
        return ["-sV"]                   # top 1000 ports, service detection


def parse_nmap_xml(xml_data):
    root = ET.fromstring(xml_data)

    hosts = []

    for host in root.findall("host"):
        addr = host.find("address").get("addr")

        ports_data = []

        ports = host.find("ports")
        if ports:
            for port in ports.findall("port"):
                state = port.find("state").get("state")
                service = port.find("service").get("name", "unknown")

                ports_data.append({
                    "port": int(port.get("portid")),
                    "state": state,
                    "service": service,
                })

        hosts.append({
            "host": addr,
            "ports": ports_data
        })

    return hosts


def run_nmap(target: str, profile: str = "standard"):
    print(f"[*] Running Nmap ({profile}) on {target}...")

    flags = get_nmap_flags(profile)

    result = subprocess.run(
        ["nmap", *flags, "-oX", "-", target],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise Exception(f"Nmap failed: {result.stderr}")

    parsed = parse_nmap_xml(result.stdout)

    return parsed


# --- EXECUTION ENGINE ---

def execute_job(job: dict, api_key: str):
    job_type = job.get("type")
    target = job.get("target")
    job_id = job.get("id")
    mode = job.get("mode")
    profile = job.get("profile", "standard")

    # this scanner only handles remote jobs
    if mode != "remote":
        print(f"[SKIP] Job {job_id} is mode='{mode}', not for this scanner")
        return

    try:
        print(f"[*] Job {job_id} → {job_type} on {target} ({profile})")

        send_job_status(api_key, job_id, "running")

        if job_type == "nmap_scan":
            output = run_nmap(target, profile)
        else:
            output = {"error": f"Unsupported job type: {job_type}"}

        print(f"[+] Scan complete for job {job_id}")

        send_result(api_key, job_id, json.dumps(output))
        send_job_status(api_key, job_id, "done")

        print("[+] Result + status sent")

    except Exception as e:
        print(f"[ERROR] Job {job_id} failed: {e}")
        send_job_status(api_key, job_id, "failed")


# --- MAIN LOOP ---

def main():
    api_key = load_api_key()

    if not api_key:
        api_key = register()

    print(f"[*] Remote scanner '{AGENT_NAME}' started, polling for jobs...")

    while True:
        try:
            send_heartbeat(api_key)
            job = get_job(api_key)

            if job:
                print(f"[+] Received job: {job}")
                execute_job(job, api_key)
            else:
                print("[-] No remote jobs available")

        except Exception as e:
            print(f"[ERROR] {e}")

        time.sleep(10)


if __name__ == "__main__":
    main()
