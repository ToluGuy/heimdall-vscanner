# agent.py

import time
import json
import os
import requests
import subprocess
import xml.etree.ElementTree as ET

SERVER_URL = "http://127.0.0.1:8000"
AGENT_NAME = "agent-1"
API_KEY_FILE = "agent_key.txt"


def register():
    payload = {
        "name": AGENT_NAME,
        "capabilities": "nmap_scan",
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

    print(f"[+] Registered. API Key saved: {api_key}")
    return api_key


def load_api_key():
    if os.path.exists(API_KEY_FILE):
        with open(API_KEY_FILE, "r") as f:
            return f.read().strip()
    return None


def get_job(api_key):
    headers = {"x-api-key": api_key}

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
        "http://127.0.0.1:8000/agents/job-status",
        headers={"x-api-key": api_key},
        json={
            "job_id": job_id,
            "status": status
        }
    )


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


def run_nmap(target):
    print(f"[*] Running Nmap scan on {target}...")

    result = subprocess.run(
        ["nmap", "-sV", "-oX", "-", target],
        capture_output=True,
        text=True,
    )

    parsed = parse_nmap_xml(result.stdout)

    return parsed


#This is the sixth execute_job ive made...kill me
def execute_job(job: dict, api_key: str):

    job_type = job.get("type")
    target = job.get("target")
    job_id = job.get("id")

    try:
        print(f"[DEBUG] Job {job_id} → RUNNING")

        # This job status below will tell server job started
        send_job_status(api_key, job_id, "running")

        if job_type == "nmap_scan":
            print(f"[*] Running Nmap scan on {target}...")
            output = run_nmap(target)
        else:
            output = {"error": f"Unknown job type: {job_type}"}

        print(f"[+] Scan complete for job {job_id}")

        send_result(api_key, job_id, json.dumps(output))
        send_job_status(api_key, job_id, "done")

        print("[+] Result + status sent")

    except Exception as e:
        print(f"[ERROR] Job Execution failed: {e}")

        send_job_status(api_key, job_id, "failed")


def main():
    api_key = load_api_key()

    if not api_key:
        api_key = register()

    print("[*] Starting job polling...")

    while True:
        try:
            send_heartbeat(api_key)
            job = get_job(api_key)

            if job:
                print(f"[+] Received job: {job}")
                execute_job(job, api_key)
            else:
                print("[-] No jobs available")

        except Exception as e:
            print(f"[ERROR] {e}")

        time.sleep(10)


if __name__ == "__main__":
    main()



#IMPORTS

#CONFIG/CONSTANTS

#AUTH FUNCTIONS:
#register
#load_api_key

#JOB COMMUNICATION FUNCTION:
#get_job
#send_result
#send_job_status

#AGENT HEALTH:
#send_heartbeat

#SCANNERS / TOOLS
#parse_nmap_tools
#run_nmap

#EXECUTION ENGINE:
#execute_job

#MAIN LOOP:
#main
