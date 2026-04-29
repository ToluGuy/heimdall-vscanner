# agent.py

import time
import json
import os
import requests
import subprocess
import xml.etree.ElementTree as ET

SERVER_URL = "http://127.0.0.1:8000"
AGENT_NAME = "agent-2"
API_KEY_FILE = "agent2_key.txt"


def register():
    response = requests.post(
        f"{SERVER_URL}/agents/register",
        json={"name": AGENT_NAME},
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
        f"{SERVER_URL}/agents/jobs",
        headers=headers,
        timeout=10,
    )

    if response.status_code == 401:
        raise Exception("Invalid API key")

    response.raise_for_status()
    return response.json()

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


def execute_job(job, api_key):
    job_type = job["type"]
    target = job["target"]
    job_id = job["id"]

    if job_type == "nmap_scan":
        output = run_nmap(target)
        print("[+] Parsed Result:")
        print(json.dumps(output, indent=2))
        
        send_result(api_key, job_id, json.dumps(output))
        print("[+] Result sent to server")

    else:
        print(f"[!] Unknown job type: {job_type}")


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
