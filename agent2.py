# agent2.py

import time
import json
import os
import requests
import subprocess
import xml.etree.ElementTree as ET

SERVER_URL = "http://127.0.0.1:8000"
AGENT_NAME = "agent-2"
API_KEY_FILE = "agent_key2.txt"


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
