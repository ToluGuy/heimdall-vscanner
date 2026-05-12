#!/usr/bin/env python3
# tools/test_connection.py
# Heimdall V-Scanner — Connection Tester
#
# Verifies that an agent or endpoint can reach the Heimdall server correctly.
# Tests the full handshake: reachability, authentication, job polling, and
# heartbeat. Useful for debugging agent connectivity issues on new endpoints
# before deploying the agent for real.
#
# Usage:
#   python tools/test_connection.py
#   python tools/test_connection.py --url http://192.168.1.200:8000
#   python tools/test_connection.py --url http://192.168.1.200:8000 --key abc123
#   python tools/test_connection.py --from-env   # read from .env file

import sys
import os
import argparse
import json
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import requests
except ImportError:
    print("[✗] 'requests' is not installed. Run: pip install requests")
    sys.exit(1)

GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

def ok(msg):   print(f"  {GREEN}[✓]{RESET} {msg}")
def warn(msg): print(f"  {YELLOW}[!]{RESET} {msg}")
def err(msg):  print(f"  {RED}[✗]{RESET} {msg}")
def info(msg): print(f"  {CYAN}[→]{RESET} {msg}")


def test_reachability(url: str) -> bool:
    info(f"Testing reachability: {url}")
    try:
        r = requests.get(f"{url}/", timeout=5)
        if r.status_code == 200:
            ok(f"Server is reachable (HTTP {r.status_code})")
            return True
        else:
            warn(f"Server responded with HTTP {r.status_code} — may still be starting up")
            return True
    except requests.exceptions.ConnectionError:
        err(f"Cannot reach server at {url}")
        err("Check that the server is running and port 8000 is open on the firewall.")
        return False
    except requests.exceptions.Timeout:
        err(f"Connection timed out after 5 seconds")
        return False


def test_registration(url: str) -> str | None:
    info("Testing agent registration endpoint...")
    payload = {
        "name": "heimdall-test-agent",
        "capabilities": "nmap_scan"
    }
    try:
        r = requests.post(f"{url}/agents/register", json=payload, timeout=10)
        if r.status_code == 200:
            api_key = r.json().get("api_key")
            ok(f"Registration successful — received API key")
            return api_key
        else:
            err(f"Registration failed: HTTP {r.status_code} — {r.text[:200]}")
            return None
    except Exception as e:
        err(f"Registration request failed: {e}")
        return None


def test_heartbeat(url: str, api_key: str) -> bool:
    info("Testing heartbeat endpoint...")
    try:
        r = requests.post(
            f"{url}/agents/heartbeat",
            headers={"x-api-key": api_key},
            timeout=5
        )
        if r.status_code == 200:
            ok("Heartbeat accepted")
            return True
        else:
            err(f"Heartbeat rejected: HTTP {r.status_code}")
            return False
    except Exception as e:
        err(f"Heartbeat request failed: {e}")
        return False


def test_job_poll(url: str, api_key: str) -> bool:
    info("Testing job polling endpoint...")
    try:
        r = requests.get(
            f"{url}/jobs/next",
            headers={"x-api-key": api_key, "x-agent-mode": "agent"},
            timeout=5
        )
        if r.status_code == 200:
            body = r.json()
            if body is None:
                ok("Job poll successful — no jobs pending (this is normal)")
            else:
                ok(f"Job poll successful — received job #{body.get('id')}")
            return True
        elif r.status_code == 401:
            err("Job poll rejected — invalid API key")
            return False
        else:
            err(f"Job poll failed: HTTP {r.status_code}")
            return False
    except Exception as e:
        err(f"Job poll request failed: {e}")
        return False


def test_existing_key(url: str, api_key: str) -> bool:
    """Test an existing API key without registering a new agent."""
    info(f"Testing existing API key: {api_key[:8]}...")
    try:
        r = requests.post(
            f"{url}/agents/heartbeat",
            headers={"x-api-key": api_key},
            timeout=5
        )
        if r.status_code == 200:
            ok("API key is valid")
            return True
        elif r.status_code == 401:
            err("API key is invalid or the agent no longer exists in the database")
            return False
        else:
            err(f"Unexpected response: HTTP {r.status_code}")
            return False
    except Exception as e:
        err(f"Request failed: {e}")
        return False


def load_from_env() -> tuple[str, str | None]:
    env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
    if not os.path.exists(env_path):
        warn(".env file not found — using defaults")
        return "http://127.0.0.1:8000", None

    url = "http://127.0.0.1:8000"
    key = None

    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if line.startswith("VAPT_SERVER_URL="):
                url = line.split("=", 1)[1].strip()
            if line.startswith("VAPT_KEY_FILE="):
                key_file = line.split("=", 1)[1].strip()
                if os.path.exists(key_file):
                    with open(key_file) as kf:
                        key = kf.read().strip()

    return url, key


def main():
    parser = argparse.ArgumentParser(description="Heimdall V-Scanner — Connection Tester")
    parser.add_argument("--url", default=None, help="Server URL (default: http://127.0.0.1:8000)")
    parser.add_argument("--key", default=None, help="Existing API key to test (skips registration)")
    parser.add_argument("--from-env", action="store_true", help="Load server URL and key from .env file")
    args = parser.parse_args()

    print(f"\n{BOLD}Heimdall V-Scanner — Connection Test{RESET}\n")

    # Resolve URL and key
    if args.from_env:
        url, key = load_from_env()
        info(f"Loaded from .env: {url}")
        if key:
            info(f"Found existing API key in key file")
    else:
        url = args.url or "http://127.0.0.1:8000"
        key = args.key

    print(f"  Server: {BOLD}{url}{RESET}\n")

    # Step 1: Reachability
    if not test_reachability(url):
        print()
        sys.exit(1)

    print()

    # Step 2: Use existing key or register
    if key:
        if not test_existing_key(url, key):
            print()
            sys.exit(1)
        api_key = key
    else:
        api_key = test_registration(url)
        if not api_key:
            print()
            sys.exit(1)

    print()

    # Step 3: Heartbeat
    heartbeat_ok = test_heartbeat(url, api_key)
    print()

    # Step 4: Job polling
    poll_ok = test_job_poll(url, api_key)
    print()

    # Summary
    all_ok = heartbeat_ok and poll_ok
    if all_ok:
        ok(f"All tests passed — this endpoint can communicate with the server at {url}")
    else:
        warn("Some tests failed — check the output above for details")

    if not key:
        warn("A test agent was registered during this run. You can dismiss it from the dashboard (Agents → Show Stale → Dismiss).")

    print()
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
