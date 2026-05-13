#!/usr/bin/env python3
# tools/test_ports.py
# Open or close a set of ports for scan testing using netcat listeners
#
# Usage:
#   python tools/test_ports.py open 22 80 443 445 3389
#   python tools/test_ports.py close
#   python tools/test_ports.py status

import sys
import os
import subprocess
import json
import signal

STATE_FILE = "/tmp/heimdall_test_ports.json"

GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def open_ports(ports: list[int]):
    pids = {}
    existing = load_state()
    if existing:
        print(f"  {YELLOW}[!]{RESET} Some ports already open — close them first with: python tools/test_ports.py close")
        return

    for port in ports:
        try:
            proc = subprocess.Popen(
                ["nc", "-lkp", str(port)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            pids[port] = proc.pid
            print(f"  {GREEN}[✓]{RESET} Port {port} open (pid {proc.pid})")
        except Exception as e:
            print(f"  {RED}[✗]{RESET} Failed to open port {port}: {e}")

    save_state(pids)
    print(f"\n  {CYAN}[→]{RESET} {len(pids)} port(s) open. Run 'close' when done.\n")

def close_ports():
    state = load_state()
    if not state:
        print(f"  {YELLOW}[!]{RESET} No tracked ports to close.")
        return

    for port, pid in state.items():
        try:
            os.kill(pid, signal.SIGTERM)
            print(f"  {GREEN}[✓]{RESET} Port {port} closed (pid {pid})")
        except ProcessLookupError:
            print(f"  {YELLOW}[!]{RESET} Port {port} — process {pid} already gone")
        except Exception as e:
            print(f"  {RED}[✗]{RESET} Port {port}: {e}")

    os.remove(STATE_FILE)
    print(f"\n  {CYAN}[→]{RESET} All test ports closed.\n")

def show_status():
    state = load_state()
    if not state:
        print(f"\n  No test ports currently open.\n")
        return

    print(f"\n  {BOLD}Open test ports:{RESET}")
    for port, pid in state.items():
        alive = is_running(pid)
        status = f"{GREEN}running{RESET}" if alive else f"{RED}dead{RESET}"
        print(f"    Port {port} — pid {pid} — {status}")
    print()

def is_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False

def save_state(pids: dict):
    with open(STATE_FILE, "w") as f:
        json.dump({str(k): v for k, v in pids.items()}, f)

def load_state() -> dict:
    if not os.path.exists(STATE_FILE):
        return {}
    with open(STATE_FILE) as f:
        return {int(k): v for k, v in json.load(f).items()}

def main():
    if len(sys.argv) < 2:
        print(f"\nUsage:")
        print(f"  python tools/test_ports.py open 22 80 443 445")
        print(f"  python tools/test_ports.py close")
        print(f"  python tools/test_ports.py status\n")
        sys.exit(1)

    command = sys.argv[1].lower()

    if command == "open":
        if len(sys.argv) < 3:
            print(f"  {RED}[✗]{RESET} Specify at least one port: open 22 80 443")
            sys.exit(1)
        ports = [int(p) for p in sys.argv[2:]]
        open_ports(ports)

    elif command == "close":
        close_ports()

    elif command == "status":
        show_status()

    else:
        print(f"  {RED}[✗]{RESET} Unknown command: {command}")
        sys.exit(1)

if __name__ == "__main__":
    main()
