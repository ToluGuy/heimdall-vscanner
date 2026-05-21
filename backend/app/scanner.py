# scanner.py
# Agentless remote scanner — runs on central server
# Picks up remote jobs and scans targets from the outside

import time
import json
import os
import logging
import requests
import subprocess
import xml.etree.ElementTree as ET
import tempfile
import threading

# --- LOGGING ---
os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(f"logs/scanner-{os.environ.get('VAPT_AGENT_NAME', 'scanner-1')}.log")
    ]
)
logger = logging.getLogger("vapt.scanner")

logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("requests").setLevel(logging.WARNING)

# --- CONFIG ---
SERVER_URL = os.environ.get("VAPT_SERVER_URL", "http://127.0.0.1:8000")
AGENT_NAME = os.environ.get("VAPT_AGENT_NAME", "scanner-1")
CAPABILITIES = os.environ.get("VAPT_CAPABILITIES", "nmap_scan,nikto_scan,nse_scan")
API_KEY_FILE = os.environ.get("VAPT_KEY_FILE", f"{AGENT_NAME}_key.txt")

# Web ports are Nikto's domain — NSE skips these automatically
WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888}


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

    logger.info(f"Registered as '{AGENT_NAME}'. API key saved.")
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


# --- NMAP ---

def get_nmap_flags(profile: str) -> list:
    if profile == "light":
        return ["-F"]
    elif profile == "full":
        return ["-sV", "-O", "-p-"]
    else:
        return ["-sV"]


def parse_nmap_xml(xml_data):
    root = ET.fromstring(xml_data)
    hosts = []

    for host in root.findall("host"):
        ip = None
        mac = None
        vendor = None
        for addr_el in host.findall("address"):
            atype = addr_el.get("addrtype", "")
            if atype in ("ipv4", "ipv6"):
                ip = addr_el.get("addr")
            elif atype == "mac":
                mac = addr_el.get("addr")
                vendor = addr_el.get("vendor")
        if not ip:
            continue

        hostname = None
        hostnames_el = host.find("hostnames")
        if hostnames_el is not None:
            for hn in hostnames_el.findall("hostname"):
                if hn.get("type") in ("PTR", "user"):
                    hostname = hn.get("name")
                    break

        os_name = None
        os_el = host.find("os")
        if os_el is not None:
            match = os_el.find("osmatch")
            if match is not None:
                os_name = match.get("name")

        ports_data = []
        ports = host.find("ports")
        if ports:
            for port in ports.findall("port"):
                state = port.find("state").get("state")
                svc_el = port.find("service")
                service = svc_el.get("name", "unknown") if svc_el is not None else "unknown"
                ports_data.append({
                    "port": int(port.get("portid")),
                    "state": state,
                    "service": service,
                })

        hosts.append({
            "host": ip,
            "mac": mac,
            "vendor": vendor,
            "hostname": hostname,
            "os": os_name,
            "ports": ports_data,
        })

    return hosts


def run_nmap(target: str, profile: str = "standard"):
    logger.info(f"Running Nmap ({profile}) on {target}")

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


# --- NSE ---

def get_nse_flags(profile: str) -> list:
    """
    Maps scan profile to NSE script intensity.
      light    -> --script safe      (non-intrusive, safe to run anywhere)
      standard -> --script vuln      (vulnerability checks, low disruption risk)
      full     -> --script vuln,exploit  (intrusive — may affect services)
    """
    if profile == "light":
        return ["--script", "safe"]
    elif profile == "full":
        return ["--script", "vuln,exploit"]
    else:
        return ["--script", "vuln"]


def parse_nse_from_xml(xml_data: str) -> list:
    """
    Parses Nmap XML output and extracts NSE script results from <script> elements.
    Returns a list of findings, each tied to the host/port they came from.
    """
    root = ET.fromstring(xml_data)
    findings = []

    for host in root.findall("host"):
        addr_el = host.find("address")
        if addr_el is None:
            continue
        addr = addr_el.get("addr")

        # host-level scripts (e.g. smb-vuln-*)
        hostscript = host.find("hostscript")
        if hostscript is not None:
            for script in hostscript.findall("script"):
                output = script.get("output", "").strip()
                if output.startswith("ERROR: Script execution failed"):
                    continue
                findings.append({
                    "host": addr,
                    "port": None,
                    "service": None,
                    "script_id": script.get("id"),
                    "output": output,
                })

        # port-level scripts
        ports_el = host.find("ports")
        if ports_el is None:
            continue

        for port_el in ports_el.findall("port"):
            portid = int(port_el.get("portid"))
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            service_el = port_el.find("service")
            service = service_el.get("name", "unknown") if service_el is not None else "unknown"

            for script in port_el.findall("script"):
                output = script.get("output", "").strip()
                if output.startswith("ERROR: Script execution failed"):
                    continue
                findings.append({
                    "host": addr,
                    "port": portid,
                    "service": service,
                    "script_id": script.get("id"),
                    "output": output,
                })

    return findings


def resolve_nse_ports(ports_str: str | None, profile: str) -> list[str]:
    """
    Resolves the -p flag list for an NSE scan.

    - If ports_str is provided, parse and exclude web ports.
    - If nothing remains after exclusion, return an empty list (caller handles warning).
    - If ports_str is blank, return [] meaning "use Nmap profile defaults" (no -p flag).
    """
    if not ports_str:
        return []

    requested = []
    for part in ports_str.split(","):
        part = part.strip()
        if part.isdigit():
            requested.append(int(part))

    non_web = [p for p in requested if p not in WEB_PORTS]
    return [str(p) for p in non_web]


def run_nse(target: str, profile: str = "standard", ports_str: str | None = None):
    """
    Runs an NSE scan against target.
    Web ports are excluded — Nikto owns that surface.
    Returns a dict with 'findings' (list) and optionally 'warning'.
    """
    logger.info(f"Running NSE ({profile}) on {target}")

    nse_flags = get_nse_flags(profile)
    port_list = resolve_nse_ports(ports_str, profile)

    # If the user specified ports but all were web ports, warn and bail out
    if ports_str and not port_list:
        warning = (
            "All specified ports are web ports (80, 443, 8080, 8443, 8000, 8888). "
            "NSE skips these — use a Nikto scan for web surface testing."
        )
        logger.warning(f"NSE job on {target}: {warning}")
        return {"findings": [], "warning": warning}

    cmd = ["nmap", "-sV", *nse_flags]

    if port_list:
        cmd += ["-p", ",".join(port_list)]
        logger.info(f"NSE port list (web ports excluded): {port_list}")
    else:
        logger.info("NSE using profile default port range")

    cmd += ["-oX", "-", target]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise Exception(f"NSE scan failed: {result.stderr}")

    findings = parse_nse_from_xml(result.stdout)
    logger.info(f"NSE complete — {len(findings)} finding(s) on {target}")

    return {"findings": findings}


# --- NIKTO ---

def get_nikto_flags(profile: str) -> list:
    if profile == "light":
        return ["-Tuning", "1"]
    elif profile == "full":
        return ["-Tuning", "x6"]
    else:
        return []


def run_nikto(target: str, port: int, profile: str = "standard"):
    logger.info(f"Running Nikto ({profile}) on {target}:{port}")

    flags = get_nikto_flags(profile)

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        result = subprocess.run(
            ["timeout", "90", "nikto", "-h", target, "-p", str(port),
             "-Format", "json", "-output", tmp_path,
             "-nolookup", *flags],
            input="n\n",
            capture_output=True,
            text=True,
            timeout=100
        )

        logger.debug(f"Nikto returncode: {result.returncode}")
        logger.debug(f"Nikto stderr: {result.stderr[:200] if result.stderr else 'none'}")

        # returncode 124 means `timeout` killed the process — treat as timeout
        if result.returncode == 124:
            logger.warning(f"Nikto timed out on {target}:{port}")
            return {"error": "Nikto timed out"}

        if os.path.exists(tmp_path):
            with open(tmp_path, "r", errors="replace") as f:
                content = f.read().strip()
            if content:
                try:
                    return json.loads(content)
                except json.JSONDecodeError:
                    safe = content[:4000] if len(content) > 4000 else content
                    return {"raw": safe}

        return {"raw": result.stdout[:4000] if result.stdout else (result.stderr[:1000] if result.stderr else "no output")}

    except subprocess.TimeoutExpired:
        logger.warning(f"Nikto subprocess timeout on {target}:{port}")
        return {"error": "Nikto timed out"}
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


# --- EXECUTION ENGINE ---

def execute_job(job: dict, api_key: str):
    job_type = job.get("type")
    target = job.get("target")
    job_id = job.get("id")
    mode = job.get("mode")
    profile = job.get("profile", "standard")
    port = job.get("port")       # single port (nikto_scan)
    ports = job.get("ports")     # comma-separated (nse_scan / multi-port nikto)

    if mode != "remote":
        logger.info(f"Job {job_id} is mode='{mode}', not for this scanner")
        return

    try:
        logger.info(f"Job {job_id} → {job_type} on {target} ({profile})")

        send_job_status(api_key, job_id, "running")

        if job_type == "nmap_scan":
            nmap_output = run_nmap(target, profile)

            web_ports = []
            for host in nmap_output:
                for port_info in host.get("ports", []):
                    if port_info["state"] == "open" and port_info["port"] in WEB_PORTS:
                        web_ports.append(port_info["port"])

            output = {"nmap": nmap_output}

            if web_ports:
                logger.info(f"Web ports found: {web_ports} — running Nikto")
                nikto_results = {}
                for wp in web_ports:
                    try:
                        nikto_results[str(wp)] = run_nikto(target, wp, profile)
                    except Exception as e:
                        nikto_results[str(wp)] = {"error": str(e)}
                output["nikto"] = nikto_results
            else:
                logger.debug(f"No web ports found on {target}, skipping Nikto")

        elif job_type == "nikto_scan":
            scan_port = int(port) if port else 80
            logger.info(f"Standalone Nikto scan on {target}:{scan_port}")
            nikto_result = run_nikto(target, scan_port, profile)
            output = {"nikto": {str(scan_port): nikto_result}}

        elif job_type == "nse_scan":
            nse_result = run_nse(target, profile, ports)
            output = {"nse": nse_result}

        else:
            output = {"error": f"Unsupported job type: {job_type}"}

        logger.info(f"Job {job_id} complete")

        send_result(api_key, job_id, json.dumps(output))
        send_job_status(api_key, job_id, "done")

        logger.info(f"Job {job_id} result and status sent")

    except Exception as e:
        logger.error(f"Job {job_id} execution failed: {e}")
        send_job_status(api_key, job_id, "failed")


def heartbeat_loop(api_key):
    """Sends heartbeats every 10 seconds regardless of scan activity."""
    import time as _time
    while True:
        send_heartbeat(api_key)
        _time.sleep(10)


# --- MAIN LOOP ---

def main():
    api_key = load_api_key()

    if not api_key:
        api_key = register()

    logger.info(f"Remote scanner '{AGENT_NAME}' started, polling for jobs...")
    
    hb_thread = threading.Thread(target=heartbeat_loop, args=(api_key,), daemon=True)
    hb_thread.start()

    while True:
        try:
            send_heartbeat(api_key)
            job = get_job(api_key)

            if job:
                logger.info(f"Received job: {job}")
                execute_job(job, api_key)
            else:
                logger.info("No remote jobs available")

        except Exception as e:
            logger.error(f"Main loop error: {e}")

        time.sleep(10)


if __name__ == "__main__":
    main()
