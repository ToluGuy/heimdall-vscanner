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

# Ports that are recognised as web ports but should NOT be auto-scanned by Nikto.
# Port 8000 is excluded because it is typically the Heimdall backend itself —
# scanning it with Nikto is meaningless and reliably times out.
NIKTO_SKIP_PORTS = {8000}

# --- CUSTOM PROFILE: SCRIPT → PORT MAPPING ---
#
# Maps each NSE script name to the TCP ports it targets.
# Used to auto-derive the -p flag when running a custom profile scan.
# Scripts not listed here get no dedicated port added — they rely on Nmap's
# default service discovery or host-level execution.
#
# UDP ports are handled separately in CUSTOM_SCRIPT_UDP_PORTS.

CUSTOM_SCRIPT_TCP_PORTS: dict[str, list[int]] = {
    # ── Auth & Access Control ──────────────────────────────────────────────
    "ftp-anon":              [21],
    "http-auth-finder":      [80, 443, 8080, 8443],
    "ssh-auth-methods":      [22],
    "snmp-brute":            [],          # UDP — handled separately
    "smb-security-mode":     [445, 139],
    "http-open-proxy":       [80, 443, 8080, 8443, 3128, 8118],
    "irc-unrealircd-backdoor": [6667, 6697],

    # ── Windows & SMB Enumeration ──────────────────────────────────────────
    "smb-os-discovery":      [445, 139],
    "smb-system-info":       [445, 139],
    "smb-enum-shares":       [445, 139],
    "smb-vuln-ms17-010":     [445],
    "smb-vuln-ms10-054":     [445],
    "smb-enum-users":        [445, 139],
    "smb-enum-groups":       [445, 139],
    "smb-enum-sessions":     [445, 139],
    "smb-enum-domains":      [445, 139],

    # ── SNMP & Network Device Enumeration ──────────────────────────────────
    "snmp-info":             [],          # UDP
    "snmp-sysdescr":         [],          # UDP
    "snmp-interfaces":       [],          # UDP
    "snmp-netstat":          [],          # UDP
    "snmp-processes":        [],          # UDP
    "snmp-win32-users":      [],          # UDP
    "snmp-win32-shares":     [],          # UDP

    # ── SSL/TLS Analysis ───────────────────────────────────────────────────
    "ssl-cert":              [443, 8443, 993, 995, 465, 636, 3389],
    "ssl-enum-ciphers":      [443, 8443, 993, 995, 465, 636, 3389],
    "ssl-heartbleed":        [443, 8443],
    "ssl-poodle":            [443, 8443],
    "ssl-dh-params":         [443, 8443],
    "ssl-ccs-injection":     [443, 8443],
    "tls-ticketbleed":       [443, 8443],
    "ssl-known-key":         [443, 8443],

    # ── Network Service Discovery ──────────────────────────────────────────
    "dns-zone-transfer":     [53],
    "dns-recursion":         [53],
    "nfs-ls":                [2049, 111],
    "nfs-showmount":         [2049, 111],
    "rdp-enum-encryption":   [3389],
    "telnet-encryption":     [23],
    "vnc-info":              [5900, 5901, 5902],
    "finger":                [79],
    "broadcast-dhcp-discover": [],       # broadcast — no specific target port
    "ldap-rootdse":          [389, 636],
}

# Scripts that run over UDP — added as a separate protocol argument
CUSTOM_SCRIPT_UDP_PORTS: dict[str, list[int]] = {
    "snmp-brute":            [161],
    "snmp-info":             [161],
    "snmp-sysdescr":         [161],
    "snmp-interfaces":       [161],
    "snmp-netstat":          [161],
    "snmp-processes":        [161],
    "snmp-win32-users":      [161],
    "snmp-win32-shares":     [161],
}


def derive_custom_ports(scripts: list[str]) -> tuple[list[int], list[int]]:
    """
    Given a list of selected NSE script names, returns two lists:
      (tcp_ports, udp_ports)

    TCP ports are deduplicated and sorted. Web ports (80, 443, etc.) are
    included here because SSL/TLS scripts legitimately need them — unlike
    standard NSE scans, custom profiles explicitly choose those scripts.
    """
    tcp: set[int] = set()
    udp: set[int] = set()

    for script in scripts:
        for port in CUSTOM_SCRIPT_TCP_PORTS.get(script, []):
            tcp.add(port)
        for port in CUSTOM_SCRIPT_UDP_PORTS.get(script, []):
            udp.add(port)

    return sorted(tcp), sorted(udp)


def build_custom_nmap_command(
    target: str,
    scripts: list[str],
    tcp_ports: list[int],
    udp_ports: list[int],
) -> list[str]:
    """
    Constructs the nmap command for a custom profile scan.

    Strategy:
    - Always run -sV for service detection (scripts need it)
    - If TCP ports derived: add -p <ports>
    - If UDP ports derived: add -sU and merge UDP ports into the -p flag
      using the T:<tcp>/U:<udp> syntax
    - If no ports at all (broadcast/host-level scripts only): no -p flag,
      rely on Nmap defaults
    - --script takes the comma-joined list of selected scripts
    """
    script_str = ",".join(scripts)
    cmd = ["nmap", "-sV", "--script", script_str]

    if tcp_ports and udp_ports:
        # Mixed TCP + UDP — use T:/U: prefix syntax
        tcp_str = ",".join(str(p) for p in tcp_ports)
        udp_str = ",".join(str(p) for p in udp_ports)
        cmd += ["-sU", "-p", f"T:{tcp_str},U:{udp_str}"]
    elif tcp_ports:
        cmd += ["-p", ",".join(str(p) for p in tcp_ports)]
    elif udp_ports:
        udp_str = ",".join(str(p) for p in udp_ports)
        cmd += ["-sU", "-p", f"U:{udp_str}"]
    # else: no -p flag — Nmap will use its default port range

    cmd += ["-oX", "-", target]
    return cmd


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


def is_job_cancelled(api_key: str, job_id: int) -> bool:
    """Poll the server to check if a job has been cancelled mid-execution."""
    try:
        res = requests.get(
            f"{SERVER_URL}/jobs/{job_id}/status",
            headers={"x-api-key": api_key},
            timeout=5,
        )
        if res.status_code == 200:
            return res.json().get("status") == "cancelled"
    except Exception:
        pass
    return False


# --- AGENT HEALTH ---

def send_heartbeat(api_key):
    headers = {"x-api-key": api_key}

    try:
        requests.post(
            f"{SERVER_URL}/agents/heartbeat",
            headers=headers,
            timeout=5,
        )
    except Exception:
        pass


# --- NMAP ---

def get_nmap_flags(profile: str) -> list:
    if profile == "light":
        return ["-F"]
    elif profile == "full":
        return ["-sV", "-O", "-p-"]
    else:
        return ["-sV"]


def parse_nmap_xml(xml_data: str) -> list:
    root = ET.fromstring(xml_data)
    hosts = []

    for host in root.findall("host"):
        # ── IP address + MAC ──────────────────────────────────────────────
        ip = None
        mac = None
        for addr_el in host.findall("address"):
            atype = addr_el.get("addrtype", "")
            if atype in ("ipv4", "ipv6"):
                ip = addr_el.get("addr")
            elif atype == "mac":
                mac = addr_el.get("addr")

        if ip is None:
            continue  # skip hosts with no IP (shouldn't happen but be safe)

        # ── Hostname ──────────────────────────────────────────────────────
        hostname = None
        hostnames_el = host.find("hostnames")
        if hostnames_el is not None:
            for hn in hostnames_el.findall("hostname"):
                name = hn.get("name", "").strip()
                if name:
                    hostname = name
                    break  # take the first non-empty one

        # ── OS fingerprint ────────────────────────────────────────────────
        os_guess = None
        os_el = host.find("os")
        if os_el is not None:
            best_match = None
            best_accuracy = -1
            for osmatch in os_el.findall("osmatch"):
                try:
                    accuracy = int(osmatch.get("accuracy", "0"))
                except ValueError:
                    accuracy = 0
                if accuracy > best_accuracy:
                    best_accuracy = accuracy
                    best_match = osmatch.get("name", "").strip()
            if best_match:
                os_guess = best_match

        # ── Ports ─────────────────────────────────────────────────────────
        ports_data = []
        ports_el = host.find("ports")
        if ports_el:
            for port in ports_el.findall("port"):
                state_el = port.find("state")
                service_el = port.find("service")
                state = state_el.get("state") if state_el is not None else "unknown"
                service = service_el.get("name", "unknown") if service_el is not None else "unknown"
                ports_data.append({
                    "port": int(port.get("portid")),
                    "state": state,
                    "service": service,
                })

        hosts.append({
            "host": ip,
            "mac": mac,
            "hostname": hostname,
            "os": os_guess,
            "ports": ports_data,
        })

    return hosts


def run_nmap(target: str, profile: str = "standard") -> list:
    logger.info(f"Running Nmap ({profile}) on {target}")

    flags = get_nmap_flags(profile)

    result = subprocess.run(
        ["nmap", *flags, "-oX", "-", target],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise Exception(f"Nmap failed: {result.stderr}")

    return parse_nmap_xml(result.stdout)


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
        # ── IP address — iterate all address elements to avoid picking up MAC ──
        addr = None
        for addr_el in host.findall("address"):
            atype = addr_el.get("addrtype", "")
            if atype in ("ipv4", "ipv6"):
                addr = addr_el.get("addr")
                break

        if addr is None:
            continue

        # ── Host-level scripts (e.g. smb-vuln-*) ─────────────────────────
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

        # ── Port-level scripts ────────────────────────────────────────────
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


def resolve_nse_ports(ports_str: str | None) -> tuple[list[str], str | None]:
    """
    Resolves the -p flag list for a standard NSE scan.

    Web ports are no longer filtered out — users can scan any port they choose.
    If the requested list includes web ports, a soft advisory is returned alongside
    the port list so the result card can display it.

    Returns (port_list, advisory_message | None).
    """
    if not ports_str:
        return [], None

    requested = []
    for part in ports_str.split(","):
        part = part.strip()
        if part.isdigit():
            requested.append(int(part))

    if not requested:
        return [], None

    web_in_request = [p for p in requested if p in WEB_PORTS]
    advisory = None
    if web_in_request:
        advisory = (
            f"Port(s) {web_in_request} are web ports. NSE vulnerability scripts may have "
            "limited coverage on web services — consider also running a Web Scan (Nikto) "
            "for deeper web surface testing."
        )

    return [str(p) for p in requested], advisory


def run_nse(target: str, profile: str = "standard", ports_str: str | None = None) -> dict:
    """
    Runs a standard NSE scan against target.
    All requested ports are scanned — web ports are no longer excluded.
    If web ports are included, a soft advisory is added to the result.
    Returns a dict with 'findings' (list) and optionally 'advisory'.
    """
    logger.info(f"Running NSE ({profile}) on {target}")

    nse_flags = get_nse_flags(profile)
    port_list, advisory = resolve_nse_ports(ports_str)

    cmd = ["nmap", "-sV", *nse_flags]

    if port_list:
        cmd += ["-p", ",".join(port_list)]
        logger.info(f"NSE port list: {port_list}")
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

    out: dict = {"findings": findings}
    if advisory:
        out["advisory"] = advisory
    return out


def run_custom_nse(target: str, scripts: list[str]) -> dict:
    """
    Runs a custom NSE scan using only the explicitly selected scripts.
    Port targeting is derived automatically from the script list.

    Unlike standard NSE, custom scans:
    - Do NOT blanket-exclude web ports (SSL scripts legitimately need 443)
    - Use a derived port list rather than Nmap's default range
    - Run exactly the scripts the user chose, nothing more
    """
    if not scripts:
        return {"findings": [], "warning": "No scripts selected for custom scan."}

    logger.info(f"Running custom NSE on {target} — {len(scripts)} script(s): {', '.join(scripts)}")

    tcp_ports, udp_ports = derive_custom_ports(scripts)
    cmd = build_custom_nmap_command(target, scripts, tcp_ports, udp_ports)

    logger.info(f"Custom NSE command: {' '.join(cmd)}")
    if tcp_ports:
        logger.info(f"  TCP ports targeted: {tcp_ports}")
    if udp_ports:
        logger.info(f"  UDP ports targeted: {udp_ports}")
    if not tcp_ports and not udp_ports:
        logger.info("  No ports derived — using Nmap default range")

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise Exception(f"Custom NSE scan failed: {result.stderr}")

    findings = parse_nse_from_xml(result.stdout)
    logger.info(f"Custom NSE complete — {len(findings)} finding(s) on {target}")

    return {
        "findings": findings,
        "scripts_used": scripts,
        "tcp_ports": tcp_ports,
        "udp_ports": udp_ports,
    }


# --- NIKTO ---

def get_nikto_flags(profile: str, nikto_tuning: list = None) -> list:
    if profile == "custom" and nikto_tuning:
        # Join selected tuning codes into a single string e.g. "049" for categories 0, 4, 9
        return ["-Tuning", "".join(nikto_tuning)]
    elif profile == "light":
        return ["-Tuning", "1"]
    elif profile == "full":
        return ["-Tuning", "x6"]
    else:
        return []


def run_nikto(target: str, port: int, profile: str = "standard", nikto_tuning: list = None) -> dict:
    logger.info(f"Running Nikto ({profile}) on {target}:{port}")

    flags = get_nikto_flags(profile, nikto_tuning)

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

        if os.path.exists(tmp_path):
            with open(tmp_path, "r") as f:
                content = f.read().strip()
            if content:
                try:
                    return json.loads(content)
                except json.JSONDecodeError:
                    return {"raw": content}

        return {"raw": result.stdout or result.stderr or "no output"}

    except subprocess.TimeoutExpired:
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
    port = job.get("port")            # single port (nikto_scan)
    ports = job.get("ports")          # comma-separated (nse_scan / multi-port nikto)
    custom_scripts = job.get("custom_scripts")  # list of script names (custom profile)
    nikto_tuning = job.get("nikto_tuning")      # list of tuning category codes (custom nikto profile)
    auto_nikto = job.get("auto_nikto", True)    # whether to auto-run Nikto after nmap_scan

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

            # Check for cancellation before starting Nikto (which can be slow)
            if is_job_cancelled(api_key, job_id):
                logger.info(f"Job {job_id} was cancelled — stopping after nmap")
                send_job_status(api_key, job_id, "cancelled")
                return

            if web_ports and auto_nikto:
                logger.info(f"Web ports found: {web_ports} — running Nikto (auto_nikto=on)")
                nikto_results = {}
                for wp in web_ports:
                    if wp in NIKTO_SKIP_PORTS:
                        logger.info(f"Port {wp} in skip list — omitting from Nikto")
                        continue
                    try:
                        nikto_results[str(wp)] = run_nikto(target, wp, profile)
                    except Exception as e:
                        nikto_results[str(wp)] = {"error": str(e)}
                if nikto_results:
                    output["nikto"] = nikto_results
            elif web_ports and not auto_nikto:
                logger.info(f"Web ports found: {web_ports} — skipping Nikto (auto_nikto=off)")
            else:
                logger.debug(f"No web ports found on {target}, skipping Nikto")

        elif job_type == "nikto_scan":
            scan_port = int(port) if port else 80
            logger.info(f"Standalone Nikto scan on {target}:{scan_port}")
            nikto_result = run_nikto(target, scan_port, profile, nikto_tuning)
            output = {"nikto": {str(scan_port): nikto_result}}

        elif job_type == "nse_scan":
            if profile == "custom":
                # Custom profile — use explicitly selected scripts
                scripts = custom_scripts if custom_scripts else []
                if not scripts:
                    logger.warning(f"Job {job_id} is custom profile but has no scripts — falling back to standard vuln scan")
                    nse_result = run_nse(target, "standard", ports)
                else:
                    nse_result = run_custom_nse(target, scripts)
                output = {"nse": nse_result}
            else:
                # Standard / light / full profile
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

def recover_interrupted_jobs(api_key: str):
    """
    On startup, tell the server to mark any jobs that were assigned to this
    scanner and left in 'running' status as 'failed'. This handles the case
    where the scanner was killed mid-execution.
    """
    try:
        res = requests.post(
            f"{SERVER_URL}/agents/recover",
            headers={"x-api-key": api_key},
            timeout=10,
        )
        if res.status_code == 200:
            data = res.json()
            recovered = data.get("recovered", 0)
            if recovered:
                logger.warning(f"Crash recovery: marked {recovered} interrupted job(s) as failed")
        else:
            logger.debug(f"Crash recovery endpoint returned {res.status_code}")
    except Exception as e:
        logger.debug(f"Crash recovery check failed: {e}")


def main():
    api_key = load_api_key()

    if not api_key:
        api_key = register()

    logger.info(f"Remote scanner '{AGENT_NAME}' started, polling for jobs...")

    # Recover any jobs left 'running' from a previous crash
    recover_interrupted_jobs(api_key)

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
