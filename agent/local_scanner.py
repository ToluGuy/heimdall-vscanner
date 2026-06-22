# local_scanner.py
# Heimdall V-Scanner — standalone workstation tool
# Runs a local web server, opens a browser, lets the user scan from their
# own machine without needing the central server.
#
# Supports: nmap_scan, nse_scan (standard, light, full, custom)
# Does NOT require: central server, database, Nikto, Perl
#
# Usage:
#   python local_scanner.py
#   python local_scanner.py --port 9999   # custom port
#   python local_scanner.py --no-browser  # don't auto-open browser

import argparse
import json
import os
import socket
import subprocess
import sys
import threading
import time
import webbrowser
import xml.etree.ElementTree as ET
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

# ── in-memory result store ────────────────────────────────────────────────────
_results = []
_results_lock = threading.Lock()
_scan_running = False
_scan_lock = threading.Lock()


def find_free_port(preferred: int = 9731) -> int:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", preferred))
            return preferred
    except OSError:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]


# ── scan logic ────────────────────────────────────────────────────────────────

WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888}

# ── Custom profile: script → port mapping ─────────────────────────────────────

CUSTOM_SCRIPT_TCP_PORTS: dict[str, list[int]] = {
    "ftp-anon":               [21],
    "http-auth-finder":       [80, 443, 8080, 8443],
    "ssh-auth-methods":       [22],
    "snmp-brute":             [],
    "smb-security-mode":      [445, 139],
    "http-open-proxy":        [80, 443, 8080, 8443, 3128, 8118],
    "irc-unrealircd-backdoor":[6667, 6697],
    "smb-os-discovery":       [445, 139],
    "smb-system-info":        [445, 139],
    "smb-enum-shares":        [445, 139],
    "smb-vuln-ms17-010":      [445],
    "smb-vuln-ms10-054":      [445],
    "smb-enum-users":         [445, 139],
    "smb-enum-groups":        [445, 139],
    "smb-enum-sessions":      [445, 139],
    "smb-enum-domains":       [445, 139],
    "snmp-info":              [],
    "snmp-sysdescr":          [],
    "snmp-interfaces":        [],
    "snmp-netstat":           [],
    "snmp-processes":         [],
    "snmp-win32-users":       [],
    "snmp-win32-shares":      [],
    "ssl-cert":               [443, 8443, 993, 995, 465, 636, 3389],
    "ssl-enum-ciphers":       [443, 8443, 993, 995, 465, 636, 3389],
    "ssl-heartbleed":         [443, 8443],
    "ssl-poodle":             [443, 8443],
    "ssl-dh-params":          [443, 8443],
    "ssl-ccs-injection":      [443, 8443],
    "tls-ticketbleed":        [443, 8443],
    "ssl-known-key":          [443, 8443],
    "dns-zone-transfer":      [53],
    "dns-recursion":          [53],
    "nfs-ls":                 [2049, 111],
    "nfs-showmount":          [2049, 111],
    "rdp-enum-encryption":    [3389],
    "telnet-encryption":      [23],
    "vnc-info":               [5900, 5901, 5902],
    "finger":                 [79],
    "broadcast-dhcp-discover":[],
    "ldap-rootdse":           [389, 636],
}

CUSTOM_SCRIPT_UDP_PORTS: dict[str, list[int]] = {
    "snmp-brute":      [161],
    "snmp-info":       [161],
    "snmp-sysdescr":   [161],
    "snmp-interfaces": [161],
    "snmp-netstat":    [161],
    "snmp-processes":  [161],
    "snmp-win32-users":[161],
    "snmp-win32-shares":[161],
}


def derive_custom_ports(scripts: list[str]) -> tuple[list[int], list[int]]:
    tcp: set[int] = set()
    udp: set[int] = set()
    for script in scripts:
        for port in CUSTOM_SCRIPT_TCP_PORTS.get(script, []):
            tcp.add(port)
        for port in CUSTOM_SCRIPT_UDP_PORTS.get(script, []):
            udp.add(port)
    return sorted(tcp), sorted(udp)


def build_custom_nmap_command(target: str, scripts: list[str],
                               tcp_ports: list[int], udp_ports: list[int]) -> list[str]:
    script_str = ",".join(scripts)
    cmd = ["nmap", "-sV", "--script", script_str]
    if tcp_ports and udp_ports:
        tcp_str = ",".join(str(p) for p in tcp_ports)
        udp_str = ",".join(str(p) for p in udp_ports)
        cmd += ["-sU", "-p", f"T:{tcp_str},U:{udp_str}"]
    elif tcp_ports:
        cmd += ["-p", ",".join(str(p) for p in tcp_ports)]
    elif udp_ports:
        cmd += ["-sU", "-p", f"U:{','.join(str(p) for p in udp_ports)}"]
    cmd += ["-oX", "-", target]
    return cmd


def get_nmap_flags(profile: str) -> list:
    if profile == "light":
        return ["-F"]
    elif profile == "full":
        return ["-sV", "-O", "-p-"]
    return ["-sV"]


def get_nse_flags(profile: str) -> list:
    if profile == "light":
        return ["--script", "safe"]
    elif profile == "full":
        return ["--script", "vuln,exploit"]
    return ["--script", "vuln"]


def parse_nmap_xml(xml_data: str) -> list:
    root = ET.fromstring(xml_data)
    hosts = []
    for host in root.findall("host"):
        ip = None
        for addr_el in host.findall("address"):
            atype = addr_el.get("addrtype", "")
            if atype in ("ipv4", "ipv6"):
                ip = addr_el.get("addr")
                break
        if ip is None:
            continue
        ports_data = []
        ports_el = host.find("ports")
        if ports_el:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                service_el = port_el.find("service")
                ports_data.append({
                    "port": int(port_el.get("portid")),
                    "state": state_el.get("state") if state_el is not None else "unknown",
                    "service": service_el.get("name", "unknown") if service_el is not None else "unknown",
                })
        hosts.append({"host": ip, "ports": ports_data})
    return hosts


def parse_nse_xml(xml_data: str) -> list:
    root = ET.fromstring(xml_data)
    findings = []
    for host in root.findall("host"):
        addr = None
        for addr_el in host.findall("address"):
            atype = addr_el.get("addrtype", "")
            if atype in ("ipv4", "ipv6"):
                addr = addr_el.get("addr")
                break
        if addr is None:
            continue

        hostscript = host.find("hostscript")
        if hostscript is not None:
            for script in hostscript.findall("script"):
                output = script.get("output", "").strip()
                if output.startswith("ERROR: Script execution failed"):
                    continue
                findings.append({
                    "host": addr, "port": None, "service": None,
                    "script_id": script.get("id"), "output": output,
                })

        ports_el = host.find("ports")
        if ports_el is None:
            continue
        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            portid = int(port_el.get("portid"))
            service_el = port_el.find("service")
            service = service_el.get("name", "unknown") if service_el is not None else "unknown"
            for script in port_el.findall("script"):
                output = script.get("output", "").strip()
                if output.startswith("ERROR: Script execution failed"):
                    continue
                findings.append({
                    "host": addr, "port": portid, "service": service,
                    "script_id": script.get("id"), "output": output,
                })
    return findings


def run_nmap_scan(target: str, profile: str) -> dict:
    flags = get_nmap_flags(profile)
    cmd = ["nmap", *flags, "-oX", "-", target]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if result.returncode != 0:
        raise RuntimeError(f"nmap failed: {result.stderr[:300]}")
    return {"nmap": parse_nmap_xml(result.stdout)}


def run_nse_scan(target: str, profile: str, ports_str: str,
                 custom_scripts: list[str] | None = None) -> dict:
    """
    Runs an NSE scan. If profile is 'custom' and custom_scripts is provided,
    uses those scripts with auto-derived ports. Otherwise uses the profile flags.
    Web ports are no longer filtered — an advisory note is included if relevant.
    """
    if profile == "custom" and custom_scripts:
        if not custom_scripts:
            return {"nse": {"findings": [], "advisory": "No scripts selected."}}
        tcp_ports, udp_ports = derive_custom_ports(custom_scripts)
        cmd = build_custom_nmap_command(target, custom_scripts, tcp_ports, udp_ports)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if result.returncode != 0:
            raise RuntimeError(f"nmap custom NSE failed: {result.stderr[:300]}")
        findings = parse_nse_xml(result.stdout)
        return {"nse": {
            "findings": findings,
            "scripts_used": custom_scripts,
            "tcp_ports": tcp_ports,
            "udp_ports": udp_ports,
        }}

    # Standard / light / full profile
    nse_flags = get_nse_flags(profile)
    cmd = ["nmap", "-sV", *nse_flags]
    advisory = None

    if ports_str:
        requested = [int(p.strip()) for p in ports_str.split(",") if p.strip().isdigit()]
        web_in_request = [p for p in requested if p in WEB_PORTS]
        if web_in_request:
            advisory = (
                f"Port(s) {web_in_request} are web ports. NSE scripts may have limited "
                "coverage here — consider a dedicated Web Scan for thorough web testing."
            )
        if requested:
            cmd += ["-p", ",".join(str(p) for p in requested)]

    cmd += ["-oX", "-", target]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if result.returncode != 0:
        raise RuntimeError(f"nmap NSE failed: {result.stderr[:300]}")
    findings = parse_nse_xml(result.stdout)
    out = {"nse": {"findings": findings}}
    if advisory:
        out["nse"]["advisory"] = advisory
    return out


def execute_scan(scan_id: str, scan_type: str, target: str, profile: str,
                 ports: str, custom_scripts: list[str] | None = None):
    global _scan_running
    started_at = datetime.now().isoformat()
    try:
        if scan_type == "nmap_scan":
            output = run_nmap_scan(target, profile)
        elif scan_type == "nse_scan":
            output = run_nse_scan(target, profile, ports, custom_scripts)
        else:
            output = {"error": f"Unknown scan type: {scan_type}"}
        status = "done"
    except Exception as e:
        output = {"error": str(e)}
        status = "failed"

    completed_at = datetime.now().isoformat()
    with _results_lock:
        _results.append({
            "id": scan_id,
            "scan_type": scan_type,
            "target": target,
            "profile": profile,
            "custom_scripts": custom_scripts,
            "status": status,
            "started_at": started_at,
            "completed_at": completed_at,
            "output": output,
        })
    with _scan_lock:
        _scan_running = False


# ── dashboard HTML ─────────────────────────────────────────────────────────────

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Heimdall // Local Scanner</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap');

  :root {
    --bg:        #0b0e14;
    --surface:   #111520;
    --surface2:  #161b28;
    --border:    #1e2535;
    --border2:   #2a3347;
    --green:     #00e5a0;
    --green-dim: #00a870;
    --blue:      #4d9fff;
    --purple:    #a78bfa;
    --yellow:    #f5c842;
    --orange:    #f97316;
    --red:       #f04f4f;
    --text:      #d4dbe8;
    --muted:     #5a6a82;
    --mono:      'IBM Plex Mono', monospace;
    --sans:      'IBM Plex Sans', sans-serif;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: var(--sans); min-height: 100vh; font-size: 14px; line-height: 1.6; }

  body::before {
    content: ''; position: fixed; inset: 0;
    background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,229,160,0.012) 2px, rgba(0,229,160,0.012) 4px);
    pointer-events: none; z-index: 9999;
  }

  header { border-bottom: 1px solid var(--border); padding: 14px 28px; display: flex; align-items: center; gap: 14px; background: var(--surface); position: sticky; top: 0; z-index: 100; }
  .logo-dot { width: 9px; height: 9px; border-radius: 50%; background: var(--green); box-shadow: 0 0 8px var(--green); animation: pulse 2s ease-in-out infinite; flex-shrink: 0; }
  @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.35; } }
  .logo-text { font-family: var(--mono); font-size: 12px; font-weight: 600; color: var(--green); letter-spacing: 0.14em; text-transform: uppercase; }
  .logo-sub { font-family: var(--mono); font-size: 10px; color: var(--muted); margin-left: auto; }

  main { max-width: 980px; margin: 0 auto; padding: 28px 20px; display: flex; flex-direction: column; gap: 20px; }

  .panel { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
  .panel-header { padding: 13px 20px; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 10px; }
  .panel-title { font-family: var(--mono); font-size: 10px; font-weight: 600; letter-spacing: 0.12em; text-transform: uppercase; color: var(--muted); }
  .panel-body { padding: 20px; }

  .form-grid { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 14px; margin-bottom: 16px; }
  .field { display: flex; flex-direction: column; gap: 5px; }
  label { font-family: var(--mono); font-size: 10px; font-weight: 500; letter-spacing: 0.08em; text-transform: uppercase; color: var(--muted); }

  input, select { background: var(--bg); border: 1px solid var(--border2); border-radius: 5px; color: var(--text); font-family: var(--mono); font-size: 13px; padding: 8px 12px; outline: none; transition: border-color 0.15s; width: 100%; }
  input:focus, select:focus { border-color: var(--green-dim); }
  input::placeholder { color: var(--muted); }
  select option { background: var(--surface); }

  .ports-field { grid-column: 1 / -1; display: none; }
  .ports-field.visible { display: flex; flex-direction: column; gap: 5px; }

  .actions { display: flex; gap: 10px; align-items: center; }

  .btn { font-family: var(--mono); font-size: 11px; font-weight: 600; letter-spacing: 0.06em; padding: 9px 22px; border-radius: 5px; border: none; cursor: pointer; transition: all 0.15s; text-transform: uppercase; }
  .btn-primary { background: var(--green); color: #000; }
  .btn-primary:hover { background: #00ffb2; }
  .btn-primary:disabled { background: var(--border2); color: var(--muted); cursor: not-allowed; }
  .btn-secondary { background: transparent; color: var(--muted); border: 1px solid var(--border2); }
  .btn-secondary:hover { border-color: var(--blue); color: var(--blue); }
  .btn-ghost { background: transparent; color: var(--red); border: 1px solid transparent; padding: 4px 8px; font-size: 11px; }
  .btn-ghost:hover { border-color: var(--red); }

  /* Custom capability cards */
  .custom-panel { display: none; margin-top: 18px; padding-top: 18px; border-top: 1px solid var(--border); }
  .custom-panel.visible { display: block; }
  .custom-panel-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; }
  .custom-panel-title { font-family: var(--mono); font-size: 10px; font-weight: 600; letter-spacing: 0.1em; text-transform: uppercase; color: var(--green); }
  .custom-actions { display: flex; gap: 12px; align-items: center; }
  .custom-action-btn { font-family: var(--mono); font-size: 10px; color: var(--muted); background: none; border: none; cursor: pointer; text-decoration: underline; }
  .custom-action-btn:hover { color: var(--text); }
  .script-count { font-family: var(--mono); font-size: 10px; color: var(--muted); }

  .cap-card { background: var(--surface2); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 8px; overflow: hidden; }
  .cap-card:last-child { margin-bottom: 0; }
  .cap-header { display: flex; align-items: center; gap: 10px; padding: 10px 14px; }
  .cap-label-wrap { flex: 1; cursor: pointer; min-width: 0; }
  .cap-label { font-size: 13px; font-weight: 500; color: var(--text); }
  .cap-count { font-family: var(--mono); font-size: 10px; color: var(--muted); margin-left: 8px; }
  .cap-chevron { font-size: 9px; color: var(--muted); cursor: pointer; flex-shrink: 0; transition: transform 0.15s; }
  .cap-chevron.open { transform: rotate(180deg); }
  .cap-scripts { display: none; padding: 0 14px 10px; border-top: 1px solid var(--border); }
  .cap-scripts.open { display: block; }
  .script-row { display: flex; align-items: center; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid rgba(255,255,255,0.04); }
  .script-row:last-child { border-bottom: none; }
  .script-label { font-family: var(--mono); font-size: 11px; color: var(--text); }
  .sensitive-tag { font-family: var(--mono); font-size: 9px; padding: 1px 5px; border-radius: 3px; background: rgba(255,255,255,0.05); border: 1px solid var(--border); color: var(--muted); margin-left: 6px; }

  /* Toggle switch */
  .toggle { position: relative; width: 32px; height: 16px; border-radius: 8px; border: none; cursor: pointer; transition: background 0.15s; flex-shrink: 0; }
  .toggle.off { background: var(--border2); }
  .toggle.on  { background: var(--green-dim); }
  .toggle-knob { position: absolute; top: 2px; left: 2px; width: 12px; height: 12px; border-radius: 50%; background: #fff; transition: transform 0.15s; pointer-events: none; }
  .toggle.on .toggle-knob { transform: translateX(16px); }

  /* Cap-level toggle (larger) */
  .cap-toggle { width: 40px; height: 20px; border-radius: 10px; }
  .cap-toggle .toggle-knob { width: 16px; height: 16px; }
  .cap-toggle.on .toggle-knob { transform: translateX(20px); }

  .custom-warning { display: none; margin-top: 10px; font-family: var(--mono); font-size: 11px; color: var(--red); }
  .custom-warning.visible { display: block; }

  .exploit-warning { display: none; margin-top: 14px; padding: 10px 14px; background: rgba(240,79,79,0.07); border: 1px solid rgba(240,79,79,0.28); border-radius: 5px; font-size: 12px; color: #f9a0a0; gap: 8px; align-items: flex-start; }
  .exploit-warning.visible { display: flex; }

  .scan-status { display: none; align-items: center; gap: 10px; font-family: var(--mono); font-size: 11px; color: var(--green); margin-left: auto; }
  .scan-status.visible { display: flex; }
  .spinner { width: 7px; height: 7px; border-radius: 50%; background: var(--green); animation: spin-pulse 0.8s ease-in-out infinite alternate; }
  @keyframes spin-pulse { from { opacity: 0.3; transform: scale(0.8); } to { opacity: 1; transform: scale(1.2); } }

  .results-empty { text-align: center; padding: 48px 20px; font-family: var(--mono); font-size: 12px; color: var(--muted); }

  .result-card { background: var(--surface2); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 10px; overflow: hidden; }
  .result-card:last-child { margin-bottom: 0; }
  .result-header { padding: 13px 18px; display: flex; align-items: center; gap: 10px; cursor: pointer; transition: background 0.1s; user-select: none; flex-wrap: wrap; }
  .result-header:hover { background: rgba(255,255,255,0.03); }
  .result-num { font-family: var(--mono); font-size: 12px; font-weight: 600; color: var(--text); flex-shrink: 0; }
  .result-id { font-family: var(--mono); font-size: 10px; color: var(--muted); flex-shrink: 0; }
  .result-meta { font-family: var(--mono); font-size: 11px; color: var(--muted); flex-shrink: 0; }

  .badge { font-family: var(--mono); font-size: 10px; font-weight: 600; padding: 2px 8px; border-radius: 20px; letter-spacing: 0.05em; flex-shrink: 0; }
  .badge-done    { background: rgba(0,229,160,0.1);  color: var(--green);  border: 1px solid rgba(0,229,160,0.22); }
  .badge-failed  { background: rgba(240,79,79,0.1);  color: var(--red);    border: 1px solid rgba(240,79,79,0.22); }
  .badge-running { background: rgba(77,159,255,0.1); color: var(--blue);   border: 1px solid rgba(77,159,255,0.22); }

  .pills { display: flex; gap: 6px; flex-wrap: wrap; align-items: center; }
  .pill { font-family: var(--mono); font-size: 10px; font-weight: 500; padding: 2px 8px; border-radius: 20px; white-space: nowrap; }
  .pill-ports { background: rgba(77,159,255,0.1);   color: var(--blue);   border: 1px solid rgba(77,159,255,0.2); }
  .pill-vuln  { background: rgba(167,139,250,0.1);  color: var(--purple); border: 1px solid rgba(167,139,250,0.2); }
  .pill-error { background: rgba(240,79,79,0.1);    color: var(--red);    border: 1px solid rgba(240,79,79,0.2); }

  .result-actions { margin-left: auto; display: flex; gap: 6px; align-items: center; flex-shrink: 0; }
  .arrow { font-size: 9px; color: var(--muted); transition: transform 0.2s; flex-shrink: 0; }
  .arrow.open { transform: rotate(180deg); }

  .result-body { display: none; padding: 18px; border-top: 1px solid var(--border); }
  .result-body.open { display: block; }

  .section-label { font-family: var(--mono); font-size: 10px; font-weight: 600; letter-spacing: 0.1em; text-transform: uppercase; color: var(--muted); border-bottom: 1px solid var(--border); padding-bottom: 6px; margin-bottom: 12px; margin-top: 18px; }
  .section-label:first-child { margin-top: 0; }

  table { width: 100%; border-collapse: collapse; }
  th { font-family: var(--mono); font-size: 10px; font-weight: 500; letter-spacing: 0.08em; text-transform: uppercase; color: var(--muted); text-align: left; padding: 6px 14px 6px 0; border-bottom: 1px solid var(--border); }
  td { font-family: var(--mono); font-size: 12px; padding: 7px 14px 7px 0; border-bottom: 1px solid rgba(255,255,255,0.03); vertical-align: top; }
  .td-port    { color: var(--blue);  font-weight: 600; }
  .td-open    { color: var(--green); }
  .td-service { color: var(--text);  }

  .finding { background: rgba(0,0,0,0.25); border: 1px solid var(--border); border-radius: 5px; padding: 11px 14px; margin-bottom: 8px; }
  .finding:last-child { margin-bottom: 0; }
  .finding-meta { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin-bottom: 7px; }
  .finding-script { font-family: var(--mono); font-size: 12px; font-weight: 600; color: var(--purple); }
  .finding-port   { font-family: var(--mono); font-size: 11px; color: var(--blue); }
  .finding-host   { font-family: var(--mono); font-size: 11px; color: var(--muted); }
  .finding-output { font-family: var(--mono); font-size: 11px; color: var(--text); white-space: pre-wrap; line-height: 1.55; max-height: 180px; overflow: hidden; }
  .finding-output.expanded { max-height: none; }

  .show-more { font-family: var(--mono); font-size: 11px; color: var(--muted); background: none; border: none; cursor: pointer; padding: 4px 0 0; text-decoration: underline; }
  .show-more:hover { color: var(--text); }

  .error-box { background: rgba(240,79,79,0.07); border: 1px solid rgba(240,79,79,0.22); border-radius: 5px; padding: 10px 14px; font-family: var(--mono); font-size: 12px; color: var(--red); }
  .advisory-box { background: rgba(245,200,66,0.07); border: 1px solid rgba(245,200,66,0.22); border-radius: 5px; padding: 10px 14px; font-family: var(--mono); font-size: 11px; color: var(--yellow); margin-bottom: 10px; display: flex; gap: 8px; align-items: flex-start; }

  .export-bar { padding: 12px 20px; border-top: 1px solid var(--border); display: flex; align-items: center; gap: 10px; background: rgba(0,0,0,0.18); }
  .export-note { font-family: var(--mono); font-size: 10px; color: var(--muted); margin-left: auto; }
  .count-badge { font-family: var(--mono); font-size: 10px; padding: 1px 7px; border-radius: 20px; background: rgba(255,255,255,0.06); color: var(--muted); margin-left: 6px; }

  .alert-banner { display: none; padding: 9px 14px; background: rgba(245,200,66,0.08); border: 1px solid rgba(245,200,66,0.25); border-radius: 5px; font-family: var(--mono); font-size: 11px; color: var(--yellow); margin-top: 14px; gap: 8px; align-items: center; }
  .alert-banner.visible { display: flex; }

  .scripts-used-box { background: rgba(167,139,250,0.06); border: 1px solid rgba(167,139,250,0.18); border-radius: 5px; padding: 8px 12px; margin-bottom: 10px; font-family: var(--mono); font-size: 10px; color: var(--purple); }
</style>
</head>
<body>

<header>
  <div class="logo-dot"></div>
  <span class="logo-text">Heimdall // Local Scanner</span>
  <span class="logo-sub">session only · results lost on close</span>
</header>

<main>

  <!-- Scan panel -->
  <div class="panel">
    <div class="panel-header">
      <span class="panel-title">New Scan</span>
      <div class="scan-status" id="scanStatus">
        <div class="spinner"></div>
        <span id="scanStatusText">Scanning…</span>
      </div>
    </div>
    <div class="panel-body">
      <div class="form-grid">
        <div class="field">
          <label>Target IP / Host</label>
          <input id="target" type="text" placeholder="192.168.1.1">
        </div>
        <div class="field">
          <label>Scan Type</label>
          <select id="scanType" onchange="onTypeChange()">
            <option value="nmap_scan">Open Port Scan</option>
            <option value="nse_scan">Vulnerability Scan</option>
          </select>
        </div>
        <div class="field">
          <label>Profile</label>
          <select id="profile" onchange="onProfileChange()">
            <option value="standard">Standard</option>
            <option value="light">Light</option>
            <option value="full">Full</option>
            <option value="custom">Custom</option>
          </select>
        </div>
        <div class="field ports-field" id="portsField">
          <label>Ports (optional, comma-separated)</label>
          <input id="ports" type="text" placeholder="22,445,3389 — blank = profile default range">
        </div>
      </div>

      <div class="actions">
        <button class="btn btn-primary" id="runBtn" onclick="startScan()">▶ Run Scan</button>
      </div>

      <div class="exploit-warning" id="exploitWarn">
        <span>⚠</span>
        <span><strong>Full + Vulnerability Scan</strong> uses <code>--script vuln,exploit</code> — intrusive scripts
        that can disrupt services. Only scan hosts you own or have permission to test.</span>
      </div>

      <!-- Custom profile capability cards -->
      <div class="custom-panel" id="customPanel">
        <div class="custom-panel-header">
          <span class="custom-panel-title">Select Capabilities</span>
          <div class="custom-actions">
            <button class="custom-action-btn" onclick="selectAllCaps()">Select all</button>
            <button class="custom-action-btn" onclick="clearAllCaps()">Clear all</button>
            <span class="script-count" id="scriptCount">0 scripts selected</span>
          </div>
        </div>
        <div id="capCards"></div>
        <p class="custom-warning" id="customWarning">Select at least one capability before scanning.</p>
      </div>

      <div class="alert-banner" id="busyBanner">
        <span>⚠</span>
        <span>A scan is already running — wait for it to finish before starting another.</span>
      </div>
    </div>
  </div>

  <!-- Results panel -->
  <div class="panel">
    <div class="panel-header">
      <span class="panel-title">Results <span class="count-badge" id="countBadge">0</span></span>
    </div>
    <div class="panel-body" id="resultsBody">
      <div class="results-empty" id="emptyMsg">
        No scans yet — run a scan above to see results here.
      </div>
    </div>
    <div class="export-bar" id="exportBar" style="display:none">
      <button class="btn btn-secondary" onclick="exportAll()">↓ Export All (JSON)</button>
      <button class="btn btn-secondary" onclick="exportSelected()">↓ Export Selected</button>
      <span class="export-note">Results are lost when this window closes</span>
    </div>
  </div>

</main>

<script>
// ── CAPABILITY DATA ───────────────────────────────────────────────────────────
const CUSTOM_CAPABILITIES = [
  { id:'auth', label:'Authentication & Access Control',
    tooltip:'Checks for anonymous access, weak auth methods, and insecure credential handling.',
    scripts:[
      {id:'ftp-anon',               label:'FTP Anonymous',       desc:'Checks if FTP allows anonymous login.',                             def:true},
      {id:'http-auth-finder',       label:'HTTP Auth Finder',    desc:'Discovers HTTP auth methods (Basic, Digest, NTLM).',                def:true},
      {id:'ssh-auth-methods',       label:'SSH Auth Methods',    desc:'Lists auth methods accepted by the SSH server.',                    def:true},
      {id:'snmp-brute',             label:'SNMP Brute',          desc:'Attempts to guess SNMP community strings (default strings only).',  def:true},
      {id:'smb-security-mode',      label:'SMB Security Mode',   desc:'Reports whether SMB signing and plaintext auth are in use.',        def:true},
      {id:'http-open-proxy',        label:'HTTP Open Proxy',     desc:'Tests whether the HTTP server acts as an open proxy.',              def:false},
      {id:'irc-unrealircd-backdoor',label:'UnrealIRCd Backdoor', desc:'Checks for the UnrealIRCd 3.2.8.1 backdoor (CVE-2010-2075).',     def:false},
    ]},
  { id:'smb', label:'Windows & SMB Enumeration',
    tooltip:'Enumerates Windows host info, SMB shares, and checks for EternalBlue.',
    scripts:[
      {id:'smb-os-discovery',  label:'OS Discovery',  desc:'Determines OS, computer name, domain via SMB.',              def:true},
      {id:'smb-system-info',   label:'System Info',   desc:'Retrieves system info from SMB (OS version, build).',        def:true},
      {id:'smb-enum-shares',   label:'Enum Shares',   desc:'Enumerates SMB shares and access permissions.',              def:true},
      {id:'smb-security-mode', label:'Security Mode', desc:'Reports whether SMB signing is enabled.',                    def:true},
      {id:'smb-vuln-ms17-010', label:'EternalBlue',   desc:'Checks for MS17-010 — exploited by WannaCry.',              def:true},
      {id:'smb-vuln-ms10-054', label:'MS10-054',      desc:'Checks for MS10-054, a remote memory corruption bug.',       def:true},
      {id:'smb-enum-users',    label:'Enum Users',    desc:'Enumerates local users via SMB (may need credentials).',     def:false},
      {id:'smb-enum-groups',   label:'Enum Groups',   desc:'Enumerates local groups via SMB.',                           def:false},
      {id:'smb-enum-sessions', label:'Enum Sessions', desc:'Lists active SMB sessions.',                                 def:false},
      {id:'smb-enum-domains',  label:'Enum Domains',  desc:'Enumerates domains visible through SMB.',                   def:false},
    ]},
  { id:'snmp', label:'SNMP & Network Device Enumeration',
    tooltip:'Queries SNMP devices for system info, interfaces, and running processes.',
    scripts:[
      {id:'snmp-info',         label:'SNMP Info',          desc:'Retrieves basic system info from SNMP.',              def:true},
      {id:'snmp-sysdescr',     label:'System Description', desc:'Fetches the sysDescr OID — reveals OS/firmware.',    def:true},
      {id:'snmp-interfaces',   label:'Interfaces',         desc:'Lists network interfaces via SNMP.',                  def:true},
      {id:'snmp-netstat',      label:'Netstat',            desc:'Retrieves TCP/UDP connection table via SNMP.',        def:false},
      {id:'snmp-processes',    label:'Processes',          desc:'Lists running processes via SNMP.',                   def:false},
      {id:'snmp-win32-users',  label:'Win32 Users',        desc:'Enumerates Windows users via SNMP.',                 def:false},
      {id:'snmp-win32-shares', label:'Win32 Shares',       desc:'Lists Windows shares via SNMP.',                     def:false},
    ]},
  { id:'ssl', label:'SSL/TLS Analysis',
    tooltip:'Checks SSL/TLS for weak ciphers, bad certs, and known vulnerabilities.',
    scripts:[
      {id:'ssl-cert',          label:'Certificate',    desc:'Retrieves SSL certificate details.',                        def:true},
      {id:'ssl-enum-ciphers',  label:'Cipher Suites',  desc:'Enumerates supported cipher suites and grades them.',       def:true},
      {id:'ssl-heartbleed',    label:'Heartbleed',     desc:'Tests for OpenSSL Heartbleed (CVE-2014-0160).',            def:true},
      {id:'ssl-poodle',        label:'POODLE',         desc:'Checks for POODLE in SSLv3 (CVE-2014-3566).',             def:true},
      {id:'ssl-dh-params',     label:'DH Parameters',  desc:'Checks DH params for weakness (Logjam).',                  def:true},
      {id:'ssl-ccs-injection', label:'CCS Injection',  desc:'Tests for OpenSSL CCS Injection (CVE-2014-0224).',        def:true},
      {id:'tls-ticketbleed',   label:'Ticketbleed',    desc:'Checks for Ticketbleed in F5 TLS session tickets.',        def:false},
      {id:'ssl-known-key',     label:'Known Key',      desc:'Checks if SSL key is in a known-compromised database.',    def:false},
    ]},
  { id:'discovery', label:'Network Service Discovery',
    tooltip:'Probes common services for misconfigurations — DNS, NFS, RDP, VNC, and more.',
    scripts:[
      {id:'dns-zone-transfer',       label:'DNS Zone Transfer', desc:'Attempts zone transfer — reveals all DNS records if open.',    def:true},
      {id:'dns-recursion',           label:'DNS Recursion',     desc:'Checks if DNS server allows recursive queries.',               def:true},
      {id:'nfs-ls',                  label:'NFS List',          desc:'Lists NFS exports without auth.',                             def:true},
      {id:'nfs-showmount',           label:'NFS Showmount',     desc:'Shows the NFS server export list.',                           def:true},
      {id:'rdp-enum-encryption',     label:'RDP Encryption',    desc:'Enumerates RDP security and encryption protocols.',           def:true},
      {id:'telnet-encryption',       label:'Telnet Encryption', desc:'Checks whether Telnet offers encryption.',                    def:true},
      {id:'vnc-info',                label:'VNC Info',          desc:'Retrieves VNC server protocol version and auth type.',        def:true},
      {id:'finger',                  label:'Finger',            desc:'Queries finger service to enumerate users.',                  def:false},
      {id:'broadcast-dhcp-discover', label:'DHCP Discover',     desc:'Sends broadcast DHCP discover to identify DHCP servers.',    def:false},
      {id:'ldap-rootdse',            label:'LDAP Root DSE',     desc:'Retrieves LDAP root DSE — reveals domain info.',             def:false},
    ]},
];

// ── STATE ─────────────────────────────────────────────────────────────────────
let results = [];
let selectedIds = new Set();
let pollInterval = null;
let capState = {};    // capState[capId][scriptId] = bool

function initCapState() {
  capState = {};
  CUSTOM_CAPABILITIES.forEach(cap => {
    capState[cap.id] = {};
    cap.scripts.forEach(s => { capState[cap.id][s.id] = false; });
  });
}

function getSelectedScripts() {
  const out = [];
  CUSTOM_CAPABILITIES.forEach(cap => {
    cap.scripts.forEach(s => {
      if (capState[cap.id]?.[s.id]) out.push(s.id);
    });
  });
  return out;
}

function updateScriptCount() {
  const n = getSelectedScripts().length;
  const el = document.getElementById('scriptCount');
  if (el) el.textContent = n === 1 ? '1 script selected' : `${n} scripts selected`;
}

// ── CAPABILITY CARD RENDERING ─────────────────────────────────────────────────
function renderCapCards() {
  const container = document.getElementById('capCards');
  if (!container) return;
  container.innerHTML = CUSTOM_CAPABILITIES.map(cap => {
    const scripts = cap.scripts;
    const onCount = scripts.filter(s => capState[cap.id]?.[s.id]).length;
    const allOn   = onCount === scripts.length;
    const someOn  = onCount > 0;
    const bgCls   = allOn ? 'on' : (someOn ? 'on' : 'off');
    const scriptRows = scripts.map(s => {
      const checked = capState[cap.id]?.[s.id];
      const sensTag = s.def ? '' : '<span class="sensitive-tag">sensitive</span>';
      return `<div class="script-row">
        <span class="script-label" title="${s.desc}">${s.label}${sensTag}</span>
        <button class="toggle ${checked ? 'on' : 'off'}"
          onclick="toggleScript('${cap.id}','${s.id}')" title="${s.desc}">
          <span class="toggle-knob"></span>
        </button>
      </div>`;
    }).join('');
    return `<div class="cap-card">
      <div class="cap-header">
        <button class="toggle cap-toggle ${someOn ? 'on' : 'off'}"
          onclick="toggleCap('${cap.id}')" title="${cap.tooltip}">
          <span class="toggle-knob"></span>
        </button>
        <div class="cap-label-wrap" onclick="toggleCapExpand('${cap.id}')">
          <span class="cap-label">${cap.label}</span>
          <span class="cap-count">${onCount}/${scripts.length}</span>
        </div>
        <span class="cap-chevron" id="chev-${cap.id}" onclick="toggleCapExpand('${cap.id}')">▼</span>
      </div>
      <div class="cap-scripts" id="cap-scripts-${cap.id}">${scriptRows}</div>
    </div>`;
  }).join('');
  updateScriptCount();
}

function toggleCap(capId) {
  const cap = CUSTOM_CAPABILITIES.find(c => c.id === capId);
  if (!cap) return;
  const anyOn = cap.scripts.some(s => capState[capId]?.[s.id]);
  if (anyOn) {
    cap.scripts.forEach(s => { capState[capId][s.id] = false; });
  } else {
    cap.scripts.forEach(s => { capState[capId][s.id] = s.def; });
  }
  renderCapCards();
}

function toggleScript(capId, scriptId) {
  if (!capState[capId]) return;
  capState[capId][scriptId] = !capState[capId][scriptId];
  renderCapCards();
  // Keep expanded after toggling
  const el = document.getElementById(`cap-scripts-${capId}`);
  const ch = document.getElementById(`chev-${capId}`);
  if (el) { el.classList.add('open'); }
  if (ch) { ch.classList.add('open'); ch.textContent = '▲'; }
}

function toggleCapExpand(capId) {
  const el = document.getElementById(`cap-scripts-${capId}`);
  const ch = document.getElementById(`chev-${capId}`);
  if (!el) return;
  const open = el.classList.toggle('open');
  if (ch) { ch.classList.toggle('open', open); ch.textContent = open ? '▲' : '▼'; }
}

function selectAllCaps() {
  CUSTOM_CAPABILITIES.forEach(cap => {
    cap.scripts.forEach(s => { capState[cap.id][s.id] = true; });
  });
  renderCapCards();
}
function clearAllCaps() {
  CUSTOM_CAPABILITIES.forEach(cap => {
    cap.scripts.forEach(s => { capState[cap.id][s.id] = false; });
  });
  renderCapCards();
}

// ── FORM BEHAVIOUR ────────────────────────────────────────────────────────────
function onTypeChange() {
  const type    = document.getElementById('scanType').value;
  const profile = document.getElementById('profile').value;
  // Custom profile only valid for vulnerability scan
  const profileSel  = document.getElementById('profile');
  const customOption = profileSel.querySelector('option[value="custom"]');
  if (customOption) customOption.disabled = (type !== 'nse_scan');
  if (type !== 'nse_scan' && profile === 'custom') {
    profileSel.value = 'standard';
  }
  document.getElementById('portsField').classList.toggle('visible', type === 'nse_scan' && profile !== 'custom');
  updateExploitWarn();
  updateCustomPanel();
}

function onProfileChange() {
  const type    = document.getElementById('scanType').value;
  const profile = document.getElementById('profile').value;
  document.getElementById('portsField').classList.toggle('visible', type === 'nse_scan' && profile !== 'custom');
  updateExploitWarn();
  updateCustomPanel();
}

function updateExploitWarn() {
  const type    = document.getElementById('scanType').value;
  const profile = document.getElementById('profile').value;
  document.getElementById('exploitWarn').classList.toggle('visible', type === 'nse_scan' && profile === 'full');
}

function updateCustomPanel() {
  const type    = document.getElementById('scanType').value;
  const profile = document.getElementById('profile').value;
  const isCustom = (type === 'nse_scan' && profile === 'custom');
  const panel = document.getElementById('customPanel');
  panel.classList.toggle('visible', isCustom);
  if (isCustom && Object.keys(capState).length === 0) {
    initCapState();
    renderCapCards();
  }
}

// ── SCAN ──────────────────────────────────────────────────────────────────────
function startScan() {
  const target  = document.getElementById('target').value.trim();
  const type    = document.getElementById('scanType').value;
  const profile = document.getElementById('profile').value;
  const ports   = document.getElementById('ports').value.trim();

  if (!target) { alert('Please enter a target IP or hostname.'); return; }

  let customScripts = null;
  if (type === 'nse_scan' && profile === 'custom') {
    customScripts = getSelectedScripts();
    if (!customScripts.length) {
      document.getElementById('customWarning').classList.add('visible');
      return;
    }
    document.getElementById('customWarning').classList.remove('visible');
  }

  const btn = document.getElementById('runBtn');
  btn.disabled = true;
  document.getElementById('busyBanner').classList.remove('visible');
  document.getElementById('scanStatus').classList.add('visible');

  const startTime = Date.now();
  function tick() {
    const elapsed = Math.floor((Date.now() - startTime) / 1000);
    const m = Math.floor(elapsed / 60);
    const s = elapsed % 60;
    document.getElementById('scanStatusText').textContent =
      `Scanning… ${m > 0 ? m + 'm ' : ''}${s}s`;
  }
  const ticker = setInterval(tick, 1000);

  fetch('/api/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target, type, profile, ports, custom_scripts: customScripts })
  })
  .then(r => {
    if (r.status === 409) {
      clearInterval(ticker);
      btn.disabled = false;
      document.getElementById('scanStatus').classList.remove('visible');
      document.getElementById('busyBanner').classList.add('visible');
      return null;
    }
    return r.json();
  })
  .then(data => {
    if (!data) return;
    const scanId = data.scan_id;
    pollInterval = setInterval(() => {
      fetch(`/api/result/${scanId}`)
        .then(r => r.json())
        .then(res => {
          if (res.status === 'done' || res.status === 'failed') {
            clearInterval(pollInterval);
            clearInterval(ticker);
            btn.disabled = false;
            document.getElementById('scanStatus').classList.remove('visible');
            // Reset custom profile after scan
            if (type === 'nse_scan' && profile === 'custom') {
              initCapState();
              renderCapCards();
              document.getElementById('profile').value = 'standard';
              updateCustomPanel();
            }
            addResult(res);
          }
        });
    }, 1500);
  })
  .catch(err => {
    clearInterval(ticker);
    btn.disabled = false;
    document.getElementById('scanStatus').classList.remove('visible');
    alert('Scan request failed: ' + err);
  });
}

// ── RESULTS ───────────────────────────────────────────────────────────────────
function addResult(res) {
  results.unshift(res);
  renderResults();
}

function removeResult(id) {
  results = results.filter(r => r.id !== id);
  selectedIds.delete(id);
  renderResults();
}

function toggleSelect(id) {
  if (selectedIds.has(id)) selectedIds.delete(id);
  else selectedIds.add(id);
}

function buildSummary(out) {
  const pills = [];
  if (out.nmap) {
    const open = out.nmap.reduce((a, h) => a + h.ports.filter(p => p.state === 'open').length, 0);
    pills.push(`<span class="pill pill-ports">${open} open port${open !== 1 ? 's' : ''}</span>`);
  }
  if (out.nse) {
    const n = (out.nse.findings || []).length;
    if (n > 0) pills.push(`<span class="pill pill-vuln">${n} vulnerability finding${n !== 1 ? 's' : ''}</span>`);
  }
  if (out.error) pills.push('<span class="pill pill-error">error</span>');
  return pills.length ? `<div class="pills">${pills.join('')}</div>` : '';
}

function renderResults() {
  const body    = document.getElementById('resultsBody');
  const empty   = document.getElementById('emptyMsg');
  const counter = document.getElementById('countBadge');
  const bar     = document.getElementById('exportBar');

  counter.textContent = results.length;

  if (!results.length) {
    empty.style.display = '';
    bar.style.display = 'none';
    body.innerHTML = '';
    body.appendChild(empty);
    return;
  }

  empty.style.display = 'none';
  bar.style.display = 'flex';

  body.innerHTML = results.map((r, idx) => {
    const num     = results.length - idx;
    const out     = r.output || {};
    const summary = buildSummary(out);
    const statusCls = r.status === 'done' ? 'badge-done' : 'badge-failed';
    // Show both scan counter and session ID
    const profileLabel = r.profile === 'custom' ? 'Custom' : r.profile;
    const scanTypeLabel = r.scan_type === 'nmap_scan' ? 'Open Port Scan'
                        : r.scan_type === 'nse_scan'  ? 'Vulnerability Scan'
                        : r.scan_type;

    return `
    <div class="result-card" id="card-${r.id}">
      <div class="result-header" onclick="toggleBody('${r.id}')">
        <span class="result-num">Scan #${num}</span>
        <span class="result-id">[${r.id.slice(0,6)}]</span>
        <span class="badge ${statusCls}">${r.status}</span>
        <span class="result-meta">${scanTypeLabel} · ${escHtml(r.target)} · ${profileLabel}</span>
        ${summary}
        <div class="result-actions" onclick="event.stopPropagation()">
          <input type="checkbox" onchange="toggleSelect('${r.id}')" title="Select for export">
          <button class="btn btn-ghost" onclick="removeResult('${r.id}')">✕</button>
        </div>
        <span class="arrow" id="arrow-${r.id}">▼</span>
      </div>
      <div class="result-body" id="body-${r.id}">
        ${renderOutput(out, r)}
      </div>
    </div>`;
  }).join('');
}

function toggleBody(id) {
  const body  = document.getElementById(`body-${id}`);
  const arrow = document.getElementById(`arrow-${id}`);
  body.classList.toggle('open');
  arrow.classList.toggle('open');
}

function renderOutput(out, r) {
  if (out.error) {
    return `<div class="error-box">Error: ${escHtml(out.error)}</div>`;
  }

  let html = '';

  if (out.nmap) {
    html += '<div class="section-label">Open Port Scan — Nmap</div>';
    for (const host of out.nmap) {
      const open = host.ports.filter(p => p.state === 'open');
      if (!open.length) {
        html += `<p style="font-family:var(--mono);font-size:12px;color:var(--muted);padding:4px 0">${escHtml(host.host)}: no open ports found</p>`;
        continue;
      }
      html += `<p style="font-family:var(--mono);font-size:11px;color:var(--muted);margin-bottom:8px">${escHtml(host.host)}</p>
        <table><thead><tr><th>Port</th><th>State</th><th>Service</th></tr></thead><tbody>`;
      for (const p of open) {
        html += `<tr>
          <td class="td-port">${p.port}</td>
          <td class="td-open">${p.state}</td>
          <td class="td-service">${escHtml(p.service)}</td>
        </tr>`;
      }
      html += '</tbody></table>';
    }
  }

  if (out.nse) {
    html += '<div class="section-label">Vulnerability Findings</div>';

    // Advisory (soft warning about web ports)
    if (out.nse.advisory) {
      html += `<div class="advisory-box"><span>ℹ</span><span>${escHtml(out.nse.advisory)}</span></div>`;
    }

    // Scripts used (custom profile only)
    if (out.nse.scripts_used && out.nse.scripts_used.length) {
      html += `<div class="scripts-used-box">Scripts: ${out.nse.scripts_used.join(', ')}</div>`;
    }

    const findings = out.nse.findings || [];
    if (!findings.length) {
      html += `<p style="font-family:var(--mono);font-size:12px;color:var(--muted)">No vulnerability findings.</p>`;
    } else {
      for (const f of findings) {
        const uid  = 'f-' + Math.random().toString(36).slice(2);
        const port = f.port ? `port ${f.port} (${escHtml(f.service)})` : 'host-level';
        const isLong = f.output.length > 250;
        const short  = isLong ? f.output.slice(0, 250) + '…' : f.output;
        html += `
        <div class="finding">
          <div class="finding-meta">
            <span class="finding-script">${escHtml(f.script_id)}</span>
            <span class="finding-port">${port}</span>
            <span class="finding-host">${escHtml(f.host)}</span>
          </div>
          <div class="finding-output" id="${uid}">${escHtml(short)}</div>
          ${isLong ? `<button class="show-more" onclick="expandFinding('${uid}',${JSON.stringify(f.output)})">Show more</button>` : ''}
        </div>`;
      }
    }
  }

  return html || `<p style="font-family:var(--mono);font-size:12px;color:var(--muted)">No output.</p>`;
}

function expandFinding(uid, full) {
  const el = document.getElementById(uid);
  el.textContent = full;
  el.nextElementSibling.remove();
}

function escHtml(s) {
  return String(s ?? '')
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;');
}

// ── EXPORT ────────────────────────────────────────────────────────────────────
function buildExportDoc(subset) {
  return {
    exported_at: new Date().toISOString(),
    source: 'Heimdall Local Scanner',
    host: location.hostname,
    total: subset.length,
    results: subset.map(r => ({
      scan_id:        r.id,
      scan_type:      r.scan_type,
      target:         r.target,
      profile:        r.profile,
      custom_scripts: r.custom_scripts || null,
      status:         r.status,
      started_at:     r.started_at,
      completed_at:   r.completed_at,
      nmap:  r.output.nmap  || null,
      nse:   r.output.nse   || null,
      error: r.output.error || null,
    }))
  };
}

function downloadJson(doc, filename) {
  const blob = new Blob([JSON.stringify(doc, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  URL.revokeObjectURL(a.href);
}

function exportAll() {
  if (!results.length) { alert('No results to export.'); return; }
  const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  downloadJson(buildExportDoc(results), `heimdall-local-${ts}.json`);
}

function exportSelected() {
  const subset = results.filter(r => selectedIds.has(r.id));
  if (!subset.length) { alert('No results selected — tick the checkboxes first.'); return; }
  const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  downloadJson(buildExportDoc(subset), `heimdall-local-selected-${ts}.json`);
}

// Initialise profile option state on load
onTypeChange();
</script>
</body>
</html>"""


# ── HTTP request handler ───────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        pass

    def send_json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html: str):
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path

        if path in ("/", "/index.html"):
            self.send_html(DASHBOARD_HTML)
        elif path.startswith("/api/result/"):
            scan_id = path.split("/api/result/")[-1]
            with _results_lock:
                match = next((r for r in _results if r["id"] == scan_id), None)
            if match:
                self.send_json(match)
            else:
                self.send_json({"id": scan_id, "status": "running"})
        elif path == "/api/results":
            with _results_lock:
                self.send_json(list(_results))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        global _scan_running

        if self.path == "/api/scan":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length))

            with _scan_lock:
                if _scan_running:
                    self.send_json({"error": "A scan is already running"}, 409)
                    return
                _scan_running = True

            import uuid
            scan_id = str(uuid.uuid4())[:8]

            thread = threading.Thread(
                target=execute_scan,
                args=(
                    scan_id,
                    body.get("type", "nmap_scan"),
                    body.get("target", ""),
                    body.get("profile", "standard"),
                    body.get("ports", ""),
                    body.get("custom_scripts") or None,
                ),
                daemon=True
            )
            thread.start()
            self.send_json({"scan_id": scan_id})
        else:
            self.send_response(404)
            self.end_headers()


# ── startup ───────────────────────────────────────────────────────────────────

def check_nmap() -> bool:
    try:
        result = subprocess.run(
            ["nmap", "--version"],
            capture_output=True, text=True, timeout=5
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def main():
    parser = argparse.ArgumentParser(description="Heimdall Local Scanner")
    parser.add_argument("--port", type=int, default=9731, help="Port to listen on (default: 9731)")
    parser.add_argument("--no-browser", action="store_true", help="Don't open browser automatically")
    args = parser.parse_args()

    if not check_nmap():
        print("ERROR: nmap not found. Install nmap and ensure it is on your PATH.")
        print("  Windows: https://nmap.org/download.html")
        print("  Linux:   sudo apt install nmap")
        sys.exit(1)

    port = find_free_port(args.port)
    url  = f"http://127.0.0.1:{port}"

    server = HTTPServer(("127.0.0.1", port), Handler)

    print(f"\n  Heimdall Local Scanner")
    print(f"  {'─' * 36}")
    print(f"  URL  : {url}")
    print(f"  Ctrl+C to stop\n")

    if not args.no_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Scanner stopped.")
        server.shutdown()


if __name__ == "__main__":
    main()
