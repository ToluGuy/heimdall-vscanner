# local_scanner.py
# VAPT Local Scanner — standalone workstation tool
# Runs a local web server, opens a browser, lets the user scan from their
# own machine without needing the central server.
#
# Supports: nmap_scan, nse_scan
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
from urllib.parse import parse_qs, urlparse

# ── in-memory result store ────────────────────────────────────────────────────
# Results live for the session only. Export before closing.
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
        addr_el = host.find("address")
        if addr_el is None:
            continue
        addr = addr_el.get("addr")
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
        hosts.append({"host": addr, "ports": ports_data})
    return hosts


def parse_nse_xml(xml_data: str) -> list:
    root = ET.fromstring(xml_data)
    findings = []
    for host in root.findall("host"):
        addr_el = host.find("address")
        if addr_el is None:
            continue
        addr = addr_el.get("addr")
        hostscript = host.find("hostscript")
        if hostscript is not None:
            for script in hostscript.findall("script"):
                output = script.get("output", "").strip()
                if output.startswith("ERROR: Script execution failed"):
                    continue
                findings.append({
                    "host": addr, "port": None, "service": None,
                    "script_id": script.get("id"),
                    "output": output,
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
                if output.startswith("ERROR: Script execution failed"):
                    continue
                findings.append({
                    "host": addr, "port": None, "service": None,
                    "script_id": script.get("id"),
                    "output": output,
                })
    return findings


def run_nmap_scan(target: str, profile: str) -> dict:
    flags = get_nmap_flags(profile)
    cmd = ["nmap", *flags, "-oX", "-", target]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if result.returncode != 0:
        raise RuntimeError(f"nmap failed: {result.stderr[:300]}")
    hosts = parse_nmap_xml(result.stdout)
    return {"nmap": hosts}


def run_nse_scan(target: str, profile: str, ports_str: str) -> dict:
    nse_flags = get_nse_flags(profile)
    cmd = ["nmap", "-sV", *nse_flags]
    warning = None
    if ports_str:
        requested = [int(p.strip()) for p in ports_str.split(",") if p.strip().isdigit()]
        non_web = [p for p in requested if p not in WEB_PORTS]
        if requested and not non_web:
            warning = ("All specified ports are web ports — NSE skips these. "
                       "Leave blank to scan all non-web ports.")
            return {"nse": {"findings": [], "warning": warning}}
        if non_web:
            cmd += ["-p", ",".join(str(p) for p in non_web)]
    cmd += ["-oX", "-", target]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if result.returncode != 0:
        raise RuntimeError(f"nmap NSE failed: {result.stderr[:300]}")
    findings = parse_nse_xml(result.stdout)
    out = {"nse": {"findings": findings}}
    if warning:
        out["nse"]["warning"] = warning
    return out


def execute_scan(scan_id: str, scan_type: str, target: str, profile: str, ports: str):
    global _scan_running
    started_at = datetime.now().isoformat()
    try:
        if scan_type == "nmap_scan":
            output = run_nmap_scan(target, profile)
        elif scan_type == "nse_scan":
            output = run_nse_scan(target, profile, ports)
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
<title>VAPT Local Scanner</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap');

  :root {
    --bg:        #0b0e14;
    --surface:   #111520;
    --border:    #1e2535;
    --border2:   #2a3347;
    --green:     #00e5a0;
    --green-dim: #00a870;
    --blue:      #4d9fff;
    --purple:    #a78bfa;
    --yellow:    #f5c842;
    --red:       #f04f4f;
    --text:      #d4dbe8;
    --muted:     #5a6a82;
    --mono:      'IBM Plex Mono', monospace;
    --sans:      'IBM Plex Sans', sans-serif;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    min-height: 100vh;
    font-size: 14px;
    line-height: 1.6;
  }

  /* scanline texture */
  body::before {
    content: '';
    position: fixed; inset: 0;
    background: repeating-linear-gradient(
      0deg,
      transparent,
      transparent 2px,
      rgba(0,229,160,0.015) 2px,
      rgba(0,229,160,0.015) 4px
    );
    pointer-events: none;
    z-index: 9999;
  }

  header {
    border-bottom: 1px solid var(--border);
    padding: 16px 28px;
    display: flex;
    align-items: center;
    gap: 16px;
    background: var(--surface);
  }

  .logo-dot {
    width: 10px; height: 10px;
    border-radius: 50%;
    background: var(--green);
    box-shadow: 0 0 8px var(--green);
    animation: pulse 2s ease-in-out infinite;
  }
  @keyframes pulse {
    0%,100% { opacity: 1; }
    50% { opacity: 0.4; }
  }

  .logo-text {
    font-family: var(--mono);
    font-size: 13px;
    font-weight: 600;
    color: var(--green);
    letter-spacing: 0.12em;
    text-transform: uppercase;
  }

  .logo-sub {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--muted);
    margin-left: auto;
  }

  main {
    max-width: 960px;
    margin: 0 auto;
    padding: 32px 24px;
    display: flex;
    flex-direction: column;
    gap: 24px;
  }

  .panel {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
  }

  .panel-header {
    padding: 14px 20px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .panel-title {
    font-family: var(--mono);
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--muted);
  }

  .panel-body { padding: 20px; }

  /* scan form */
  .form-grid {
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
    gap: 14px;
    margin-bottom: 14px;
  }

  .field { display: flex; flex-direction: column; gap: 5px; }

  label {
    font-family: var(--mono);
    font-size: 10px;
    font-weight: 500;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--muted);
  }

  input, select {
    background: var(--bg);
    border: 1px solid var(--border2);
    border-radius: 4px;
    color: var(--text);
    font-family: var(--mono);
    font-size: 13px;
    padding: 8px 12px;
    outline: none;
    transition: border-color 0.15s;
    width: 100%;
  }

  input:focus, select:focus { border-color: var(--green-dim); }
  input::placeholder { color: var(--muted); }

  select option { background: var(--surface); }

  .ports-field { grid-column: 1 / -1; display: none; }
  .ports-field.visible { display: flex; flex-direction: column; gap: 5px; }

  .actions { display: flex; gap: 10px; align-items: center; }

  .btn {
    font-family: var(--mono);
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 0.06em;
    padding: 9px 20px;
    border-radius: 4px;
    border: none;
    cursor: pointer;
    transition: all 0.15s;
    text-transform: uppercase;
  }

  .btn-primary {
    background: var(--green);
    color: #000;
  }
  .btn-primary:hover { background: #00ffb2; }
  .btn-primary:disabled {
    background: var(--border2);
    color: var(--muted);
    cursor: not-allowed;
  }

  .btn-secondary {
    background: transparent;
    color: var(--muted);
    border: 1px solid var(--border2);
  }
  .btn-secondary:hover { border-color: var(--blue); color: var(--blue); }

  .btn-danger {
    background: transparent;
    color: var(--red);
    border: 1px solid transparent;
    padding: 4px 8px;
    font-size: 11px;
  }
  .btn-danger:hover { border-color: var(--red); }

  /* warning banner */
  .exploit-warning {
    display: none;
    margin-top: 12px;
    padding: 10px 14px;
    background: rgba(240,79,79,0.08);
    border: 1px solid rgba(240,79,79,0.3);
    border-radius: 4px;
    font-size: 12px;
    color: #f9a0a0;
  }
  .exploit-warning.visible { display: flex; gap: 8px; align-items: flex-start; }

  /* scan status */
  .scan-status {
    display: none;
    align-items: center;
    gap: 10px;
    font-family: var(--mono);
    font-size: 12px;
    color: var(--green);
    margin-left: auto;
  }
  .scan-status.visible { display: flex; }

  .spinner {
    width: 8px; height: 8px;
    border-radius: 50%;
    background: var(--green);
    animation: spin-pulse 0.8s ease-in-out infinite alternate;
  }
  @keyframes spin-pulse {
    from { opacity: 0.3; transform: scale(0.8); }
    to   { opacity: 1;   transform: scale(1.2); }
  }

  /* results */
  .results-empty {
    text-align: center;
    padding: 40px;
    font-family: var(--mono);
    font-size: 12px;
    color: var(--muted);
  }

  .result-card {
    border: 1px solid var(--border);
    border-radius: 6px;
    margin-bottom: 12px;
    overflow: hidden;
  }
  .result-card:last-child { margin-bottom: 0; }

  .result-header {
    padding: 12px 16px;
    display: flex;
    align-items: center;
    gap: 12px;
    cursor: pointer;
    background: rgba(255,255,255,0.02);
    transition: background 0.1s;
    user-select: none;
  }
  .result-header:hover { background: rgba(255,255,255,0.04); }

  .result-id {
    font-family: var(--mono);
    font-size: 12px;
    font-weight: 600;
    color: var(--text);
  }

  .result-meta {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--muted);
  }

  .result-summary {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--muted);
    margin-left: 4px;
  }

  .badge {
    font-family: var(--mono);
    font-size: 10px;
    font-weight: 600;
    padding: 2px 8px;
    border-radius: 20px;
    letter-spacing: 0.05em;
  }
  .badge-done    { background: rgba(0,229,160,0.12); color: var(--green); border: 1px solid rgba(0,229,160,0.25); }
  .badge-failed  { background: rgba(240,79,79,0.12);  color: var(--red);   border: 1px solid rgba(240,79,79,0.25); }
  .badge-running { background: rgba(77,159,255,0.12); color: var(--blue);  border: 1px solid rgba(77,159,255,0.25); }

  .result-actions { margin-left: auto; display: flex; gap: 8px; align-items: center; }

  .arrow {
    font-size: 10px;
    color: var(--muted);
    transition: transform 0.2s;
  }
  .arrow.open { transform: rotate(180deg); }

  .result-body {
    display: none;
    padding: 16px;
    border-top: 1px solid var(--border);
  }
  .result-body.open { display: block; }

  .section-label {
    font-family: var(--mono);
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--muted);
    border-bottom: 1px solid var(--border);
    padding-bottom: 6px;
    margin-bottom: 12px;
    margin-top: 16px;
  }
  .section-label:first-child { margin-top: 0; }

  /* nmap table */
  table { width: 100%; border-collapse: collapse; }
  th {
    font-family: var(--mono);
    font-size: 10px;
    font-weight: 500;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--muted);
    text-align: left;
    padding: 6px 12px 6px 0;
    border-bottom: 1px solid var(--border);
  }
  td {
    font-family: var(--mono);
    font-size: 12px;
    padding: 7px 12px 7px 0;
    border-bottom: 1px solid rgba(255,255,255,0.03);
    vertical-align: top;
  }
  .td-port  { color: var(--blue); font-weight: 500; }
  .td-open  { color: var(--green); }
  .td-service { color: var(--text); }

  /* NSE findings */
  .finding {
    background: rgba(0,0,0,0.3);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 10px 12px;
    margin-bottom: 8px;
  }
  .finding:last-child { margin-bottom: 0; }

  .finding-meta {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    align-items: center;
    margin-bottom: 6px;
  }
  .finding-script { font-family: var(--mono); font-size: 12px; font-weight: 600; color: var(--purple); }
  .finding-port   { font-family: var(--mono); font-size: 11px; color: var(--blue); }
  .finding-host   { font-family: var(--mono); font-size: 11px; color: var(--muted); }

  .finding-output {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--text);
    white-space: pre-wrap;
    line-height: 1.5;
    max-height: 180px;
    overflow: hidden;
    position: relative;
  }
  .finding-output.expanded { max-height: none; }
  .show-more {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--muted);
    background: none;
    border: none;
    cursor: pointer;
    padding: 4px 0 0;
    text-decoration: underline;
  }
  .show-more:hover { color: var(--text); }

  .error-box {
    background: rgba(240,79,79,0.08);
    border: 1px solid rgba(240,79,79,0.25);
    border-radius: 4px;
    padding: 10px 14px;
    font-family: var(--mono);
    font-size: 12px;
    color: var(--red);
  }

  /* export toolbar */
  .export-bar {
    padding: 12px 20px;
    border-top: 1px solid var(--border);
    display: flex;
    align-items: center;
    gap: 10px;
    background: rgba(0,0,0,0.2);
  }
  .export-note {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--muted);
    margin-left: auto;
  }

  /* scan counter */
  .count-badge {
    font-family: var(--mono);
    font-size: 10px;
    padding: 1px 7px;
    border-radius: 20px;
    background: rgba(255,255,255,0.06);
    color: var(--muted);
    margin-left: 6px;
  }
</style>
</head>
<body>

<header>
  <div class="logo-dot"></div>
  <span class="logo-text">VAPT // Local Scanner</span>
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
          <label>Target IP</label>
          <input id="target" type="text" placeholder="192.168.1.1">
        </div>
        <div class="field">
          <label>Scan Type</label>
          <select id="scanType" onchange="onTypeChange()">
            <option value="nmap_scan">Nmap Scan</option>
            <option value="nse_scan">NSE Scan</option>
          </select>
        </div>
        <div class="field">
          <label>Profile</label>
          <select id="profile" onchange="onProfileChange()">
            <option value="standard">Standard</option>
            <option value="light">Light</option>
            <option value="full">Full</option>
          </select>
        </div>
        <div class="field ports-field" id="portsField">
          <label>Ports (optional, comma-separated)</label>
          <input id="ports" type="text" placeholder="22,445,3389 — blank = all non-web ports">
        </div>
      </div>

      <div class="actions">
        <button class="btn btn-primary" id="runBtn" onclick="startScan()">▶ Run Scan</button>
      </div>

      <div class="exploit-warning" id="exploitWarn">
        <span>⚠</span>
        <span><strong>Full + NSE</strong> uses <code>--script vuln,exploit</code> — intrusive scripts
        that can disrupt services. Only scan hosts you own or have permission to test.</span>
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
        No scans yet. Run a scan above to see results here.
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
let results = [];
let selectedIds = new Set();
let scanCounter = 0;
let pollInterval = null;

function onTypeChange() {
  const type = document.getElementById('scanType').value;
  const portsField = document.getElementById('portsField');
  portsField.classList.toggle('visible', type === 'nse_scan');
  updateExploitWarn();
}

function onProfileChange() {
  updateExploitWarn();
}

function updateExploitWarn() {
  const type    = document.getElementById('scanType').value;
  const profile = document.getElementById('profile').value;
  const warn    = document.getElementById('exploitWarn');
  warn.classList.toggle('visible', type === 'nse_scan' && profile === 'full');
}

function startScan() {
  const target  = document.getElementById('target').value.trim();
  const type    = document.getElementById('scanType').value;
  const profile = document.getElementById('profile').value;
  const ports   = document.getElementById('ports').value.trim();

  if (!target) { alert('Please enter a target IP.'); return; }

  const btn = document.getElementById('runBtn');
  btn.disabled = true;
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
    body: JSON.stringify({ target, type, profile, ports })
  })
  .then(r => r.json())
  .then(data => {
    const scanId = data.scan_id;
    // poll for completion
    pollInterval = setInterval(() => {
      fetch(`/api/result/${scanId}`)
        .then(r => r.json())
        .then(res => {
          if (res.status === 'done' || res.status === 'failed') {
            clearInterval(pollInterval);
            clearInterval(ticker);
            btn.disabled = false;
            document.getElementById('scanStatus').classList.remove('visible');
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

    return `
    <div class="result-card" id="card-${r.id}">
      <div class="result-header" onclick="toggleBody('${r.id}')">
        <span class="result-id">#${num}</span>
        <span class="${r.status === 'done' ? 'badge badge-done' : 'badge badge-failed'}">${r.status}</span>
        <span class="result-meta">${r.scan_type.replace('_', ' ')} · ${r.target} · ${r.profile}</span>
        <span class="result-summary">${summary}</span>
        <div class="result-actions" onclick="event.stopPropagation()">
          <input type="checkbox" onchange="toggleSelect('${r.id}')" title="Select for export">
          <button class="btn btn-danger" onclick="removeResult('${r.id}')">✕</button>
        </div>
        <span class="arrow" id="arrow-${r.id}">▼</span>
      </div>
      <div class="result-body" id="body-${r.id}">
        ${renderOutput(out)}
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

function buildSummary(out) {
  const parts = [];
  if (out.nmap) {
    const open = out.nmap.reduce((a, h) => a + h.ports.filter(p => p.state === 'open').length, 0);
    parts.push(`${open} open port(s)`);
  }
  if (out.nse) {
    parts.push(`${(out.nse.findings || []).length} NSE finding(s)`);
  }
  if (out.error) parts.push('error');
  return parts.join(' · ') || 'no data';
}

function renderOutput(out) {
  if (out.error) {
    return `<div class="error-box">Error: ${escHtml(out.error)}</div>`;
  }

  let html = '';

  if (out.nmap) {
    html += '<div class="section-label">Port Scan — Nmap</div>';
    for (const host of out.nmap) {
      const open = host.ports.filter(p => p.state === 'open');
      if (!open.length) {
        html += `<p style="font-family:var(--mono);font-size:12px;color:var(--muted)">
          ${escHtml(host.host)}: no open ports found</p>`;
        continue;
      }
      html += `<p style="font-family:var(--mono);font-size:11px;color:var(--muted);margin-bottom:6px">
        ${escHtml(host.host)}</p>
        <table><thead><tr>
          <th>Port</th><th>State</th><th>Service</th>
        </tr></thead><tbody>`;
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
    html += '<div class="section-label">NSE Findings</div>';
    if (out.nse.warning) {
      html += `<div class="exploit-warning visible" style="margin-bottom:10px">
        <span>⚠</span><span>${escHtml(out.nse.warning)}</span></div>`;
    }
    const findings = out.nse.findings || [];
    if (!findings.length) {
      html += `<p style="font-family:var(--mono);font-size:12px;color:var(--muted)">No NSE findings.</p>`;
    } else {
      for (const f of findings) {
        const uid   = 'f-' + Math.random().toString(36).slice(2);
        const port  = f.port ? `port ${f.port} (${escHtml(f.service)})` : 'host-level';
        const short = f.output.length > 250 ? f.output.slice(0, 250) + '…' : f.output;
        const more  = f.output.length > 250;
        html += `
        <div class="finding">
          <div class="finding-meta">
            <span class="finding-script">${escHtml(f.script_id)}</span>
            <span class="finding-port">${port}</span>
            <span class="finding-host">${escHtml(f.host)}</span>
          </div>
          <div class="finding-output" id="${uid}">${escHtml(short)}</div>
          ${more ? `<button class="show-more" onclick="expandFinding('${uid}', ${JSON.stringify(f.output)})">Show more</button>` : ''}
        </div>`;
      }
    }
  }

  return html || '<p style="font-family:var(--mono);font-size:12px;color:var(--muted)">No output.</p>';
}

function expandFinding(uid, full) {
  const el = document.getElementById(uid);
  el.textContent = full;
  el.nextElementSibling.remove();
}

function escHtml(s) {
  return String(s)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;');
}

// ── export ────────────────────────────────────────────────────────────────────

function buildExportDoc(subset) {
  return {
    exported_at: new Date().toISOString(),
    source: 'VAPT Local Scanner',
    host: location.hostname,
    total: subset.length,
    results: subset.map(r => ({
      scan_type: r.scan_type,
      target:    r.target,
      profile:   r.profile,
      status:    r.status,
      started_at:   r.started_at,
      completed_at: r.completed_at,
      nmap: r.output.nmap || null,
      nse:  r.output.nse  || null,
      error: r.output.error || null,
    }))
  };
}

function downloadJson(doc, filename) {
  const blob = new Blob([JSON.stringify(doc, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(a.href);
}

function exportAll() {
  if (!results.length) { alert('No results to export.'); return; }
  const ts = new Date().toISOString().replace(/[:.]/g,'-').slice(0,19);
  downloadJson(buildExportDoc(results), `vapt-local-${ts}.json`);
}

function exportSelected() {
  const subset = results.filter(r => selectedIds.has(r.id));
  if (!subset.length) { alert('No results selected — tick the checkboxes first.'); return; }
  const ts = new Date().toISOString().replace(/[:.]/g,'-').slice(0,19);
  downloadJson(buildExportDoc(subset), `vapt-local-selected-${ts}.json`);
}
</script>
</body>
</html>"""


# ── HTTP request handler ───────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        pass  # silence default request logging

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
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/" or path == "/index.html":
            self.send_html(DASHBOARD_HTML)

        elif path.startswith("/api/result/"):
            scan_id = path.split("/api/result/")[-1]
            with _results_lock:
                match = next((r for r in _results if r["id"] == scan_id), None)
            if match:
                self.send_json(match)
            else:
                # still running
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
                ),
                daemon=True
            )
            thread.start()
            self.send_json({"scan_id": scan_id})

        else:
            self.send_response(404)
            self.end_headers()


# ── main ──────────────────────────────────────────────────────────────────────

def check_nmap():
    try:
        result = subprocess.run(
            ["nmap", "--version"],
            capture_output=True, text=True, timeout=5
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def main():
    parser = argparse.ArgumentParser(description="VAPT Local Scanner")
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

    print(f"\n  VAPT Local Scanner")
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
