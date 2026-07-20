# backend/routes/insights.py

import json
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Job, Result
from ..core import require_auth

router = APIRouter()


@router.get("/insights")
def get_insights(
    db: Session = Depends(get_db),
    username: str = Depends(require_auth),
    window: str = "7d",
    host: str = None,
):
    import re
 
    window_map = {"24h": 1, "7d": 7, "30d": 30, "3m": 90}
    days   = window_map.get(window, 7)
    cutoff = datetime.utcnow() - timedelta(days=days)
 
    job_q = db.query(Job).filter(
        Job.completed_at >= cutoff,
        Job.status == "done"
    )
    if host:
        job_q = job_q.filter(Job.target == host)
 
    jobs    = job_q.all()
    job_ids = [j.id for j in jobs]
    job_map = {j.id: j for j in jobs}
 
    results = db.query(Result).filter(Result.job_id.in_(job_ids)).all() if job_ids else []
 
    # ── Aggregate stats ───────────────────────────────────────────────────────
    total_scans  = len(jobs)
    unique_hosts = len(set(j.target for j in jobs))
 
    unique_open_ports: set = set()
    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "UNANALYSED": 0}
 
    for r in results:
        try:
            out = json.loads(r.output)
        except Exception:
            continue
        j_ref = job_map.get(r.job_id)
        target_ip = j_ref.target if j_ref else None
        for h in out.get("nmap", []):
            host_ip = h.get("host") or target_ip or ""
            for p in h.get("ports", []):
                if p.get("state") == "open":
                    unique_open_ports.add((host_ip, p["port"]))
        # Also collect ports from NSE findings
        for f in out.get("nse", {}).get("findings", []):
            if f.get("port") and f.get("host"):
                unique_open_ports.add((f["host"], f["port"]))
 
        if r.analysis:
            # Single backslash — this is real Python regex, not an embedded string
            m = re.search(r"##\s*Risk Level\s*\n+(\w+)", r.analysis, re.IGNORECASE)
            risk = m.group(1).upper() if m else "INFO"
            if risk in risk_counts:
                risk_counts[risk] += 1
            else:
                risk_counts["INFO"] += 1
        else:
            risk_counts["UNANALYSED"] += 1
 
    total_open_ports = len(unique_open_ports)
 
    # ── Scans per day ─────────────────────────────────────────────────────────
    scans_by_day = {}
    for j in jobs:
        if j.completed_at:
            day = j.completed_at.strftime("%Y-%m-%d")
            scans_by_day[day] = scans_by_day.get(day, 0) + 1
 
    days_list = []
    for i in range(days - 1, -1, -1):
        d = (datetime.utcnow() - timedelta(days=i)).strftime("%Y-%m-%d")
        days_list.append(d)
    scan_activity = [{"date": d, "count": scans_by_day.get(d, 0)} for d in days_list]
 
    # ── Per-host summary ──────────────────────────────────────────────────────
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNANALYSED"]
    host_data: dict = {}
 
    for j in jobs:
        ip = j.target
        if ip not in host_data:
            host_data[ip] = {
                "ip":               ip,
                "scan_count":       0,
                "open_ports_set":   set(),
                "findings":         0,
                "last_scan":        None,
                "risk":             "UNANALYSED",
                "result_id":        None,
                "latest_result_ts": None,
            }
        host_data[ip]["scan_count"] += 1
        if j.completed_at:
            cur = host_data[ip]["last_scan"]
            if cur is None or j.completed_at > cur:
                host_data[ip]["last_scan"] = j.completed_at
 
    for r in results:
        j = job_map.get(r.job_id)
        if not j:
            continue
        ip = j.target
        if ip not in host_data:
            continue
        try:
            out = json.loads(r.output)
        except Exception:
            continue
 
        # Deduplicated open ports — nmap + NSE findings
        for h in out.get("nmap", []):
            host_ip = h.get("host") or ip
            for p in h.get("ports", []):
                if p.get("state") == "open":
                    host_data[ip]["open_ports_set"].add((host_ip, p["port"]))
        for f in out.get("nse", {}).get("findings", []):
            if f.get("port") and f.get("host"):
                host_data[ip]["open_ports_set"].add((f["host"], f["port"]))
 
        # Findings from the latest result only
        result_ts = j.completed_at or datetime.min
        if host_data[ip]["latest_result_ts"] is None or result_ts > host_data[ip]["latest_result_ts"]:
            host_data[ip]["latest_result_ts"] = result_ts
            host_data[ip]["result_id"]        = r.id
 
            nse_count = len(out.get("nse", {}).get("findings", [])) if out.get("nse") else 0
            nikto_count = 0
            for v in out.get("nikto", {}).values():
                if v.get("error"):
                    continue
                if v.get("raw"):
                    nikto_count += len([l for l in v["raw"].split("\n") if l.startswith("+ [")])
                elif isinstance(v, list) and v:
                    nikto_count += len(v[0].get("vulnerabilities", []))
            host_data[ip]["findings"] = nse_count + nikto_count
 
        # Risk: worst seen
        if r.analysis:
            m = re.search(r"##\s*Risk Level\s*\n+(\w+)", r.analysis, re.IGNORECASE)
            risk    = m.group(1).upper() if m else "INFO"
            current = host_data[ip]["risk"]
            try:
                if severity_order.index(risk) < severity_order.index(current):
                    host_data[ip]["risk"] = risk
            except ValueError:
                pass
 
    hosts_list = []
    for ip, d in host_data.items():
        hosts_list.append({
            "ip":         d["ip"],
            "scan_count": d["scan_count"],
            "open_ports": len(d["open_ports_set"]),
            "findings":   d["findings"],
            "last_scan":  d["last_scan"].isoformat() if d["last_scan"] else None,
            "risk":       d["risk"],
            "result_id":  d["result_id"],
        })
    hosts_list.sort(key=lambda x: x["findings"], reverse=True)

    # ── Scan type breakdown ────────────────────────────────────────────────────
    scan_type_counts = {}
    for j in jobs:
        label = {"nmap_scan": "Open Port Scan", "nikto_scan": "Web Scan", "nse_scan": "Vulnerability Scan"}.get(j.type, j.type)
        scan_type_counts[label] = scan_type_counts.get(label, 0) + 1

    # ── Port frequency ─────────────────────────────────────────────────────────
    port_host_map: dict = {}
    for r in results:
        try:
            out = json.loads(r.output)
        except Exception:
            continue
        j_ref = job_map.get(r.job_id)
        target_ip = j_ref.target if j_ref else "unknown"
        for h in out.get("nmap", []):
            host_ip = h.get("host") or target_ip
            for p in h.get("ports", []):
                if p.get("state") == "open":
                    port_num = str(p["port"])
                    if port_num not in port_host_map:
                        port_host_map[port_num] = set()
                    port_host_map[port_num].add(host_ip)

    top_ports = sorted(
        [{"port": k, "host_count": len(v)} for k, v in port_host_map.items()],
        key=lambda x: x["host_count"],
        reverse=True
    )[:15]

    # ── Coverage gaps (all-time, not window-scoped) ────────────────────────────
    # Hosts that have ever been port-scanned but whose last vuln scan
    # is either absent or older than 30 days — genuinely unassessed hosts.
    all_nmap_jobs = db.query(Job).filter(
        Job.type == "nmap_scan",
        Job.status == "done"
    ).all()
    all_nse_jobs = db.query(Job).filter(
        Job.type == "nse_scan",
        Job.status == "done"
    ).all()

    all_nmap_hosts = set(j.target for j in all_nmap_jobs)
    # Map each host to its most recent completed nse scan date
    nse_by_host: dict = {}
    for j in all_nse_jobs:
        if j.completed_at:
            nse_by_host[j.target] = max(nse_by_host.get(j.target, datetime.min), j.completed_at)

    stale_threshold = datetime.utcnow() - timedelta(days=30)
    coverage_gaps = []
    for host in sorted(all_nmap_hosts):
        last_nse = nse_by_host.get(host)
        if last_nse is None:
            coverage_gaps.append({"ip": host, "last_vuln_scan": None, "days_ago": None})
        elif last_nse < stale_threshold:
            days = (datetime.utcnow() - last_nse).days
            coverage_gaps.append({"ip": host, "last_vuln_scan": last_nse.strftime("%Y-%m-%d"), "days_ago": days})
    coverage_gaps.sort(key=lambda x: (x["last_vuln_scan"] or "", x["ip"]))
 
    # ── Per-host drilldown ────────────────────────────────────────────────────
    scan_history = []
    if host:
        for j in sorted(jobs, key=lambda x: x.completed_at or datetime.min):
            result_for_job = next((r for r in results if r.job_id == j.id), None)
            entry = {
                "date":       j.completed_at.strftime("%Y-%m-%d") if j.completed_at else None,
                "type":       j.type,
                "profile":    j.profile,
                "open_ports": 0,
                "findings":   0,
                "risk":       "UNANALYSED",
                "result_id":  result_for_job.id if result_for_job else None,
            }
            if result_for_job:
                try:
                    out = json.loads(result_for_job.output)
 
                    # Count unique open ports: nmap + NSE findings
                    ports_in_scan: set = set()
                    for h in out.get("nmap", []):
                        for p in h.get("ports", []):
                            if p.get("state") == "open":
                                ports_in_scan.add(p["port"])
                    for f in out.get("nse", {}).get("findings", []):
                        if f.get("port"):
                            ports_in_scan.add(f["port"])
                    entry["open_ports"] = len(ports_in_scan)
 
                    nse_f   = len(out.get("nse", {}).get("findings", [])) if out.get("nse") else 0
                    nikto_f = 0
                    for v in out.get("nikto", {}).values():
                        if v.get("error"):
                            continue
                        if v.get("raw"):
                            nikto_f += len([l for l in v["raw"].split("\n") if l.startswith("+ [")])
                        elif isinstance(v, list) and v:
                            nikto_f += len(v[0].get("vulnerabilities", []))
                    entry["findings"] = nse_f + nikto_f
                except Exception:
                    pass
 
                if result_for_job.analysis:
                    m = re.search(r"##\s*Risk Level\s*\n+(\w+)", result_for_job.analysis, re.IGNORECASE)
                    entry["risk"] = m.group(1).upper() if m else "INFO"
            scan_history.append(entry)
 
    return {
        "window": window,
        "host":   host,
        "stats": {
            "total_scans":      total_scans,
            "unique_hosts":     unique_hosts,
            "total_open_ports": total_open_ports,
            "risk_counts":      risk_counts,
        },
        "scan_activity":    scan_activity,
        "scan_type_counts": scan_type_counts,
        "top_ports":        top_ports,
        "coverage_gaps":    coverage_gaps,
        "hosts":            hosts_list,
        "scan_history":     scan_history,
        "scan_health": {
            "done":      sum(1 for j in jobs if j.status == "done"),
            "failed":    sum(1 for j in jobs if j.status == "failed"),
            "cancelled": sum(1 for j in jobs if j.status == "cancelled"),
            "pending":   sum(1 for j in jobs if j.status == "pending"),
        },
    }

