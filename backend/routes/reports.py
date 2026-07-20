# backend/routes/reports.py

import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Job, Result
from ..core import require_auth

router = APIRouter()


@router.get("/report/{result_id}", response_class=HTMLResponse)
def generate_report(
    result_id: int,
    db: Session = Depends(get_db),
    username: str = Depends(require_auth),
):
    result = db.query(Result).filter(Result.id == result_id).first()
    if not result:
        raise HTTPException(status_code=404, detail="Result not found")

    output = json.loads(result.output)
    job = db.query(Job).filter(Job.id == result.job_id).first()

    # Build job metadata block
    if job:
        job_meta = {
            "id": job.id,
            "type": job.type,
            "target": job.target,
            "mode": job.mode,
            "profile": job.profile,
            "priority": job.priority,
            "status": job.status,
            "started_at": job.started_at.strftime("%Y-%m-%d %H:%M:%S UTC") if job.started_at else "—",
            "completed_at": job.completed_at.strftime("%Y-%m-%d %H:%M:%S UTC") if job.completed_at else "—",
        }
    else:
        job_meta = {"id": result.job_id}

    generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    # ── Nmap section ──────────────────────────────────────────────────────────
    nmap_html = ""
    if output.get("nmap"):
        rows = []
        for host in output["nmap"]:
            for p in host.get("ports", []):
                state_class = "text-green-700 font-semibold" if p["state"] == "open" else "text-gray-400"
                rows.append(f"""
                <tr>
                    <td class="py-1.5 pr-6 font-mono text-sm text-blue-700">{host["host"]}</td>
                    <td class="py-1.5 pr-6 font-mono text-sm font-semibold">{p["port"]}</td>
                    <td class="py-1.5 pr-6 text-sm {state_class}">{p["state"]}</td>
                    <td class="py-1.5 text-sm text-gray-600">{p["service"]}</td>
                </tr>""")
        if rows:
            nmap_html = f"""
            <section class="mb-8">
                <h2 class="section-title">Open Port Scan Results</h2>
                <table class="w-full border-collapse">
                    <thead>
                        <tr class="border-b-2 border-gray-200 text-left text-xs uppercase tracking-wider text-gray-500">
                            <th class="pb-2 pr-6">Host</th>
                            <th class="pb-2 pr-6">Port</th>
                            <th class="pb-2 pr-6">State</th>
                            <th class="pb-2">Service</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-100">{"".join(rows)}</tbody>
                </table>
            </section>"""
        else:
            nmap_html = """
            <section class="mb-8">
                <h2 class="section-title">Open Port Scan Results</h2>
                <p class="text-sm text-gray-500">No open ports found.</p>
            </section>"""

    # ── NSE section ───────────────────────────────────────────────────────────
    nse_html = ""
    if output.get("nse"):
        nse = output["nse"]
        findings = nse.get("findings", [])
        warning = nse.get("warning", "")

        warning_block = ""
        if warning:
            warning_block = f'<div class="warning-box mb-4"><strong>Warning:</strong> {warning}</div>'

        if findings:
            cards = []
            for f in findings:
                port_label = f"{f['port']} ({f['service']})" if f.get("port") else "host-level"
                # Escape any HTML in output
                safe_output = str(f.get("output", "")).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                cards.append(f"""
                <div class="finding-card mb-3">
                    <div class="flex flex-wrap gap-4 mb-1">
                        <span class="font-mono font-semibold text-purple-700 text-sm">{f["script_id"]}</span>
                        <span class="text-gray-500 text-sm">port {port_label}</span>
                        <span class="text-gray-400 text-xs font-mono">{f["host"]}</span>
                    </div>
                    <pre class="text-xs text-gray-700 whitespace-pre-wrap leading-relaxed mt-1">{safe_output}</pre>
                </div>""")
            nse_html = f"""
            <section class="mb-8">
                <h2 class="section-title">NSE Findings <span class="badge">{len(findings)}</span></h2>
                {warning_block}
                {"".join(cards)}
            </section>"""
        else:
            nse_html = f"""
            <section class="mb-8">
                <h2 class="section-title">NSE Findings</h2>
                {warning_block}
                <p class="text-sm text-gray-500">No NSE findings.</p>
            </section>"""

    # ── Nikto section ─────────────────────────────────────────────────────────
    nikto_html = ""
    if output.get("nikto"):
        port_sections = []
        for port, data in output["nikto"].items():
            if data.get("error"):
                port_sections.append(
                    f'<p class="text-sm text-red-600 mb-3">Port {port}: {data["error"]}</p>'
                )
                continue

            vulns = []
            if data.get("raw"):
                for line in data["raw"].split("\n"):
                    if line.startswith("+ ["):
                        safe_line = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                        vulns.append(f'<div class="finding-card mb-2 text-sm">{safe_line.lstrip("+ ")}</div>')
            elif isinstance(data, list) and data:
                for v in data[0].get("vulnerabilities", []):
                    url_part = f' — <a href="{v.get("url","")}" class="text-blue-600">{v.get("url","")}</a>' if v.get("url") else ""
                    safe_msg = str(v.get("msg", "")).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                    vulns.append(f'<div class="finding-card mb-2 text-sm"><span class="font-mono text-yellow-700">[{v.get("id","")}]</span> {safe_msg}{url_part}</div>')

            count = len(vulns)
            block = "".join(vulns) if vulns else '<p class="text-sm text-gray-500">No findings on this port.</p>'
            port_sections.append(f"""
                <div class="mb-4">
                    <h3 class="text-sm font-semibold text-orange-700 mb-2">Port {port} — {count} finding(s)</h3>
                    {block}
                </div>""")

        nikto_html = f"""
        <section class="mb-8">
            <h2 class="section-title">Web Vulnerability Scan (Nikto)</h2>
            {"".join(port_sections)}
        </section>"""

    # ── Summary counts ────────────────────────────────────────────────────────
    open_ports = sum(
        len([p for p in h.get("ports", []) if p["state"] == "open"])
        for h in output.get("nmap", [])
    )
    nse_count = len(output.get("nse", {}).get("findings", []))
    nikto_count = 0
    for data in output.get("nikto", {}).values():
        if data.get("raw"):
            nikto_count += len([l for l in data["raw"].split("\n") if l.startswith("+ [")])
        elif isinstance(data, list) and data:
            nikto_count += len(data[0].get("vulnerabilities", []))

    summary_items = []
    if output.get("nmap"):
        summary_items.append(f'<div class="stat-box"><div class="stat-num">{open_ports}</div><div class="stat-label">Open Ports</div></div>')
    if output.get("nse"):
        summary_items.append(f'<div class="stat-box"><div class="stat-num">{nse_count}</div><div class="stat-label">NSE Findings</div></div>')
    if output.get("nikto"):
        summary_items.append(f'<div class="stat-box"><div class="stat-num">{nikto_count}</div><div class="stat-label">Web Findings</div></div>')

    summary_html = f'<div class="flex gap-4 flex-wrap mb-8">{"".join(summary_items)}</div>' if summary_items else ""

    # ── Job metadata table ────────────────────────────────────────────────────
    meta_rows = ""
    for label, key in [
        ("Job ID", "id"), ("Target", "target"), ("Type", "type"),
        ("Mode", "mode"), ("Profile", "profile"), ("Priority", "priority"),
        ("Started", "started_at"), ("Completed", "completed_at"),
    ]:
        val = job_meta.get(key, "—")
        meta_rows += f"""
        <tr class="border-b border-gray-100">
            <td class="py-1.5 pr-8 text-sm text-gray-500 w-32">{label}</td>
            <td class="py-1.5 text-sm font-medium text-gray-800">{val}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>VAPT Report — Result #{result_id}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @media print {{
            body {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
            .no-print {{ display: none !important; }}
            section {{ page-break-inside: avoid; }}
            .finding-card {{ page-break-inside: avoid; }}
        }}
        .section-title {{
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: #6b7280;
            border-bottom: 2px solid #e5e7eb;
            padding-bottom: 0.4rem;
            margin-bottom: 1rem;
        }}
        .finding-card {{
            background: #f9fafb;
            border: 1px solid #e5e7eb;
            border-radius: 0.4rem;
            padding: 0.6rem 0.8rem;
        }}
        .badge {{
            display: inline-block;
            background: #ede9fe;
            color: #6d28d9;
            font-size: 0.65rem;
            font-weight: 700;
            padding: 0.1rem 0.4rem;
            border-radius: 9999px;
            vertical-align: middle;
            margin-left: 0.4rem;
        }}
        .stat-box {{
            background: #f3f4f6;
            border: 1px solid #e5e7eb;
            border-radius: 0.5rem;
            padding: 0.75rem 1.25rem;
            text-align: center;
            min-width: 7rem;
        }}
        .stat-num {{ font-size: 1.5rem; font-weight: 700; color: #111827; }}
        .stat-label {{ font-size: 0.7rem; color: #6b7280; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 0.1rem; }}
        .warning-box {{
            background: #fffbeb;
            border: 1px solid #fcd34d;
            border-radius: 0.4rem;
            padding: 0.6rem 0.8rem;
            font-size: 0.8rem;
            color: #92400e;
        }}
    </style>
</head>
<body class="bg-white text-gray-900 max-w-4xl mx-auto px-8 py-10 font-sans">

    <!-- Print button -->
    <div class="no-print flex justify-end mb-6">
        <button onclick="window.print()"
            class="bg-gray-900 hover:bg-gray-700 text-white text-sm font-semibold px-5 py-2 rounded-lg transition">
            ↓ Save as PDF
        </button>
    </div>

    <!-- Header -->
    <div class="mb-8 pb-6 border-b-2 border-gray-200">
        <div class="flex items-center gap-3 mb-1">
            <div class="w-2 h-2 rounded-full bg-green-500"></div>
            <span class="text-xs font-semibold tracking-widest text-gray-400 uppercase">VAPT Scanner</span>
        </div>
        <h1 class="text-2xl font-bold text-gray-900 mb-1">Scan Report — Result #{result_id}</h1>
        <p class="text-xs text-gray-400">Generated {generated_at}</p>
    </div>

    <!-- Summary stats -->
    {summary_html}

    <!-- Job metadata -->
    <section class="mb-8">
        <h2 class="section-title">Job Details</h2>
        <table class="w-full">
            <tbody>{meta_rows}</tbody>
        </table>
    </section>

    <!-- Scan sections -->
    {nmap_html}
    {nse_html}
    {nikto_html}

    <div class="mt-10 pt-4 border-t border-gray-200 text-xs text-gray-400 text-center">
        VAPT Scanner Report &nbsp;·&nbsp; Result #{result_id} &nbsp;·&nbsp; {generated_at}
    </div>

    <script>
        // Auto-open print dialog once page has rendered
        window.addEventListener("load", () => setTimeout(() => window.print(), 400));
    </script>
</body>
</html>"""

    return HTMLResponse(content=html)


