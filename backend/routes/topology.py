# backend/routes/topology.py

import json

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Agent, Host, Job, Result
from ..core import require_auth

router = APIRouter()


@router.get("/topology")
def get_topology(
    db: Session = Depends(get_db),
    username: str = Depends(require_auth),
):
    """
    Returns a network topology graph for the frontend map.

    Nodes: every host in the hosts table, enriched with:
      - latest scan result (open ports, services)
      - AI risk level (from latest result with analysis)
      - linked agent name
      - subnet group (first 3 octets of IP)

    Edges: hosts in the same /24 subnet are connected to a
    virtual subnet-gateway node, giving the cluster layout
    something to anchor against.
    """
    import re as _re

    hosts = db.query(Host).order_by(Host.last_seen.desc()).all()

    nodes = []
    edges = []
    subnet_set = set()

    for host in hosts:
        # Agent name
        agent_name = None
        if host.agent_id:
            agent = db.query(Agent).filter(Agent.id == host.agent_id).first()
            if agent:
                agent_name = agent.name

        # Latest scan result for this host
        latest_result = (
            db.query(Result)
            .join(Job, Job.id == Result.job_id)
            .filter(Job.target == host.ip, Result.cleared == False)
            .order_by(Result.id.desc())
            .first()
        )

        open_ports = []
        risk = "UNSCANNED"
        last_scan_at = None

        if latest_result:
            try:
                out = json.loads(latest_result.output)
                for h in out.get("nmap", []):
                    for p in h.get("ports", []):
                        if p.get("state") == "open":
                            open_ports.append({
                                "port": p["port"],
                                "service": p.get("service", "unknown"),
                            })

                # NSE findings count
                nse_count = len(out.get("nse", {}).get("findings", [])) if out.get("nse") else 0

                # Nikto findings count
                nikto_count = 0
                for v in out.get("nikto", {}).values():
                    if v.get("raw"):
                        nikto_count += len([l for l in v["raw"].split("\n") if l.startswith("+ [")])
                    elif isinstance(v, list) and v:
                        nikto_count += len(v[0].get("vulnerabilities", []))

            except Exception:
                nse_count = 0
                nikto_count = 0

            # Risk from AI analysis
            if latest_result.analysis:
                m = _re.search(r"##\s*Risk Level\s*\n+(\w+)", latest_result.analysis, _re.IGNORECASE)
                risk = m.group(1).upper() if m else "INFO"
            else:
                risk = "UNANALYSED"

            job = db.query(Job).filter(Job.id == latest_result.job_id).first()
            if job and job.completed_at:
                last_scan_at = job.completed_at.isoformat()
        else:
            nse_count = 0
            nikto_count = 0

        # Subnet group — first 3 octets
        parts = host.ip.split(".")
        subnet = ".".join(parts[:3]) + ".0/24" if len(parts) == 4 else "unknown"
        subnet_set.add(subnet)

        nodes.append({
            "id": f"host-{host.id}",
            "type": "host",
            "ip": host.ip,
            "hostname": host.hostname,
            "mac": host.mac,
            "os": host.os_fingerprint,
            "agent_name": agent_name,
            "is_agent": agent_name is not None,
            "subnet": subnet,
            "risk": risk,
            "open_ports": open_ports,
            "port_count": len(open_ports),
            "nse_findings": nse_count,
            "nikto_findings": nikto_count,
            "last_seen": host.last_seen.isoformat() if host.last_seen else None,
            "last_scan_at": last_scan_at,
            "result_id": latest_result.id if latest_result else None,
        })

        # Edge: host → subnet gateway node
        edges.append({
            "source": f"host-{host.id}",
            "target": f"subnet-{subnet}",
        })

    # Subnet gateway nodes (virtual — anchor for clustering)
    for subnet in subnet_set:
        nodes.append({
            "id": f"subnet-{subnet}",
            "type": "subnet",
            "label": subnet,
            "subnet": subnet,
        })

    return {
        "nodes": nodes,
        "edges": edges,
        "subnets": sorted(subnet_set),
        "stats": {
            "total_hosts": len([n for n in nodes if n["type"] == "host"]),
            "total_subnets": len(subnet_set),
            "risk_counts": _count_risks(nodes),
        }
    }


def _count_risks(nodes):
    counts = {}
    for n in nodes:
        if n.get("type") == "host":
            risk = n.get("risk", "UNSCANNED")
            counts[risk] = counts.get(risk, 0) + 1
    return counts


