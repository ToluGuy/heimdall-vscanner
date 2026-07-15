# Detects SQL injection on a target URL using sqlmap, detection-only. See NOTES.md.

import re
import shutil
import subprocess

SQLMAP_TIMEOUT = 600  # time-based blind tests alone can take minutes

NOT_INJECTABLE_MARKER = "do not appear to be injectable"

# Everything between "sqlmap identified/resumed the following injection
# point(s)..." and the closing "---" line.
INJECTION_BLOCK_RE = re.compile(
    r"sqlmap (?:identified|resumed) the following injection points?(?:\(s\))?.*?\n---\n(.*?)\n---",
    re.DOTALL,
)

# Two header styles seen across sqlmap versions:
#   Parameter: id (GET)
#   Place: GET \n Parameter: id
PARAM_BLOCK_RE = re.compile(
    r"(?:Place:\s*(\w+)\s*\n\s*Parameter:\s*(\S+)|Parameter:\s*(\S+)\s*\((\w+)\))"
    r"(.*?)(?=(?:Place:\s*\w+\s*\n\s*Parameter:|Parameter:\s*\S+\s*\(|\Z))",
    re.DOTALL,
)
FIELD_RE = re.compile(r"Type:\s*(.+?)\n\s*Title:\s*(.+?)\n\s*Payload:\s*(.+?)(?:\n\s*\n|\Z)", re.DOTALL)
DBMS_RE = re.compile(r"back-end DBMS:\s*(.+)")


def execute(target: str, profile: str, **kwargs) -> dict:
    if shutil.which("sqlmap") is None:
        raise Exception(
            "sqlmap is not installed on this scanner/agent. Install it "
            "(e.g. `sudo apt-get install sqlmap`, or see "
            "https://github.com/sqlmapproject/sqlmap for the git-checkout "
            "method) before running sqlmap_scan jobs here."
        )

    post_data = (kwargs.get("post_data") or "").strip()

    cmd = ["sqlmap", "-u", target, "--batch", "--flush-session"]
    if post_data:
        cmd += ["--data", post_data]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=SQLMAP_TIMEOUT)
    output = result.stdout

    if NOT_INJECTABLE_MARKER in output:
        return {"sqlmap": {"target": target, "injectable": False, "dbms": None, "findings": []}}

    header_match = INJECTION_BLOCK_RE.search(output)
    if not header_match:
        raise Exception(
            "sqlmap produced no recognizable result — not the usual "
            f"injectable/not-injectable report format, may need a manual check: "
            f"{result.stderr.strip()[:300] or 'no stderr'}"
        )

    findings = []
    for m in PARAM_BLOCK_RE.finditer(header_match.group(1)):
        place = m.group(1) or m.group(4)
        name = m.group(2) or m.group(3)
        if not name:
            continue
        type_title_payloads = FIELD_RE.findall(m.group(5))
        if not type_title_payloads:
            findings.append({"parameter": name, "place": place, "type": None, "title": None, "payload": None})
        for t, ti, p in type_title_payloads:
            findings.append({"parameter": name, "place": place, "type": t.strip(), "title": ti.strip(), "payload": p.strip()})

    dbms_match = DBMS_RE.search(output)

    return {
        "sqlmap": {
            "target": target,
            "injectable": True,
            "dbms": dbms_match.group(1).strip() if dbms_match else None,
            "findings": findings,
        }
    }
