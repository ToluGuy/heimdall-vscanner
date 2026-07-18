# Template-based vulnerability scanning using Nuclei. See NOTES.md.

import json
import os
import shutil
import subprocess
import tempfile

NUCLEI_TIMEOUT = 900  # can run long depending on template count and rate limit
DEFAULT_RATE_LIMIT = 150


def execute(target: str, profile: str, **kwargs) -> dict:
    if shutil.which("nuclei") is None:
        raise Exception(
            "nuclei is not installed on this scanner/agent. Install it "
            "(e.g. `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`) "
            "before running nuclei_scan jobs here."
        )

    severity = kwargs.get("severity") or []
    if isinstance(severity, str):
        severity = [severity]
    tags = (kwargs.get("tags") or "").strip()
    rate_limit = kwargs.get("rate_limit") or DEFAULT_RATE_LIMIT

    tmp = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False)
    out_path = tmp.name
    tmp.close()

    try:
        cmd = [
            "nuclei",
            "-u", target,
            "-jsonl-export", out_path,
            "-rate-limit", str(rate_limit),
            "-silent",
        ]
        if severity:
            cmd += ["-severity", ",".join(severity)]
        if tags:
            cmd += ["-tags", tags]

        subprocess.run(cmd, capture_output=True, text=True, timeout=NUCLEI_TIMEOUT)

        if not os.path.exists(out_path) or os.path.getsize(out_path) == 0:
            # No matches for the given filters — not an error, nuclei simply
            # doesn't write the file (or writes an empty one) when nothing hits.
            return {"nuclei": {"target": target, "total_findings": 0, "findings": []}}

        findings = []
        with open(out_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
                info = entry.get("info", {}) if isinstance(entry, dict) else {}
                findings.append({
                    "template_id": entry.get("template-id"),
                    "name": info.get("name"),
                    "severity": info.get("severity"),
                    "matched_at": entry.get("matched-at") or entry.get("host"),
                })

        return {
            "nuclei": {
                "target": target,
                "total_findings": len(findings),
                "findings": findings,
            }
        }
    finally:
        if os.path.exists(out_path):
            os.remove(out_path)
