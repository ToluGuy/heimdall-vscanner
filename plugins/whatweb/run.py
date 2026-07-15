# Fingerprints web technologies using WhatWeb. See NOTES.md for scope and a caveat on output parsing.

import json
import shutil
import subprocess

WHATWEB_TIMEOUT = 120
VALID_AGGRESSION = {"1", "3", "4"}  # WhatWeb's own level 2 is unused


def _normalize_values(raw):
    """WhatWeb's JSON typically nests a plugin's matches under a
    'string' key as a list — be tolerant of it being a bare list, a
    bare string, or some other key name instead."""
    if isinstance(raw, dict):
        for key in ("string", "version", "value"):
            if key in raw:
                raw = raw[key]
                break
        else:
            return [str(v) for v in raw.values()]
    if isinstance(raw, list):
        return [str(v) for v in raw]
    return [str(raw)]


def execute(target: str, profile: str, **kwargs) -> dict:
    if shutil.which("whatweb") is None:
        raise Exception(
            "whatweb is not installed on this scanner/agent. Install it "
            "(e.g. `sudo apt-get install whatweb`) before running "
            "whatweb_scan jobs here."
        )

    aggression = str(kwargs.get("aggression") or "1")
    if aggression not in VALID_AGGRESSION:
        aggression = "1"

    cmd = ["whatweb", "-a", aggression, "--no-errors", "--log-json=-", target]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=WHATWEB_TIMEOUT)

    entries = []
    for line in result.stdout.splitlines():
        line = line.strip().rstrip(",")
        if not line or line in ("[", "]"):
            continue
        try:
            entries.append(json.loads(line))
        except (json.JSONDecodeError, ValueError):
            continue

    if not entries:
        raise Exception(f"whatweb produced no usable output: {result.stderr.strip() or 'unknown error'}")

    findings = []
    for entry in entries:
        plugins = entry.get("plugins", {}) if isinstance(entry, dict) else {}
        technologies = {name: _normalize_values(val) for name, val in plugins.items()}
        findings.append({
            "url": entry.get("target"),
            "http_status": entry.get("http_status"),
            "technologies": technologies,
        })

    return {
        "whatweb": {
            "target": target,
            "aggression": aggression,
            "findings": findings,
        }
    }
