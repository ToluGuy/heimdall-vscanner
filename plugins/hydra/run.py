# Brute-forces a single username's password against a live service using Hydra. See NOTES.md.

import json
import os
import shutil
import subprocess
import tempfile

HYDRA_TIMEOUT = 600
VALID_SERVICES = {"ssh", "ftp", "telnet", "mysql", "postgres", "rdp"}
DEFAULT_THREADS = 4  # conservative on purpose — this is a live credential attack, not passive recon


def execute(target: str, profile: str, **kwargs) -> dict:
    if shutil.which("hydra") is None:
        raise Exception(
            "hydra is not installed on this scanner/agent. Install it "
            "(e.g. `sudo apt-get install hydra`) before running "
            "hydra_scan jobs here."
        )

    service = (kwargs.get("service") or "").strip().lower()
    if service not in VALID_SERVICES:
        raise Exception(f"'service' must be one of: {', '.join(sorted(VALID_SERVICES))}")

    username = (kwargs.get("username") or "").strip()
    if not username:
        raise Exception("A username is required.")

    wordlist_path = kwargs.get("password_wordlist_path") or ""
    if not os.path.isfile(wordlist_path):
        raise Exception(
            f"Password wordlist not found at '{wordlist_path}' on this machine. "
            "Point password_wordlist_path at a file that actually exists here."
        )

    threads = kwargs.get("threads") or DEFAULT_THREADS

    tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
    out_path = tmp.name
    tmp.close()

    try:
        cmd = [
            "hydra",
            "-l", username,
            "-P", wordlist_path,
            "-t", str(threads),
            "-f",  # stop at the first valid credential — fewer requests against a live service
            "-o", out_path,
            "-b", "json",
            target,
            service,
        ]
        subprocess.run(cmd, capture_output=True, text=True, timeout=HYDRA_TIMEOUT)

        if not os.path.exists(out_path) or os.path.getsize(out_path) == 0:
            # Defensive fallback only — e.g. hydra crashed before writing anything.
            # The normal "nothing found" case still produces a full JSON file with
            # an empty results array, handled below.
            return {"hydra": {"target": target, "service": service, "username": username, "quantity_found": 0, "found": []}}

        with open(out_path) as f:
            raw = f.read()

        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            raise Exception(f"hydra produced a JSON file that didn't parse: {raw[:300]}")

        results = parsed.get("results", [])
        errors = parsed.get("errormessages", [])
        if not results and errors:
            raise Exception(f"hydra reported errors and found nothing: {'; '.join(errors[:3])}")

        return {
            "hydra": {
                "target": target,
                "service": service,
                "username": username,
                "quantity_found": parsed.get("quantityfound", len(results)),
                "found": [
                    {"host": r.get("host"), "login": r.get("login"), "password": r.get("password"), "port": r.get("port")}
                    for r in results
                ],
            }
        }
    finally:
        if os.path.exists(out_path):
            os.remove(out_path)
