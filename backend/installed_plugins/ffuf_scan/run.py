# Directory/file fuzzing against a web target using ffuf. See NOTES.md for scope and setup.

import json
import os
import shutil
import subprocess

FFUF_TIMEOUT = 300  # hard cap so one fuzz job can't hang an agent indefinitely

DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"
DEFAULT_MATCH_CODES = "200,204,301,302,307,401,403"
DEFAULT_THREADS = 40


def execute(target: str, profile: str, **kwargs) -> dict:
    if shutil.which("ffuf") is None:
        raise Exception(
            "ffuf is not installed on this scanner/agent. Install it "
            "(e.g. via your package manager or "
            "`go install github.com/ffuf/ffuf/v2@latest`) before running "
            "ffuf_scan jobs here."
        )

    wordlist_path = kwargs.get("wordlist_path") or DEFAULT_WORDLIST
    if not os.path.isfile(wordlist_path):
        raise Exception(
            f"Wordlist not found at '{wordlist_path}' on this machine. "
            "Point wordlist_path at a file that actually exists here — "
            "e.g. install the `dirb` or `seclists` package, or supply "
            "your own path."
        )

    extensions = (kwargs.get("extensions") or "").strip()
    match_codes = (kwargs.get("match_codes") or DEFAULT_MATCH_CODES).strip()
    threads = kwargs.get("threads") or DEFAULT_THREADS

    fuzz_url = target if "FUZZ" in target else target.rstrip("/") + "/FUZZ"

    cmd = [
        "ffuf",
        "-u", fuzz_url,
        "-w", wordlist_path,
        "-t", str(threads),
        "-mc", match_codes,
        "-of", "json",
        "-o", "-",
        "-s",  # silent — keeps stdout to just the JSON result, no progress banner
    ]
    if extensions:
        cmd += ["-e", extensions]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=FFUF_TIMEOUT)

    # ffuf can exit non-zero on benign conditions (e.g. every request got
    # filtered) — only treat this as a hard failure if there's no JSON to parse.
    try:
        parsed = json.loads(result.stdout)
    except (json.JSONDecodeError, ValueError):
        raise Exception(f"ffuf produced no usable output: {result.stderr.strip() or 'unknown error'}")

    hits = []
    for r in parsed.get("results", []):
        hits.append({
            "url": r.get("url"),
            "status": r.get("status"),
            "length": r.get("length"),
            "words": r.get("words"),
            "lines": r.get("lines"),
            "content_type": r.get("content-type"),
        })

    return {
        "ffuf": {
            "target": target,
            "wordlist": wordlist_path,
            "extensions": extensions or None,
            "hits": hits,
            "total_hits": len(hits),
        }
    }
