# ffuf plugin notes

- **Risk tier:** intrusive — sends a wordlist's worth of requests to the
  target (can trip WAFs/rate limits) but never exploits anything found,
  only reports what responded.
- **Not installed by install.sh** — expected to already be on whichever
  scanner/agent has `ffuf_scan` enabled. `setup.sh` installs it (go/apt/brew)
  plus a default wordlist; never called automatically by `run.py`.
- **Output format:** confirmed against ffuf's documented JSON schema and
  tested with a mocked realistic response before shipping.
