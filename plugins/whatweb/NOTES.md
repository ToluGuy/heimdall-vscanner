# whatweb plugin notes

- **Risk tier:** intrusive — default aggression level (1) is a single,
  gentle HTTP request, but higher levels make more requests to confirm
  matches. Risk tier reflects the ceiling of what the job type can do,
  not its default.
- **Output format caveat:** unlike ffuf, WhatWeb's `--log-json` shape
  wasn't confirmed against a live install — parsing is defensive
  (tolerant of a couple of plausible per-match shapes), but treat the
  first real run as a check, not a sure thing.
- **Setup:** `setup.sh` installs whatweb (apt/brew/gem); no wordlist or
  other dependency needed.
