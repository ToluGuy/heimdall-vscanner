# hydra plugin notes

- **Risk tier:** high, not intrusive — the odd one out among the Loki
  tools so far. It actively attacks real credentials on a live service,
  which can trigger account lockouts or alerting, so it's the first tool
  that requires a live, time-boxed target authorization before it runs
  at all, same as the built-in high-risk job types.
- **Scope (v1):** one username (no userlist) against one password
  wordlist, stops at the first hit (`-f`) to minimize requests against
  the target. No `http-post-form` support yet — its path/body/failure-
  string template needs its own field shape.
- **Output format:** Hydra has a native, documented JSON schema
  (confirmed against the upstream project's README). Note its `success`
  field means "hydra ran without an internal error," not "credentials
  were found" — that's read from `quantityfound`/`results` instead.
- **Setup:** `setup.sh` installs hydra and offers to extract rockyou.txt
  if present but gzipped.
