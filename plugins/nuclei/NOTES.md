# nuclei plugin notes

- **Risk tier:** intrusive — sends requests across however many templates
  match the severity/tag filters (or the whole library if unset), which
  can mean thousands of requests. `severity`/`tags`/`rate_limit` let the
  admin scope how aggressive a given run is; the risk tier reflects the
  ceiling, same reasoning as whatweb's aggression levels.
- **Output format:** confirmed against several independent real examples
  of nuclei's JSONL output (official docs plus multiple GitHub
  discussions), not just one source. Reasonably high confidence, unlike
  sqlmap/whatweb's more caveated parsing.
- **Scope (v1):** whatever templates are installed locally at scan time —
  no template-set curation beyond severity/tags. `setup.sh` runs
  `nuclei -update-templates` once; templates drift out of date over time
  and there's no automatic re-fetch built in yet.
- **Timeout:** 900s default — a full unfiltered template run against a
  large target can plausibly need longer depending on rate limit; tune
  if jobs are timing out rather than actually finishing.
