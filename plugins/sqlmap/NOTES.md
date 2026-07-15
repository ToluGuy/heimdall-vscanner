# sqlmap plugin notes

- **Risk tier:** intrusive, not high — scoped to detection only (no
  `--dbs`/`--tables`/`--dump`/`--os-shell`). Confirming an injection point
  already proves exploitability without touching data. A future
  enumeration/dump job type should very likely be `high` tier and go
  through target authorization — this one deliberately doesn't need to.
- **Output format:** sqlmap has no native JSON mode for injection
  results — this parses its human-readable report format, stable across
  versions for years but still text parsing, not a documented API. Caught
  a real bug during testing: the header phrasing varies ("injection
  point(s)" vs "injection points") across versions/situations; both are
  now handled.
- **Setup:** `setup.sh` installs sqlmap via apt, or prints the git-clone
  method sqlmap itself recommends.
