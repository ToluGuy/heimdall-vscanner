# Disclaimer — Heimdall V-Scanner

Heimdall V-Scanner is a network vulnerability assessment tool intended for
use by system administrators, IT professionals, and security practitioners
on networks and systems they own or have explicit written authorisation to test.

## Authorised Use Only

Scanning networks, hosts, or systems without prior authorisation from the
owner is illegal in most jurisdictions and may violate laws including but
not limited to the Computer Fraud and Abuse Act (CFAA) in the United States,
the Computer Misuse Act in the United Kingdom, and equivalent legislation
in other countries.

By downloading, installing, or using Heimdall V-Scanner, you confirm that:

- You are the owner of the systems and networks you intend to scan, or
- You have obtained explicit written permission from the owner to perform
  security assessments against those systems, and
- You will use this tool in compliance with all applicable local, national,
  and international laws and regulations.

## No Liability

The author (Tolu Ogundiran) and contributors to this project accept no
responsibility or liability for any damage, data loss, service disruption,
legal consequences, or other harm resulting from the use or misuse of this
software. This tool is provided as-is, without warranty of any kind.

Certain scan profiles — particularly NSE scans using the `full` profile
(`--script vuln,exploit`) — are intrusive and have the potential to disrupt
or crash services on target systems. These must only be used with full
understanding of the risk and explicit authorisation from the system owner.

This applies with even more force to the Loki penetration testing suite
(ffuf, WhatWeb, sqlmap, Nuclei, Hydra). These tools actively probe, inject
payloads into, or attempt credential attacks against a target — Hydra in
particular attempts real logins against a live service and can trigger
account lockouts. Loki is disabled by default and only becomes available
once explicitly installed; high-risk job types additionally require a
time-boxed authorization granted per target before they can run at all.
None of this substitutes for explicit, written authorisation from the
system owner.

## Third-Party Tools

Heimdall V-Scanner invokes the following third-party tools. Their use is
subject to their own respective licences and terms:

- **Nmap** — https://nmap.org/book/man-legal.html
- **Nikto** — https://github.com/sullo/nikto (GPL v2)

The following are used only if separately installed and enabled via the
optional Loki plugin suite:

- **ffuf** — https://github.com/ffuf/ffuf (MIT)
- **WhatWeb** — https://github.com/urbanadventurer/WhatWeb (GPL v2)
- **sqlmap** — https://github.com/sqlmapproject/sqlmap (GPL v2 or later)
- **Nuclei** — https://github.com/projectdiscovery/nuclei (MIT)
- **Hydra** — https://github.com/vanhauser-thc/thc-hydra (GPL v3 or later)

## Intended Environment

This tool is designed for use on private, internal office networks in a
controlled environment. It is not intended for use against public internet
infrastructure, cloud services, or any system not under your direct control.

## Development Note

Portions of this project's code and documentation were generated or
assisted by Claude (Anthropic), used as a development tool throughout the
project. All AI-assisted output was reviewed, refactored, and tested by
the author before being incorporated. The author takes full
responsibility for the final codebase, regardless of how any individual
part of it was originally drafted.

---

If you are unsure whether you have authorisation to scan a system,
**do not scan it.**
