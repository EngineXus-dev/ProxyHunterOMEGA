# Security and privacy

**Experimental software; do not send credentials or sensitive traffic through public proxies.** Third-party proxy endpoints can intercept, record or alter traffic. Connectivity and ASN/ISP checks do not establish endpoint safety, authorization, anonymity or residential ownership.

- Only probe systems you are authorized to test and respect upstream source terms and rate limits.
- Keep `.cache/`, `.scrapoxy/`, `.env*`, output lists, logs and history databases private; they can contain proxy credentials and network details.
- Scrapoxy and VPNGate are optional and disabled by default in the public build. Independently configured external services have their own security and resource responsibilities.
- If publishing a fork, audit both tracked files and Git history for credentials; `.gitignore` cannot remove already committed secrets.
- For a vulnerability report, avoid posting secrets or exploit details publicly. Use private maintainer contact or GitHub security reporting if configured for the repository.

No security warranty or suitability for production traffic is implied.
