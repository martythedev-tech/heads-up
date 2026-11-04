# Heads Up

An internal dashboard of critical vulnerabilities for the system administrator.

- **Briefings:** Cloudflare Radar [Zero Wire](https://radar.cloudflare.com/security/zero-wire) RSS (every 30 min)
- **Newly exploited:** [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) additions in the last 45 days (every 3 h)
- **Ubuntu:** Security Notices for the configured releases, last 3 weeks (hourly), rated by Ubuntu's own CVE priority (via OSV)
- **Per CVE:** EPSS exploit probability (FIRST), CVSS (NVD), Ubuntu per-release fix status

Anyone who can reach it can read it. Signing in (name + shared password)
lets you mark items Untriaged / Investigating / Not affected / Patched with a
note; every change is logged.

Single-file aiohttp app (`app.py`) + static front end, SQLite state, run by
systemd with a private, name-constrained CA. Deploy from the laptop with
`deploy/deploy.sh` (`secrets` stores the sign-in password from the keyring).

Local run: `HU_DEV=1 HU_DEV_LOGIN_HASH=$(echo pw | deploy/hash-password) python3 app.py` → http://127.0.0.1:8765

Content belongs to its sources; every item links back to the original.
