#!/usr/bin/env python3
"""Fetch the real feeds through the real parsers: did anyone change a format?

Needs internet, writes only to a temporary folder. Exits non-zero if a feed
fails, comes back empty, or no longer has the fields Heads Up reads.
"""
import asyncio
import json
import re
import sys

import helpers  # noqa: F401  (sets up the temporary state directory)
import app
import exploits as X
from aiohttp import ClientSession, ClientTimeout

problems = []


def report(name, ok, detail=""):
    print(("  ok    " if ok else "  FAIL  ") + name + (f": {detail}" if detail else ""), flush=True)
    if not ok:
        problems.append(name)


async def main():
    db = app.db_open()
    f = app.Fetcher(db)
    f.session = ClientSession(headers={"User-Agent": app.UA}, timeout=ClientTimeout(total=60))
    jobs = {"zerowire": f.zero_wire, "kev": f.kev, "ubuntu": f.ubuntu, "msrc": f.msrc, "truenas": f.truenas, "fortinet": f.fortinet}
    for name, job in jobs.items():
        try:
            await job()
        except Exception as e:
            report(name, False, str(e) or type(e).__name__)
            continue
        row = db.execute("SELECT count, error FROM sources WHERE name=?", (name,)).fetchone()
        report(name, row and not row["error"] and row["count"], f"{row['count']} rows" if row else "no result")

    rows = db.execute("SELECT id, headline, body, updated, published, extra FROM items WHERE source='zerowire' AND active=1").fetchall()
    report("cloudflare: every briefing has advice", rows and all(r["headline"] for r in rows), f"{sum(bool(r['headline']) for r in rows)} of {len(rows)}")
    report("cloudflare: review dates", rows and any(r["updated"] != r["published"] for r in rows))
    report("cloudflare: update history", rows and all(json.loads(r["extra"])["chronology"] for r in rows))
    # static/app.js shows these sections by name.
    for section in ("Recommended action", "Affected deployments"):
        report(f"cloudflare: section {section}", rows and all(f"<h2>{section}</h2>" in r["body"] for r in rows))

    kev = db.execute("SELECT cve, vendor, added FROM kev LIMIT 1").fetchone()
    report("cisa: fields", kev and re.fullmatch(r"CVE-\d{4}-\d{4,}", kev["cve"]) and kev["vendor"] and kev["added"])
    ms = db.execute("SELECT severity, cvss, tag FROM msrc WHERE severity='Critical' LIMIT 1").fetchone()
    report("microsoft: fields", ms and ms["cvss"] is not None and ms["tag"])

    listed = await X.poc_listing(f.session, {"2024"})
    report("github exploit list", len(listed) > 100, f"{len(listed)} for 2024")
    async with f.session.get(app.UBUNTU_CVE.format("CVE-2024-3094")) as r:
        data = await r.json(content_type=None)
    report("ubuntu tracker: fields", r.status == 200 and data.get("packages") and "statuses" in data["packages"][0])
    answer = await f.nvd_lookup("CVE-2024-3094")
    report("nvd: fields", answer.get("found") and answer.get("cvss") is not None, str(answer.get("cvss")))
    data = await f.get(app.EPSS, params={"cve": "CVE-2024-3094"}, as_json=True)
    report("epss: fields", data.get("data") and "epss" in data["data"][0])
    await f.session.close()


asyncio.run(main())
print("\nAll feeds look right." if not problems else f"\nFAILED: {', '.join(problems)}")
sys.exit(1 if problems else 0)
