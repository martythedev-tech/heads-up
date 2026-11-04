"""Microsoft Patch Tuesday, from the Security Update Guide API (free, no key).

Only Microsoft's own fixes (issuingCna = Microsoft), not the open-source
packages Microsoft also ships for Azure Linux. The three most recent
monthly releases are kept.
"""
import asyncio
import json
import time
from collections import Counter
from datetime import date, timedelta

from aiohttp import ClientTimeout

SUG = "https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability"
SCHEMA = """
CREATE TABLE IF NOT EXISTS msrc (
  cve TEXT PRIMARY KEY, release TEXT, released TEXT, title TEXT, tag TEXT, severity TEXT,
  impact TEXT, exploited INTEGER, disclosed INTEGER, likelihood TEXT, cvss REAL, action INTEGER);
"""
MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
SEV_RANK = {"Critical": 3, "Important": 2, "Moderate": 1, "Low": 0}


def migrate(db):
    db.executescript(SCHEMA)


def recent_releases(today=None, n=3):
    d = (today or date.today()).replace(day=1)
    out = []
    for _ in range(n):
        out.append(f"{d.year}-{MONTHS[d.month - 1]}")
        d = (d - timedelta(days=1)).replace(day=1)
    return out


def release_label(release):
    y, m = release.split("-")
    return f"{['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'][MONTHS.index(m)]} {y}"


async def fetch_release(session, release):
    rows, skip = [], 0
    while True:
        params = {"$filter": f"releaseNumber eq '{release}' and issuingCna eq 'Microsoft'",
                  "$top": "500", "$skip": str(skip)}
        async with session.get(SUG, params=params, timeout=ClientTimeout(total=120)) as r:
            if r.status != 200:
                raise RuntimeError(f"Microsoft update guide: HTTP {r.status}")
            data = await r.json(content_type=None)
        page = data.get("value") or []
        for x in page:
            if x.get("isMariner") or not (x.get("cveNumber") or "").startswith("CVE-"):
                continue
            try:
                cvss = float(x.get("baseScore")) if x.get("baseScore") not in (None, "", "N/A") else None
            except ValueError:
                cvss = None
            rows.append((x["cveNumber"], release, (x.get("releaseDate") or "")[:10], x.get("cveTitle"),
                         x.get("tag"), x.get("severity"), x.get("impact"),
                         int(x.get("exploited") == "Yes"), int(x.get("publiclyDisclosed") == "Yes"),
                         x.get("latestSoftwareRelease"), cvss, int(bool(x.get("customerActionRequired")))))
        if len(page) < 500:
            break
        skip += 500
        await asyncio.sleep(0.5)
    return rows


async def refresh(db, session):
    keep = recent_releases()
    total = 0
    for release in keep:
        rows = await fetch_release(session, release)
        if not rows:
            continue  # not released yet (or only an "early" document)
        db.execute("BEGIN")
        db.execute("DELETE FROM msrc WHERE release=?", (release,))
        db.executemany("INSERT OR REPLACE INTO msrc VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", rows)
        db.execute("COMMIT")
        total += len(rows)
    db.execute(f"DELETE FROM msrc WHERE release NOT IN ({','.join('?' * len(keep))})", keep)
    return total


def zero_day_items(db):
    """Exploited or publicly disclosed Microsoft fixes, as dashboard items."""
    items = []
    for r in db.execute("SELECT * FROM msrc WHERE exploited=1 OR disclosed=1"):
        status = "Exploited" if r["exploited"] else "Publicly disclosed"
        items.append({
            "id": f"ms:{r['cve']}", "source": "msrc", "title": r["title"],
            "link": f"https://msrc.microsoft.com/update-guide/vulnerability/{r['cve']}",
            "published": r["released"], "updated": r["released"], "category": status,
            "headline": f"{r['severity']} · {r['impact']}",
            "summary": f"{r['impact']} in {r['tag']}. Microsoft rates it {r['severity']} and says it is "
                       f"{'already being exploited' if r['exploited'] else 'publicly disclosed (details were out before the fix)'}. "
                       f"The fix is in the {release_label(r['release'])} security updates.",
            "cves": [r["cve"]], "tags": [r["tag"]] if r["tag"] else [],
            "fingerprint": f"{r['release']}|{r['exploited']}|{r['disclosed']}",
            "extra": {"release": r["release"], "releaseLabel": release_label(r["release"]), "severity": r["severity"],
                      "impact": r["impact"], "product": r["tag"], "likelihood": r["likelihood"],
                      "exploited": bool(r["exploited"]), "disclosed": bool(r["disclosed"])},
        })
    return items


def cve_info(db, cve_ids):
    out = {}
    ids = list(cve_ids)
    for i in range(0, len(ids), 500):
        chunk = ids[i:i + 500]
        for r in db.execute(f"SELECT * FROM msrc WHERE cve IN ({','.join('?' * len(chunk))})", chunk):
            out[r["cve"]] = {"release": r["release"], "releaseLabel": release_label(r["release"]),
                             "severity": r["severity"], "exploited": bool(r["exploited"]),
                             "disclosed": bool(r["disclosed"]), "likelihood": r["likelihood"], "product": r["tag"]}
    return out


def summary(db):
    """Per release: totals, by product, by impact, and what to patch first."""
    out = []
    releases = [r[0] for r in db.execute("SELECT DISTINCT release FROM msrc")]
    releases.sort(key=lambda rel: (rel.split("-")[0], MONTHS.index(rel.split("-")[1])), reverse=True)
    for rel in releases:
        rows = [dict(r) for r in db.execute("SELECT * FROM msrc WHERE release=?", (rel,))]
        likely = [r for r in rows if (r["likelihood"] or "").startswith("Exploitation More Likely")]
        first = sorted((r for r in rows if r["exploited"] or r["disclosed"] or
                        (r["severity"] == "Critical" and r in likely) or
                        (r["severity"] == "Critical" and (r["cvss"] or 0) >= 9)),
                       key=lambda r: (-r["exploited"], -r["disclosed"], -SEV_RANK.get(r["severity"], 0), -(r["cvss"] or 0)))
        by_tag = Counter(r["tag"] or "Other" for r in rows)
        crit_tag = Counter(r["tag"] or "Other" for r in rows if r["severity"] == "Critical")
        out.append({
            "release": rel, "label": release_label(rel),
            # the day most fixes came out (the Patch Tuesday itself, not early or late extras)
            "date": (Counter(r["released"] for r in rows if r["released"]).most_common(1) or [(None, 0)])[0][0],
            "total": len(rows),
            "critical": sum(r["severity"] == "Critical" for r in rows),
            "exploited": sum(r["exploited"] for r in rows),
            "disclosed": sum(r["disclosed"] for r in rows),
            "likely": len(likely),
            "byProduct": [{"name": t, "count": n, "critical": crit_tag[t]} for t, n in by_tag.most_common(12)],
            "byImpact": [{"name": t, "count": n} for t, n in Counter(r["impact"] or "Other" for r in rows).most_common(8)],
            "first": [{"cve": r["cve"], "title": r["title"], "product": r["tag"], "severity": r["severity"],
                       "impact": r["impact"], "cvss": r["cvss"], "exploited": bool(r["exploited"]),
                       "disclosed": bool(r["disclosed"]), "likelihood": r["likelihood"]} for r in first[:25]],
        })
    return out
