"""Microsoft Patch Tuesday, from the Security Update Guide API (free, no key).

Only Microsoft's own fixes (issuingCna = Microsoft), not the open-source
packages Microsoft also ships for Azure Linux. The three most recent
monthly releases are kept in full.

For "What we run" (a month you're patched through), every Microsoft CVE on the
list also needs the month Microsoft fixed it in. msrc_cve keeps that for CVEs
outside the three releases: releases that age out are copied there, and older
CVEs that CISA or VulnCheck list are looked up once in the update guide.
"""
import asyncio
import json

from dbutil import batch
import time
from collections import Counter
from datetime import date, timedelta

from aiohttp import ClientTimeout

SUG = "https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability"
SCHEMA = """
CREATE TABLE IF NOT EXISTS msrc (
  cve TEXT PRIMARY KEY, release TEXT, released TEXT, title TEXT, tag TEXT, severity TEXT,
  impact TEXT, exploited INTEGER, disclosed INTEGER, likelihood TEXT, cvss REAL, action INTEGER);
CREATE TABLE IF NOT EXISTS msrc_cve (
  cve TEXT PRIMARY KEY, release TEXT, released TEXT, tag TEXT, looked REAL);
"""
LOOKUP_RETRY = 7 * 86400   # a CVE Microsoft had nothing for is asked again after a week
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


def release_key(release):
    """'2026-Nov' -> (2026, 11)"""
    y, m = release.split("-")
    return int(y), MONTHS.index(m) + 1


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
        with batch(db):
            db.execute("DELETE FROM msrc WHERE release=?", (release,))
            db.executemany("INSERT OR REPLACE INTO msrc VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", rows)
        total += len(rows)
    marks = ",".join("?" * len(keep))
    # keep the fix month of releases that age out
    db.execute(f"INSERT OR REPLACE INTO msrc_cve SELECT cve, release, released, tag, ? FROM msrc WHERE release NOT IN ({marks})",
               (time.time(), *keep))
    db.execute(f"DELETE FROM msrc WHERE release NOT IN ({marks})", keep)
    return total


def lookup_candidates(db, limit):
    """Microsoft CVEs on the list (CISA / VulnCheck) with no known fix month."""
    known = {r[0] for r in db.execute("SELECT cve FROM msrc")}
    known |= {r[0] for r in db.execute("SELECT cve FROM msrc_cve WHERE release IS NOT NULL OR looked > ?",
                                       (time.time() - LOOKUP_RETRY,))}
    out = []
    for r in db.execute("SELECT cves FROM items WHERE active=1 AND source IN ('kev', 'vulncheck')"
                        " AND (title LIKE '%Microsoft%' OR title LIKE '%Windows%') ORDER BY published DESC"):
        for c in json.loads(r[0] or "[]"):
            if c not in known and c not in out:
                out.append(c)
    return out[:limit]


async def lookup_old(db, session, limit=60):
    """Ask the update guide for the release that fixed each CVE outside the kept months."""
    found = 0
    for cve in lookup_candidates(db, limit):
        try:
            params = {"$filter": f"cveNumber eq '{cve}'"}
            async with session.get(SUG, params=params, timeout=ClientTimeout(total=30)) as r:
                if r.status != 200:
                    continue
                rows = (await r.json(content_type=None)).get("value") or []
        except Exception:
            continue
        hit = next((x for x in rows if x.get("releaseNumber") and not x.get("isMariner")), None)
        db.execute("INSERT OR REPLACE INTO msrc_cve VALUES(?,?,?,?,?)",
                   (cve, hit["releaseNumber"] if hit else None, (hit.get("releaseDate") or "")[:10] if hit else None,
                    hit.get("tag") if hit else None, time.time()))
        found += bool(hit)
        await asyncio.sleep(0.3)
    return found


def fix_months(db, cve_ids):
    """CVE -> the Microsoft release that fixed it, from the kept months or msrc_cve."""
    out = {}
    ids = list(cve_ids)
    for i in range(0, len(ids), 500):
        chunk = ids[i:i + 500]
        marks = ",".join("?" * len(chunk))
        for r in db.execute(f"SELECT cve, release, tag FROM msrc_cve WHERE release IS NOT NULL AND cve IN ({marks})", chunk):
            out[r["cve"]] = r
        for r in db.execute(f"SELECT cve, release, tag FROM msrc WHERE cve IN ({marks})", chunk):
            out[r["cve"]] = r
    return {c: {"release": r["release"], "label": release_label(r["release"]), "month": list(release_key(r["release"])),
                "product": r["tag"]} for c, r in out.items()}


def zero_day_items(db):
    """Microsoft fixes that join the main list: exploited, publicly disclosed, or
    Critical/Important with proof-of-concept code on GitHub."""
    items = []
    for r in db.execute("SELECT m.*, c.poc AS poc FROM msrc m LEFT JOIN cve c ON c.id = m.cve "
                        "WHERE m.exploited=1 OR m.disclosed=1 OR (m.severity IN ('Critical', 'Important') "
                        "AND c.poc IS NOT NULL AND c.poc != '[]')"):
        poc_only = not r["exploited"] and not r["disclosed"]
        status = "Exploited" if r["exploited"] else "Publicly disclosed" if r["disclosed"] else "Public exploit code"
        said = ("It is not reported as exploited, but unverified exploit code has appeared on GitHub." if poc_only
                else "Microsoft says it is already being exploited." if r["exploited"]
                else "Microsoft says it is publicly disclosed (details were out before the fix).")
        items.append({
            "id": f"ms:{r['cve']}", "source": "msrc", "title": r["title"],
            "link": f"https://msrc.microsoft.com/update-guide/vulnerability/{r['cve']}",
            "published": r["released"], "updated": r["released"], "category": status,
            "headline": f"{r['severity']} · {r['impact']}",
            "summary": f"{r['impact']} in {r['tag']}. Microsoft rates it {r['severity']}. {said} "
                       f"Microsoft fixed it in its {release_label(r['release'])} release.",
            "cves": [r["cve"]], "tags": [r["tag"]] if r["tag"] else [],
            "fingerprint": f"{r['release']}|{r['exploited']}|{r['disclosed']}" + ("|poc" if poc_only else ""),
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
                             "severity": r["severity"], "exploited": bool(r["exploited"]), "cvss": r["cvss"],
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
