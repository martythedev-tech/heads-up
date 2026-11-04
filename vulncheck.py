"""VulnCheck Known Exploited Vulnerabilities (VulnCheck KEV).

Everything on CISA's list plus many more, often earlier, each with citations.
Needs a free VulnCheck Community API token. Attribution: data is labelled
"VulnCheck KEV" wherever it is shown.
"""
import io
import json

from dbutil import batch
import time
import zipfile

from aiohttp import ClientTimeout

API = "https://api.vulncheck.com/v3"
SCHEMA = """
CREATE TABLE IF NOT EXISTS vckev (
  cve TEXT PRIMARY KEY, vendor TEXT, product TEXT, name TEXT, description TEXT,
  added TEXT, cisa_added TEXT, ransomware TEXT, reports TEXT, xdb TEXT, canary INTEGER);
"""


def migrate(db):
    db.executescript(SCHEMA)


def _headers(token):
    return {"Authorization": f"Bearer {token}", "Accept": "application/json"}


async def check_token(session, token):
    async with session.get(f"{API}/index/vulncheck-kev", params={"limit": "1"}, headers=_headers(token),
                           timeout=ClientTimeout(total=30)) as r:
        if r.status == 401 or r.status == 403:
            raise RuntimeError("VulnCheck refused the token (401/403)")
        if r.status != 200:
            raise RuntimeError(f"VulnCheck: HTTP {r.status}")
        return True


def _entries(blob):
    """The backup is a zip of JSON files; each holds a list of entries (or {'data': [...]})."""
    out = []
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        for name in z.namelist():
            if not name.endswith(".json"):
                continue
            data = json.loads(z.read(name))
            if isinstance(data, dict):
                data = data.get("data") or data.get("results") or []
            out.extend(x for x in data if isinstance(x, dict))
    return out


async def _download_all(session, token):
    """Prefer the bulk backup; fall back to paging the index."""
    try:
        async with session.get(f"{API}/backup/vulncheck-kev", headers=_headers(token), timeout=ClientTimeout(total=60)) as r:
            if r.status != 200:
                raise RuntimeError(f"backup: HTTP {r.status}")
            meta = await r.json(content_type=None)
        links = [d.get("url") for d in meta.get("data") or [] if d.get("url")]
        if links:
            entries = []
            for url in links:
                async with session.get(url, timeout=ClientTimeout(total=300)) as r:  # pre-signed, no auth header
                    if r.status != 200:
                        raise RuntimeError(f"backup file: HTTP {r.status}")
                    entries.extend(_entries(await r.read()))
            if entries:
                return entries
    except Exception:
        pass
    entries = []
    for page in range(1, 200):  # the index pages by number: _meta.page / _meta.total_pages
        async with session.get(f"{API}/index/vulncheck-kev", params={"limit": "500", "page": str(page)},
                               headers=_headers(token), timeout=ClientTimeout(total=120)) as r:
            if r.status != 200:
                raise RuntimeError(f"VulnCheck index: HTTP {r.status}")
            data = await r.json(content_type=None)
        entries.extend(data.get("data") or [])
        if page >= ((data.get("_meta") or {}).get("total_pages") or 0) or not data.get("data"):
            break
    return entries


def _day(s):
    return (s or "")[:10] or None


async def refresh(db, session, token):
    entries = await _download_all(session, token)
    rows = {}
    for e in entries:
        reports = sorted(({"url": x.get("url"), "date": _day(x.get("date_added"))}
                          for x in e.get("vulncheck_reported_exploitation") or [] if x.get("url")),
                         key=lambda x: x["date"] or "")
        xdb = [{"id": x.get("xdb_id"), "url": x.get("xdb_url"), "date": _day(x.get("date_added")),
                "type": x.get("exploit_type")} for x in e.get("vulncheck_xdb") or []]
        for cve in e.get("cve") or []:
            if not str(cve).startswith("CVE-"):
                continue
            rows[cve] = (cve, e.get("vendorProject"), e.get("product"), e.get("vulnerabilityName"),
                         (e.get("shortDescription") or "")[:600], _day(e.get("date_added")), _day(e.get("cisa_date_added")),
                         e.get("knownRansomwareCampaignUse"), json.dumps(reports[:6]), json.dumps(xdb[:5]),
                         int(bool(e.get("reported_exploited_by_vulncheck_canaries"))))
    if not rows:
        raise RuntimeError("VulnCheck returned no entries")
    with batch(db):
        db.execute("DELETE FROM vckev")
        db.executemany("INSERT INTO vckev VALUES(?,?,?,?,?,?,?,?,?,?,?)", list(rows.values()))
    return len(rows)


def kev_title(vendor, product):
    vendor, product = vendor or "", product or ""
    return product if product.lower().startswith(vendor.lower()) else f"{vendor} {product}".strip()


def items(db, since, cisa_cves):
    """Recently added VulnCheck KEV entries that CISA hasn't listed (the extra coverage)."""
    out = []
    for r in db.execute("SELECT * FROM vckev WHERE added >= ?", (since,)):
        if r["cve"] in cisa_cves:
            continue
        reports = json.loads(r["reports"] or "[]")
        out.append({
            "id": f"vc:{r['cve']}", "source": "vulncheck", "title": kev_title(r["vendor"], r["product"]),
            "link": f"https://vulncheck.com/browse/cve/{r['cve']}",
            "published": r["added"], "updated": r["added"], "category": "Known exploited (VulnCheck KEV)",
            "headline": r["name"], "summary": r["description"], "cves": [r["cve"]],
            "tags": [t for t in (r["vendor"],) if t],
            "fingerprint": f"{r['added']}|{len(reports)}|{r['ransomware']}",
            "extra": {"ransomware": r["ransomware"], "reports": reports, "canary": bool(r["canary"])},
        })
    return out


def cve_info(db, cve_ids):
    out = {}
    ids = list(cve_ids)
    for i in range(0, len(ids), 500):
        chunk = ids[i:i + 500]
        for r in db.execute(f"SELECT * FROM vckev WHERE cve IN ({','.join('?' * len(chunk))})", chunk):
            out[r["cve"]] = {"added": r["added"], "cisaAdded": r["cisa_added"], "ransomware": r["ransomware"],
                             "reports": json.loads(r["reports"] or "[]"), "xdb": json.loads(r["xdb"] or "[]"),
                             "canary": bool(r["canary"])}
    return out


def stats(db, today_iso, days=90):
    """How much VulnCheck adds over CISA, for the Charts tab."""
    from datetime import date, timedelta
    since = (date.fromisoformat(today_iso) - timedelta(days=days)).isoformat()
    rows = list(db.execute("SELECT v.cve, v.added, k.added AS cisa FROM vckev v LEFT JOIN kev k ON k.cve = v.cve WHERE v.added >= ?", (since,)))
    only = [r for r in rows if not r["cisa"]]
    leads = sorted((date.fromisoformat(r["cisa"][:10]) - date.fromisoformat(r["added"][:10])).days
                   for r in rows if r["cisa"] and r["added"] and r["cisa"][:10] > r["added"][:10])
    return {"days": days, "total": len(rows), "notOnCisa": len(only), "earlierThanCisa": len(leads),
            "medianLeadDays": leads[len(leads) // 2] if leads else None}
