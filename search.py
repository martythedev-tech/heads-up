"""Search everything Heads Up has stored, not only what reached the main list.

The page filters the main list by itself; this finds the rest: every Microsoft
CVE of the last three releases, the full CISA and VulnCheck lists, Fortinet
advisories and the Exploit-DB / Metasploit index. A match that is already on the
main list is left out, so nothing appears twice.
"""
import json
import re

import exploits as X
import msrc as MS

LIMIT = 50       # results sent to the page
PER_TABLE = 1000
CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
NVD_PAGE = "https://nvd.nist.gov/vuln/detail/{}"
MS_PAGE = "https://msrc.microsoft.com/update-guide/vulnerability/{}"
NEWEST_CVE = ("ORDER BY CAST(substr(cve, 5, 4) AS INTEGER) DESC, "
              "CAST(substr(cve, 10) AS INTEGER) DESC ")


def _where(columns, words):
    """Every word must appear somewhere in the columns (same rule as the page)."""
    hay = " || ' ' || ".join(f"COALESCE({c}, '')" for c in columns)
    clause = " AND ".join([f"({hay}) LIKE ? ESCAPE '\\'"] * len(words))
    escaped = [w.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") for w in words]
    return clause, [f"%{w}%" for w in escaped]


def _rows(db, table, columns, words, order=NEWEST_CVE):
    clause, params = _where(columns, words)
    return db.execute(f"SELECT * FROM {table} WHERE {clause} {order}LIMIT {PER_TABLE}", params).fetchall()


def _main_list(db):
    cves, links = set(), set()
    for r in db.execute("SELECT cves, link FROM items WHERE active=1"):
        cves.update(json.loads(r["cves"] or "[]"))
        links.add(r["link"])
    return cves, links


def _cve_sort_key(entry):
    m = re.fullmatch(r"CVE-(\d{4})-(\d+)", entry["id"])
    return (int(m[1]), int(m[2])) if m else (0, 0)


def search(db, q):
    words = q.lower().split()[:8]
    if not words:
        return {"results": [], "total": 0, "onMain": False}
    on_main, main_links = _main_list(db)
    found = {}

    def entry(key, title, link=None):
        e = found.setdefault(key, {"id": key, "title": None, "product": None, "link": link or NVD_PAGE.format(key),
                                   "severity": None, "cvss": None, "exploited": False, "sources": [], "notes": []})
        e["title"] = e["title"] or title
        return e

    # 'Microsoft MS': Microsoft's product names leave the company name out ("Windows Paint").
    for r in _rows(db, "msrc", ["cve", "title", "tag", "impact", "'Microsoft MS'"], words):
        e = entry(r["cve"], r["title"], MS_PAGE.format(r["cve"]))
        e.update(product=r["tag"], severity=r["severity"], cvss=r["cvss"], exploited=e["exploited"] or bool(r["exploited"]))
        e["sources"].append("ms")
        e["notes"].append(f"Fixed in Microsoft's {MS.release_label(r['release'])} updates. "
                          f"Microsoft: {r['likelihood'] or 'no exploitation rating'}.")
    for r in _rows(db, "kev", ["cve", "vendor", "product", "name", "description"], words):
        e = entry(r["cve"], r["name"])
        e["product"] = e["product"] or r["product"]
        e["exploited"] = True
        e["sources"].append("cisa")
        e["notes"].append(f"CISA listed it as exploited on {r['added']}; the main list shows recent ones.")
    for r in _rows(db, "vckev", ["cve", "vendor", "product", "name", "description"], words):
        e = entry(r["cve"], r["name"])
        e["product"] = e["product"] or r["product"]
        e["exploited"] = True
        e["sources"].append("vc")
        e["notes"].append(f"VulnCheck reported it exploited on {r['added']}; the main list shows recent ones.")
    for r in _rows(db, "fortinet", ["id", "title", "products", "cves", "summary", "'Fortinet'"], words, order=""):
        if r["link"] in main_links:
            continue
        for key in [c for c in (r["cves"] or "").split(",") if c] or [r["id"]]:
            e = entry(key, r["title"], r["link"])
            e["cvss"] = e["cvss"] or r["cvss"]
            e["sources"].append("fn")
            e["notes"].append(f"Fortinet advisory from {r['published'] or r['feed_date']}.")
    for r in _rows(db, "exploit_index", ["cve", "edb", "msf"], words):
        entries = json.loads(r["msf"] or "[]") or json.loads(r["edb"] or "[]")
        entry(r["cve"], entries[0]["title"] if entries else None)
    query_id = q.strip().upper()
    if CVE_ID.fullmatch(query_id) and query_id not in found and query_id not in on_main:
        if db.execute("SELECT 1 FROM cve WHERE id=?", (query_id,)).fetchone():
            entry(query_id, None)["notes"].append("Seen earlier, but no feed lists it now.")

    results = [e for e in found.values() if e["id"] not in on_main]
    results.sort(key=lambda e: (e["id"] == query_id, _cve_sort_key(e)), reverse=True)
    total = len(results)
    results = results[:LIMIT]
    _add_exploit_code(db, results)
    return {"results": results, "total": total, "onMain": query_id in on_main}


def _add_exploit_code(db, results):
    ids = [e["id"] for e in results]
    if not ids:
        return
    marks = ",".join("?" * len(ids))
    scores = {r["id"]: r for r in db.execute(f"SELECT id, cvss, severity, poc FROM cve WHERE id IN ({marks})", ids)}
    index = X.exploit_rows(db, ids)
    for e in results:
        row = scores.get(e["id"])
        if row:
            e["cvss"] = e["cvss"] or row["cvss"]
            e["severity"] = e["severity"] or row["severity"]
        code = index.get(e["id"]) or {}
        e["exploitCode"] = {"msf": len(code.get("msf") or []), "edb": len(code.get("edb") or []),
                            "poc": len(json.loads(row["poc"] or "[]")) if row else 0}
        e["title"] = e["title"] or e["id"]
