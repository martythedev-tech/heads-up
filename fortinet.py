"""Fortinet PSIRT advisories (FortiGuard), filtered to the products you run.

The RSS feed lists the 50 latest advisories; each links to a CSAF file with
the affected products, CVEs, CVSS, fixed versions per release line and any
workaround or IPS virtual patch. Fortinet's monthly batch covers its whole
catalogue (FortiSIEM, FortiMail, FortiSandbox, ...), so only advisories for
the products in HU_FORTINET_PRODUCTS become dashboard items, plus any other
advisory Fortinet says is exploited in the wild. A few entries are statements
about non-Fortinet bugs (Linux kernel, Node.js); they have no product list and
are only attached to entries that already exist for those CVEs.

Rows are kept after they leave the 50-item feed, and a CSAF file is fetched
again only when the advisory's date in the feed changes.
"""
import asyncio
import html
import json
import os
import re
import xml.etree.ElementTree as ET
from datetime import date, timedelta
from email.utils import parsedate_to_datetime

from aiohttp import ClientTimeout

from dbutil import batch

FEED = "https://filestore.fortinet.com/fortiguard/rss/ir.xml"
CSAF_NS = "{https://fortiguard.fortinet.com/rss/ns/csaf}link"
# Product families you run. A name also covers its variants (FortiClient ->
# FortiClientWindows, FortiClientEMS, ...) but not the Cloud/PaaS services.
PRODUCTS = [p.strip() for p in os.environ.get("HU_FORTINET_PRODUCTS", "FortiOS,FortiAnalyzer,FortiClient").split(",") if p.strip()]
ITEM_DAYS = 180      # advisories this recent become dashboard items
SOON_DAYS = 45       # a critical advisory for your products counts as "Patch soon" this long
SCHEMA = """
CREATE TABLE IF NOT EXISTS fortinet (
  id TEXT PRIMARY KEY, title TEXT, link TEXT, feed_date TEXT, published TEXT, revised TEXT,
  cvss REAL, products TEXT, cves TEXT, exploited INTEGER, summary TEXT, fixes TEXT,
  workaround TEXT, kind TEXT);
"""
EXPLOITED_RE = re.compile(r"exploited in the wild|observed[^.]{0,60}exploit", re.I)
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


def migrate(db):
    db.executescript(SCHEMA)


def watched(product, products=None):
    for w in products or PRODUCTS:
        if product == w or (product.startswith(w) and not re.search(r"\b(Cloud|PaaS|SaaS)\b", product)):
            return True
    return False


def text(fragment):
    t = re.sub(r"(?i)</p>|<br\s*/?>", "\n", fragment or "")
    t = re.sub(r"<[^>]+>", " ", t)
    return re.sub(r"[ \t]+", " ", html.unescape(t)).strip()


def feed_summary(desc):
    """RSS description: 'CVSSv3 Score: 9.4' / the one-line summary / 'Revised on ...'."""
    paras = [re.sub(r"\s+", " ", p).strip() for p in text(desc).split("\n")]
    paras = [p for p in paras if p and not p.startswith(("CVSSv3 Score", "Revised on")) and not re.fullmatch(r"[\d.]+", p)]
    return " ".join(paras)[:700]


def product_names(tree):
    out = []
    def walk(b):
        if b.get("category") == "product" and b.get("name") not in out:
            out.append(b["name"])
        for c in b.get("branches", []):
            walk(c)
    for b in (tree or {}).get("branches", []):
        walk(b)
    return out


def parse_csaf(doc, feed_desc=""):
    """One CSAF document -> the fields we keep."""
    vulns = doc.get("vulnerabilities") or []
    products = product_names(doc.get("product_tree"))
    cves = list(dict.fromkeys(v["cve"] for v in vulns if v.get("cve"))) or list(dict.fromkeys(CVE_RE.findall(text(feed_desc))))
    scores = [s.get("cvss_v3", {}).get("baseScore") for v in vulns for s in v.get("scores", [])]
    scores = [s for s in scores if isinstance(s, (int, float))]
    notes = [n.get("text") or "" for v in vulns for n in v.get("notes", [])]
    exploited = bool(EXPLOITED_RE.search(" ".join(notes) + " " + text(feed_desc)))
    mine = [p for p in products if watched(p)]
    # fixed versions: one line per release train, for your products if any are affected
    fixes = []
    for v in vulns:
        for r in v.get("remediations", []):
            if r.get("category") != "vendor_fix":
                continue
            for line in (r.get("details") or "").splitlines():
                line = re.sub(r"\s+", " ", line).strip()
                if not line or "Not Applicable" in line or line in fixes:
                    continue
                # "FortiAnalyzer 7.6: ..." is yours, "FortiAnalyzer Cloud 7.6: ..." is not
                if mine and not any(re.match(re.escape(p) + r" \d", line) for p in mine):
                    continue
                fixes.append(line)
    work = []
    for n in notes:
        m = re.search(r"Workaround:?\s*(.+)", n, re.S)
        if m:
            work.append(re.sub(r"\s+", " ", m.group(1)).strip())
    for v in vulns:
        for r in v.get("remediations", []):
            if r.get("category") in ("workaround", "mitigation") and r.get("details"):
                work.append(re.sub(r"\s+", " ", r["details"]).strip())
    work = list(dict.fromkeys(work))
    tracking = (doc.get("document") or {}).get("tracking") or {}
    return {
        "id": tracking.get("id"), "title": (doc.get("document") or {}).get("title"),
        "published": (tracking.get("initial_release_date") or "")[:10] or None,
        "revised": (tracking.get("current_release_date") or "")[:10] or None,
        "cvss": max(scores) if scores else None, "products": products, "cves": cves,
        "exploited": exploited, "fixes": fixes[:12], "workaround": " ".join(work)[:600],
        "kind": "advisory" if vulns else "statement",
    }


def feed_entries(xml_text):
    out = []
    for it in ET.fromstring(xml_text).iter("item"):
        link = (it.findtext("link") or "").strip()
        csaf = it.find(CSAF_NS)
        if csaf is None or not link:
            continue  # a couple of very old advisories have no CSAF file
        try:
            feed_date = parsedate_to_datetime(it.findtext("pubDate")).date().isoformat()
        except (TypeError, ValueError):
            feed_date = None
        desc = it.findtext("description") or ""
        m = re.search(r"CVSSv3 Score:\s*([\d.]+)", text(desc))
        out.append({"id": link.rstrip("/").rsplit("/", 1)[-1], "title": (it.findtext("title") or "").strip(),
                    "link": link, "csaf": csaf.text.strip(), "feed_date": feed_date, "desc": desc,
                    "cvss": float(m.group(1)) if m else None})
    return out


async def refresh(db, session):
    async with session.get(FEED, timeout=ClientTimeout(total=60)) as r:
        if r.status != 200:
            raise RuntimeError(f"Fortinet PSIRT feed: HTTP {r.status}")
        entries = feed_entries(await r.text())
    if not entries:
        raise RuntimeError("Fortinet PSIRT feed: no advisories")
    known = {r["id"]: r["feed_date"] for r in db.execute("SELECT id, feed_date FROM fortinet")}
    rows, errors = [], 0
    for e in entries:
        if e["id"] in known and known[e["id"]] == e["feed_date"]:
            continue  # unchanged since last time
        try:
            async with session.get(e["csaf"], timeout=ClientTimeout(total=30)) as r:
                if r.status != 200:
                    raise RuntimeError(f"HTTP {r.status}")
                doc = await r.json(content_type=None)
        except Exception:
            errors += 1
            continue  # try again next run
        p = parse_csaf(doc, e["desc"])
        rows.append((e["id"], p["title"] or e["title"], e["link"], e["feed_date"], p["published"] or e["feed_date"],
                     p["revised"] or e["feed_date"], p["cvss"] if p["cvss"] is not None else e["cvss"],
                     json.dumps(p["products"]), ",".join(p["cves"]), int(p["exploited"]), feed_summary(e["desc"]),
                     json.dumps(p["fixes"]), p["workaround"], p["kind"]))
        await asyncio.sleep(0.3)
    if rows:
        with batch(db):
            db.executemany("INSERT OR REPLACE INTO fortinet VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    if errors and errors == len(rows) + errors:
        raise RuntimeError(f"Fortinet PSIRT: could not fetch {errors} advisory file(s)")
    return db.execute("SELECT COUNT(*) FROM fortinet").fetchone()[0]


def info(r):
    products = json.loads(r["products"] or "[]")
    return {"id": r["id"], "title": r["title"], "link": r["link"], "published": r["published"],
            "revised": r["revised"], "cvss": r["cvss"], "products": products,
            "yours": [p for p in products if watched(p)], "exploited": bool(r["exploited"]),
            "summary": r["summary"], "fixes": json.loads(r["fixes"] or "[]"),
            "workaround": r["workaround"], "kind": r["kind"]}


def relevant(r):
    """An advisory worth its own entry: it affects your products, or Fortinet says it's exploited."""
    return r["kind"] == "advisory" and (bool(info(r)["yours"]) or bool(r["exploited"]))


def items(db, today=None):
    since = ((today or date.today()) - timedelta(days=ITEM_DAYS)).isoformat()
    out = []
    for r in db.execute("SELECT * FROM fortinet WHERE published >= ? ORDER BY published DESC", (since,)):
        if not relevant(r):
            continue
        x = info(r)
        products = x["yours"] or x["products"]
        out.append({
            "id": f"fn:{r['id']}", "source": "fortinet", "title": r["title"], "link": r["link"],
            "published": r["published"], "updated": r["revised"] or r["published"],
            "category": "exploited" if r["exploited"] else "",
            "headline": f"{', '.join(products)} · CVSS {r['cvss']:.1f}" if r["cvss"] is not None else ", ".join(products),
            "summary": r["summary"] or "", "cves": [c for c in (r["cves"] or "").split(",") if c],
            "tags": products, "fingerprint": f"{r['revised']}|{r['exploited']}|{r['cvss']}",
            "extra": x,
        })
    return out


def cve_info(db, cve_ids):
    """CVE -> the newest Fortinet advisory or statement naming it."""
    want, out = set(cve_ids), {}
    for r in db.execute("SELECT * FROM fortinet ORDER BY published"):
        for c in (r["cves"] or "").split(","):
            if c in want:
                out[c] = info(r)
    return out
