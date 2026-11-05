"""TrueNAS security advisories and impact statements (security.truenas.com).

iXsystems publishes two kinds of pages in one RSS feed: advisories for bugs in
TrueNAS itself (for example the middlewared HA bypass) and "impact statements"
on wider CVEs (kernel, Samba, PHP, ...) saying how much each one matters on
TrueNAS. Both carry a TrueNAS-adjusted rating, which is the useful part: a
CVSS 9.8 kernel bug can be Medium on TrueNAS, a High CVE can be High there too.

The feed carries every page's full text, so one request per run is enough.
Its links point at a www.truenas.com/docs/... path that 404s; the real pages
live on security.truenas.com.
"""
import html
import re
import xml.etree.ElementTree as ET
from datetime import date, datetime, timedelta

from dbutil import batch

FEED = "https://security.truenas.com/index.xml"
SITE = "https://security.truenas.com/"
SCHEMA = """
CREATE TABLE IF NOT EXISTS truenas (
  id TEXT PRIMARY KEY, title TEXT, link TEXT, published TEXT, kind TEXT, level TEXT,
  impact TEXT, rating TEXT, upstream TEXT, affected TEXT, fixed_in TEXT, summary TEXT,
  todo TEXT, cves TEXT);
"""
ITEM_DAYS = 365      # advisories this recent become dashboard items
SOON_DAYS = 45       # a High/Critical TrueNAS rating counts as "Patch soon" for this long
KEEP_SINCE = "2024-01-01"   # older pages (2020-2023 security reports) are left out
LEVELS = ["none", "low", "medium", "high", "critical"]
CVE_RE = re.compile(r"CVE-(\d{4})-(\d{4,})")
FIELD_RE = re.compile(r"^(Status|CVE|CVEs|Affected products?|Severity \(TrueNAS-adjusted\)|Severity|"
                      r"Upstream severity|Fixed in|Fixed versions?|Workaround|Mitigation)\s*:\s*(.+)$", re.I)
TODO_HEADINGS = re.compile(r"(recommend|remediat|mitigat|what (should|to do)|action|workaround|protect)", re.I)


def migrate(db):
    db.executescript(SCHEMA)


def site_link(link):
    """www.truenas.com/docs/scale/25.04/scale/x/ -> security.truenas.com/scale/x/"""
    return re.sub(r"^https?://www\.truenas\.com/docs/scale/[\d.]+/", SITE, link or "")


def text(fragment):
    t = re.sub(r"(?i)<br\s*/?>", "\n", fragment)
    t = re.sub(r"(?i)</(p|li|h\d|tr)>", "\n", t)
    t = re.sub(r"<[^>]+>", "", t)
    return re.sub(r"[ \t]+", " ", html.unescape(t)).strip()


def level_of(s):
    """'Low–Medium — ...' -> 'medium' (the higher end); 'Not applicable ...' -> 'none'."""
    s = (s or "").strip()
    if not s:
        return None
    head = re.split(r"\s[—-]\s|;|\(|,", s, maxsplit=1)[0].lower()
    if head.startswith(("not ", "none", "n/a")):
        return "none"
    found = [lv for lv in LEVELS[1:] if lv in head]
    return max(found, key=LEVELS.index) if found else None


def title_cves(title):
    """'Samba ... (CVE-2026-1933, -2340, -3012)' -> all three in full."""
    out, year = [], None
    for m in re.finditer(r"CVE-(\d{4})-(\d{4,})|(?<=[\s,])-(\d{4,})\b", title or ""):
        if m.group(1):
            year = m.group(1)
            out.append(f"CVE-{year}-{m.group(2)}")
        elif year:
            out.append(f"CVE-{year}-{m.group(3)}")
    return out


def parse(desc):
    """Pull the rating fields, summary and advice out of one page's HTML."""
    desc = re.sub(r"(?is)<script.*?</script>|<svg.*?</svg>", "", desc or "")
    parts = re.split(r"(?is)<h[23][^>]*>(.*?)</h[23]>", desc)
    head, sections = parts[0], [(text(parts[i]), parts[i + 1]) for i in range(1, len(parts) - 1, 2)]
    fields = {}
    for line in text(head).splitlines():
        m = FIELD_RE.match(line.strip())
        if m:
            fields.setdefault(m.group(1).lower(), m.group(2).strip())
    out = {"status": fields.get("status"), "affected": fields.get("affected products") or fields.get("affected product"),
           "upstream": fields.get("upstream severity"),
           "fixed_in": fields.get("fixed in") or fields.get("fixed versions") or fields.get("fixed version"),
           "cves": CVE_RE.findall(fields.get("cve") or fields.get("cves") or "")}
    rating = fields.get("severity (truenas-adjusted)")
    impact = None
    whole = text(desc)
    m = re.search(r"TrueNAS Impact\s*:\s*([^\n]+)", whole)
    if m:  # "TrueNAS Impact: LOW–MEDIUM — The kernel bug is present ..."
        lv, _, why = re.sub(r"\s[—-]\s", "\x00", m.group(1), count=1).partition("\x00")
        rating = rating or lv.strip()
        impact = why.strip() or None
    elif fields.get("severity"):  # "High (CVE), Low (TrueNAS Impact)"
        m2 = re.search(r"([^,]+?)\s*\(TrueNAS Impact\)", fields["severity"])
        rating = rating or (m2.group(1).strip() if m2 else None)
        out["upstream"] = out["upstream"] or re.sub(r"\s*\(CVE\)", "", fields["severity"].split(",")[0]).strip()
    out["level"] = level_of(rating)
    if rating:  # "High — CVSS 3.1 8.3 (...)" -> label "High", the rest explains it
        label, _, rest = re.sub(r"\s[—-]\s|;\s", "\x00", rating, count=1).partition("\x00")
        label = label.strip()
        rating = label.title() if label.isupper() or label.islower() else label
        impact = impact or rest.strip() or None
    out["rating"] = rating
    out["impact"] = impact
    # summary: first paragraphs of the first section, minus the impact line we show separately
    summary = ""
    if sections:
        paras = [text(p) for p in re.findall(r"(?is)<p>(.*?)</p>", sections[0][1])]
        paras = [p for p in paras if p and not p.startswith("TrueNAS Impact")]
        summary = " ".join(paras[:2])
    out["summary"] = shorten(summary, 700)
    todo = ""
    for name, body in sections:
        if TODO_HEADINGS.search(name):
            paras = [text(p) for p in re.findall(r"(?is)<(?:p|li)>(.*?)</(?:p|li)>", body)]
            todo = " ".join(p for p in paras[:3] if p)
            if todo:
                break
    out["todo"] = shorten(todo, 500)
    return out


def shorten(s, n):
    s = re.sub(r"\s+", " ", s or "").strip()
    return s if len(s) <= n else s[: n - 1].rsplit(" ", 1)[0] + "…"


def pub_date(s):
    """'2026-11-03 00:00 EST' -> '2026-11-03'."""
    m = re.match(r"(\d{4}-\d{2}-\d{2})", (s or "").strip())
    return m.group(1) if m else None


def parse_feed(xml_text):
    rows = []
    for it in ET.fromstring(xml_text).iter("item"):
        published = pub_date(it.findtext("pubDate"))
        if not published or published < KEEP_SINCE:
            continue  # undated reference pages (SBOMs, policies) and old reports
        link = site_link(it.findtext("link") or it.findtext("guid"))
        title = (it.findtext("title") or "").strip()
        p = parse(it.findtext("description"))
        cves = list(dict.fromkeys(title_cves(title) + [f"CVE-{y}-{n}" for y, n in p["cves"]]))
        # A "Fixed in" version means a bug in TrueNAS itself; the rest are impact statements.
        kind = "advisory" if p["fixed_in"] else "impact"
        slug = link.rstrip("/").rsplit("/", 1)[-1] or title
        rows.append((slug, title, link, published, kind, p["level"], p["impact"], p["rating"], p["upstream"],
                     p["affected"], p["fixed_in"], p["summary"], p["todo"], ",".join(cves)))
    return rows


async def refresh(db, session):
    async with session.get(FEED) as r:
        if r.status != 200:
            raise RuntimeError(f"TrueNAS advisories: HTTP {r.status}")
        rows = parse_feed(await r.text())
    if not rows:
        raise RuntimeError("TrueNAS advisories: feed had no dated entries")
    with batch(db):
        db.execute("DELETE FROM truenas")
        db.executemany("INSERT OR REPLACE INTO truenas VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    return len(rows)


def info(r):
    return {"title": r["title"], "link": r["link"], "published": r["published"], "kind": r["kind"],
            "level": r["level"], "rating": r["rating"], "impact": r["impact"], "upstream": r["upstream"],
            "affected": r["affected"], "fixedIn": r["fixed_in"], "summary": r["summary"], "todo": r["todo"]}


def items(db, today=None):
    """Recent advisories as dashboard items (merged with other sources by CVE)."""
    today = today or date.today()
    since = (today - timedelta(days=ITEM_DAYS)).isoformat()
    out = []
    for r in db.execute("SELECT * FROM truenas WHERE published >= ? ORDER BY published DESC", (since,)):
        cves = [c for c in (r["cves"] or "").split(",") if c]
        lv = r["level"]
        what = "advisory" if r["kind"] == "advisory" else "impact statement"
        rating = f"TrueNAS rates the impact {r['rating']}" if r["rating"] else "No TrueNAS rating given"
        out.append({
            "id": f"tn:{r['id']}", "source": "truenas", "title": r["title"], "link": r["link"],
            "published": r["published"], "updated": r["published"],
            "category": lv or "", "headline": rating,
            "summary": r["summary"] or r["impact"] or "",
            "cves": cves, "tags": ["TrueNAS"],
            "fingerprint": f"{r['published']}|{r['rating']}|{r['fixed_in']}",
            "extra": {**info(r), "what": what},
        })
    return out


def cve_info(db, cve_ids):
    """CVE -> what TrueNAS said about it (newest page wins)."""
    want, out = set(cve_ids), {}
    for r in db.execute("SELECT * FROM truenas ORDER BY published"):
        for c in (r["cves"] or "").split(","):
            if c in want:
                out[c] = info(r)
    return out


def is_recent(published, days=SOON_DAYS, today=None):
    try:
        d = datetime.fromisoformat(published[:10]).date()
    except (TypeError, ValueError):
        return False
    return d >= (today or date.today()) - timedelta(days=days)
