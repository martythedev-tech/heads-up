#!/usr/bin/env python3
"""Heads Up: an internal dashboard of critical vulnerabilities.

Sources, polled politely in the background:
  - Cloudflare Radar Zero Wire briefings (RSS)
  - CISA Known Exploited Vulnerabilities catalog (JSON)
  - Ubuntu Security Notices (JSON)
Each CVE is enriched with FIRST EPSS, NVD CVSS and Ubuntu's own priority and
per-release fix status. Anyone on the network can read the dashboard; marking
an item Investigating / Not affected / Patched needs the shared password.
"""
import asyncio
import hashlib
import json
import os
import re
import secrets
import sqlite3
import ssl
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from html import escape
from html.parser import HTMLParser
from pathlib import Path

from aiohttp import ClientSession, ClientTimeout, web

import charts as C
from dbutil import batch
import exploits as X
import msrc as MS
import vulncheck as VC
import users as U
import vulns as V
import webhooks as W

VERSION = "0.9.0"
UA = f"heads-up/{VERSION} (internal vulnerability dashboard)"
HERE = Path(__file__).resolve().parent
STATE = Path(os.environ.get("STATE_DIRECTORY", HERE / "state"))
CREDS = Path(os.environ.get("CREDENTIALS_DIRECTORY", "/nonexistent"))
DEV = os.environ.get("HU_DEV") == "1"
BIND = os.environ.get("HU_BIND", "127.0.0.1" if DEV else "0.0.0.0")
HTTPS_PORT = int(os.environ.get("HU_HTTPS_PORT", "9443"))
HTTP_PORT = int(os.environ.get("HU_HTTP_PORT", "8765" if DEV else "9080"))
TLS_CERT = os.environ.get("HU_TLS_CERT", "/etc/heads-up/tls/server.crt")
CA_CERT = os.environ.get("HU_CA_CERT", "/etc/heads-up/tls/ca.crt")
# Ubuntu releases the dashboard reports fix status for (codenames, oldest last).
UBUNTU_RELEASES = os.environ.get("HU_UBUNTU_RELEASES", "resolute noble jammy").split()
SERVER_NAME = os.environ.get("SERVER_NAME", "")
PUBLIC_URL = os.environ.get("HU_PUBLIC_URL") or (
    f"http://127.0.0.1:{HTTP_PORT}" if DEV else f"https://{SERVER_NAME or 'localhost'}:{HTTPS_PORT}")
COOKIE = "hu_session"
ASSET_VERSION = hashlib.sha256(b"".join(
    (HERE / "static" / f).read_bytes() for f in ("app.js", "charts.js", "style.css", "index.html"))).hexdigest()[:10]
SESSION_DAYS = 30

ZERO_WIRE_RSS = "https://radar.cloudflare.com/security/zero-wire/rss"
KEV_JSON = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
USN_JSON = "https://ubuntu.com/security/notices.json"
UBUNTU_CVE = "https://ubuntu.com/security/cves/{}.json"
EPSS = "https://api.first.org/data/v1/epss"
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV = "https://api.osv.dev/v1/vulns/UBUNTU-{}"

KEV_WINDOW_DAYS = 45      # KEV additions shown as their own items
USN_WINDOW_DAYS = 21      # Ubuntu notices shown
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
NS = {"content": "http://purl.org/rss/1.0/modules/content/",
      "dc": "http://purl.org/dc/elements/1.1/"}
STATES = ("untriaged", "investigating", "not_affected", "patched")


def log(*args):
    print(*args, flush=True)


def now():
    return time.time()


# --- storage ---------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS items (
  id TEXT PRIMARY KEY, source TEXT NOT NULL, title TEXT, link TEXT,
  published TEXT, updated TEXT, category TEXT, headline TEXT, summary TEXT,
  body TEXT, cves TEXT, tags TEXT, extra TEXT, fingerprint TEXT,
  first_seen REAL, changed_at REAL, active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS cve (
  id TEXT PRIMARY KEY, epss REAL, epss_pct REAL, epss_at REAL,
  cvss REAL, severity TEXT, vector TEXT, nvd_at REAL,
  ubuntu_priority TEXT, ubuntu_status TEXT, ubuntu_at REAL);
CREATE TABLE IF NOT EXISTS kev (
  cve TEXT PRIMARY KEY, vendor TEXT, product TEXT, name TEXT, added TEXT,
  due TEXT, ransomware TEXT, description TEXT, action TEXT, cwes TEXT);
CREATE TABLE IF NOT EXISTS triage (
  item_id TEXT PRIMARY KEY, state TEXT, note TEXT, by TEXT, at REAL);
CREATE TABLE IF NOT EXISTS triage_log (
  item_id TEXT, state TEXT, note TEXT, by TEXT, at REAL);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY, username TEXT, expires REAL);
CREATE TABLE IF NOT EXISTS sources (
  name TEXT PRIMARY KEY, ok_at REAL, err_at REAL, error TEXT, count INTEGER);
"""


def db_open():
    STATE.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(STATE / "heads-up.db", isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    # With WAL, NORMAL syncs to disk at checkpoints instead of on every
    # commit: still crash-safe, far fewer waits on a slow disk.
    db.execute("PRAGMA synchronous=NORMAL")
    db.execute("PRAGMA busy_timeout=5000")
    # 0.3 sessions belonged to the shared password; accounts replace them.
    cols = [r[1] for r in db.execute("PRAGMA table_info(sessions)")]
    if cols and "username" not in cols:
        db.execute("DROP TABLE sessions")
    db.executescript(SCHEMA)
    if "cwes" not in [r[1] for r in db.execute("PRAGMA table_info(kev)")]:
        db.execute("ALTER TABLE kev ADD COLUMN cwes TEXT")
    db.executescript(C.RADAR_SCHEMA)
    X.migrate(db)
    MS.migrate(db)
    VC.migrate(db)
    return db


def source_ok(db, name, count):
    db.execute("INSERT INTO sources(name, ok_at, count, error) VALUES(?,?,?,NULL) "
               "ON CONFLICT(name) DO UPDATE SET ok_at=excluded.ok_at, count=excluded.count, error=NULL",
               (name, now(), count))


def source_err(db, name, error):
    log(f"[{name}] {error}")
    db.execute("INSERT INTO sources(name, err_at, error) VALUES(?,?,?) "
               "ON CONFLICT(name) DO UPDATE SET err_at=excluded.err_at, error=excluded.error",
               (name, now(), str(error)[:300]))


def upsert_item(db, item):
    """Insert or update one item; changed_at moves only when its fingerprint changes."""
    row = db.execute("SELECT fingerprint, first_seen, changed_at FROM items WHERE id=?",
                     (item["id"],)).fetchone()
    t = now()
    first_seen = row["first_seen"] if row else t
    changed_at = (row["changed_at"] if row and row["fingerprint"] == item["fingerprint"] else t)
    if row and row["fingerprint"] != item["fingerprint"]:
        log(f"updated: {item['id']}")
    db.execute(
        "INSERT OR REPLACE INTO items(id, source, title, link, published, updated, category, headline,"
        " summary, body, cves, tags, extra, fingerprint, first_seen, changed_at, active)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)",
        (item["id"], item["source"], item["title"], item["link"], item.get("published"),
         item.get("updated"), item.get("category"), item.get("headline"), item.get("summary"),
         item.get("body"), json.dumps(item.get("cves", [])), json.dumps(item.get("tags", [])),
         json.dumps(item.get("extra", {})), item["fingerprint"], first_seen, changed_at))


def retire_missing(db, source, keep_ids):
    marks = ",".join("?" * len(keep_ids)) or "''"
    db.execute(f"UPDATE items SET active=0 WHERE source=? AND id NOT IN ({marks})",
               (source, *keep_ids))


# --- HTML from feeds: keep a small safe subset -------------------------------

class Sanitizer(HTMLParser):
    ALLOWED = {"p", "strong", "b", "em", "i", "ul", "ol", "li", "a", "h2", "h3", "h4",
               "code", "pre", "time", "br", "blockquote", "table", "thead", "tbody",
               "tr", "th", "td"}
    DROP_CONTENT = {"script", "style", "iframe", "object", "svg", "noscript", "template"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out = []
        self.skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in self.DROP_CONTENT:
            self.skip += 1
            return
        if self.skip or tag not in self.ALLOWED:
            return
        attrs = dict(attrs)
        extra = ""
        if tag == "a":
            href = attrs.get("href") or ""
            if href.startswith("/"):
                href = "https://radar.cloudflare.com" + href
            if not href.startswith(("https://", "http://")):
                return
            extra = f' href="{escape(href)}" target="_blank" rel="noopener noreferrer"'
        elif tag == "time" and attrs.get("datetime"):
            extra = f' datetime="{escape(attrs["datetime"])}"'
        self.out.append(f"<{tag}{extra}>")

    def handle_endtag(self, tag):
        if tag in self.DROP_CONTENT:
            self.skip = max(0, self.skip - 1)
            return
        if not self.skip and tag in self.ALLOWED and tag != "br":
            self.out.append(f"</{tag}>")

    def handle_data(self, data):
        if not self.skip:
            self.out.append(escape(data))


def sanitize(markup):
    s = Sanitizer()
    s.feed(markup or "")
    s.close()
    return "".join(s.out)


def strip_tags(markup):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", markup or "")).strip()


# --- fetching -----------------------------------------------------------------

def kev_title(vendor, product):
    if product.lower().startswith(vendor.lower()):
        return product
    return f"{vendor} {product}".strip()


class Fetcher:
    def __init__(self, db):
        self.db = db
        self.session = None
        self.nvd_last = 0.0
        self.lock = asyncio.Lock()
        self.last_run = {}
        self.after_refresh = None
        self.radar_token = lambda: None
        self.vulncheck_token = lambda: None
        self.watch_asns = lambda: []
        self.on_routing = None
        self.on_patch_tuesday = None
        self.rounds = 0

    async def get(self, url, *, params=None, as_json=False):
        for attempt in (1, 2):
            async with self.session.get(url, params=params) as r:
                if r.status == 200:
                    return await (r.json(content_type=None) if as_json else r.text())
                if r.status < 500 or attempt == 2:
                    raise RuntimeError(f"HTTP {r.status} from {url.split('?')[0]}")
            await asyncio.sleep(5)

    def due(self, name, every):
        return now() - self.last_run.get(name, 0) >= every

    async def run_forever(self):
        self.session = ClientSession(headers={"User-Agent": UA},
                                     timeout=ClientTimeout(total=60))
        while True:
            try:
                await self.refresh()
            except Exception as e:  # never let the loop die
                log(f"refresh failed: {e!r}")
            await asyncio.sleep(60)

    async def refresh(self, force=False):
        async with self.lock:
            jobs = [("zerowire", 30 * 60, self.zero_wire),
                    ("kev", 3 * 3600, self.kev),
                    ("ubuntu", 60 * 60, self.ubuntu),
                    ("exploits", 24 * 3600, self.exploits),
                    ("msrc", 6 * 3600, self.msrc),
                    ("vulncheck", 6 * 3600, self.vulncheck),
                    ("enrich", 60 * 60, self.enrich),
                    ("radar", 60 * 60, self.radar)]
            for name, every, job in jobs:
                if force or self.due(name, every):
                    self.last_run[name] = now()
                    try:
                        await job()
                    except Exception as e:
                        source_err(self.db, name, e)
                    # Check for alerts after every source, so a slow one
                    # (enrichment can take minutes) never delays them.
                    if self.after_refresh:
                        try:
                            await self.after_refresh()
                        except Exception as e:
                            log(f"after refresh: {e!r}")
            self.rounds += 1

    async def zero_wire(self):
        root = ET.fromstring(await self.get(ZERO_WIRE_RSS))
        with batch(self.db):
            ids = []
            for it in root.iter("item"):
                link = it.findtext("link") or ""
                slug = link.rstrip("/").rsplit("/", 1)[-1]
                guid = it.findtext("guid") or slug
                raw = it.findtext("content:encoded", namespaces=NS) or ""
                cats = it.findall("category")
                category = next((c.text for c in cats if c.text in ("Needs attention", "Reference")), "")
                tags = [c.text for c in cats if c.get("domain")]
                cves = sorted({c.text for c in cats if c.text and CVE_RE.fullmatch(c.text)}
                              | set(CVE_RE.findall(raw)))
                body = sanitize(raw)
                m = re.match(r"<p><strong>(.*?)</strong>.*?Last checked <time datetime=\"([^\"]+)\"", body)
                headline, checked = (m.group(1), m.group(2)) if m else ("", "")
                # Drop the status line from the body; the dashboard shows it itself.
                body = re.sub(r"^<p><strong>.*?</p>", "", body, count=1)
                chronology = re.findall(r"<li><time datetime=\"([^\"]+)\">.*?</time>:\s*(.*?)</li>",
                                        body.split("<h2>What happened</h2>")[0])
                published = it.findtext("pubDate")
                try:
                    published = parsedate_to_datetime(published).date().isoformat()
                except (TypeError, ValueError):
                    pass
                item_id = f"zw:{slug}"
                ids.append(item_id)
                upsert_item(self.db, {
                    "id": item_id, "source": "zerowire", "title": it.findtext("title"), "link": link,
                    "published": published, "updated": checked or published, "category": category,
                    "headline": headline,
                    "summary": re.sub(rf"^{re.escape(headline)}\.\s*", "", strip_tags(it.findtext("description") or "")),
                    "body": body, "cves": cves, "tags": tags, "fingerprint": guid,
                    "extra": {"chronology": [{"date": d, "text": strip_tags(t)} for d, t in chronology][:8],
                              "author": it.findtext("dc:creator", namespaces=NS)},
                })
            retire_missing(self.db, "zerowire", ids)
            source_ok(self.db, "zerowire", len(ids))

    async def kev(self):
        data = await self.get(KEV_JSON, as_json=True)
        vulns = data["vulnerabilities"]
        with batch(self.db):
            self.db.execute("DELETE FROM kev")
            self.db.executemany(
                "INSERT OR REPLACE INTO kev VALUES(?,?,?,?,?,?,?,?,?,?)",
                [(v["cveID"], v.get("vendorProject"), v.get("product"), v.get("vulnerabilityName"),
                  v.get("dateAdded"), v.get("dueDate"), v.get("knownRansomwareCampaignUse"),
                  v.get("shortDescription"), v.get("requiredAction"), json.dumps(v.get("cwes") or []))
                 for v in vulns])
            since = (datetime.now(timezone.utc) - timedelta(days=KEV_WINDOW_DAYS)).date().isoformat()
            ids = []
            for v in vulns:
                if (v.get("dateAdded") or "") < since:
                    continue
                item_id = f"kev:{v['cveID']}"
                ids.append(item_id)
                upsert_item(self.db, {
                    "id": item_id, "source": "kev",
                    "title": kev_title(v.get("vendorProject") or "", v.get("product") or ""),
                    "link": f"https://nvd.nist.gov/vuln/detail/{v['cveID']}",
                    "published": v.get("dateAdded"), "updated": v.get("dateAdded"),
                    "category": "Known exploited", "headline": v.get("vulnerabilityName"),
                    "summary": v.get("shortDescription"), "cves": [v["cveID"]],
                    "tags": [t for t in ([v.get("vendorProject")] + (v.get("cwes") or [])) if t],
                    "fingerprint": f"{v.get('dateAdded')}|{v.get('dueDate')}|{v.get('knownRansomwareCampaignUse')}",
                    "extra": {"due": v.get("dueDate"), "ransomware": v.get("knownRansomwareCampaignUse"),
                              "action": v.get("requiredAction"),
                              "notes": [n.strip() for n in (v.get("notes") or "").split(";")
                                        if n.strip().startswith("https://")][:6]},
                })
            retire_missing(self.db, "kev", ids)
            source_ok(self.db, "kev", len(vulns))

    async def ubuntu(self):
        since = datetime.now(timezone.utc) - timedelta(days=USN_WINDOW_DAYS)
        notices, offset = [], 0
        while offset < 600:  # the API returns at most 20 per page
            page = await self.get(USN_JSON, params={"limit": 20, "offset": offset,
                                                     "order": "newest"}, as_json=True)
            page_items = page.get("notices") or []
            notices += page_items
            if not page_items or (page_items[-1].get("published") or "")[:10] < since.date().isoformat():
                break
            offset += 20
            await asyncio.sleep(1)
        with batch(self.db):
            ids = []
            for n in notices:
                if (n.get("published") or "")[:10] < since.date().isoformat():
                    continue
                releases = [r.get("codename") for r in n.get("releases") or []]
                if UBUNTU_RELEASES and not set(releases) & set(UBUNTU_RELEASES):
                    continue
                cves = n.get("cves_ids") or [c.get("id") for c in n.get("cves") or [] if isinstance(c, dict)]
                cves = [c for c in cves if CVE_RE.fullmatch(c or "")]
                item_id = f"usn:{n['id']}"
                ids.append(item_id)
                upsert_item(self.db, {
                    "id": item_id, "source": "ubuntu", "title": n.get("title"),
                    "link": f"https://ubuntu.com/security/notices/{n['id']}",
                    "published": (n.get("published") or "")[:10], "updated": (n.get("published") or "")[:10],
                    "category": "", "headline": n["id"], "summary": strip_tags(n.get("summary") or ""),
                    "body": sanitize("<p>" + escape(n.get("description") or "").replace("\n\n", "</p><p>") + "</p>"),
                    "cves": sorted(set(cves)), "tags": sorted(set(n.get("release_packages") or {}) & set(releases)),
                    "fingerprint": n.get("published") or n["id"],
                    "extra": {"releases": [r for r in releases if r in UBUNTU_RELEASES] or releases,
                              "packages": sorted({p.get("name") for ps in (n.get("release_packages") or {}).values()
                                                  for p in ps if p.get("name")})[:12],
                              "instructions": strip_tags(n.get("instructions") or "")[:400]},
                })
            retire_missing(self.db, "ubuntu", ids)
            source_ok(self.db, "ubuntu", len(ids))

    async def vulncheck(self):
        token = self.vulncheck_token()
        if not token:
            return
        n = await VC.refresh(self.db, self.session, token)
        with batch(self.db):
            since = (datetime.now(timezone.utc) - timedelta(days=KEV_WINDOW_DAYS)).date().isoformat()
            cisa = {r[0] for r in self.db.execute("SELECT cve FROM kev")}
            ids = []
            for item in VC.items(self.db, since, cisa):
                ids.append(item["id"])
                upsert_item(self.db, item)
            retire_missing(self.db, "vulncheck", ids)
            source_ok(self.db, "vulncheck", n)

    async def msrc(self):
        n = await MS.refresh(self.db, self.session)
        with batch(self.db):
            ids = []
            for item in MS.zero_day_items(self.db):
                ids.append(item["id"])
                upsert_item(self.db, item)
            retire_missing(self.db, "msrc", ids)
            source_ok(self.db, "msrc", n)
        if self.on_patch_tuesday:
            await self.on_patch_tuesday()

    async def exploits(self):
        n = await X.refresh_index(self.db, self.session)
        source_ok(self.db, "exploits", n)

    async def radar(self):
        token = self.radar_token()
        if not token:
            return
        errors = await C.radar_refresh(self.db, self.session, token, self.watch_asns())
        if len(errors) >= len(C.RADAR_QUERIES):
            raise RuntimeError(errors[0])
        for e in errors:
            log(f"[radar] {e}")
        source_ok(self.db, "radar", len(C.RADAR_QUERIES) - len(errors))
        if self.on_routing:
            await self.on_routing()

    async def enrich(self):
        rows = self.db.execute("SELECT source, cves FROM items WHERE active=1").fetchall()
        everything, detailed = set(), set()
        for r in rows:
            cves = json.loads(r["cves"] or "[]")
            everything.update(cves)
            if r["source"] in ("zerowire", "kev"):
                detailed.update(cves)
        everything = sorted(everything)
        marks_all = ",".join("?" * len(everything)) or "''"
        marks_detailed = ",".join("?" * len(detailed)) or "''"
        with batch(self.db):
            self.db.executemany("INSERT OR IGNORE INTO cve(id) VALUES(?)", [(c,) for c in everything])
        # EPSS: cheap, batched, daily.
        stale = [r["id"] for r in self.db.execute(
            f"SELECT id FROM cve WHERE id IN ({marks_all})"
            " AND (epss_at IS NULL OR epss_at < ?)", (*everything, now() - 12 * 3600))]
        for i in range(0, len(stale), 80):
            chunk = stale[i:i + 80]
            data = await self.get(EPSS, params={"cve": ",".join(chunk)}, as_json=True)
            got = {d["cve"]: d for d in data.get("data") or []}
            with batch(self.db):
                self.db.executemany("UPDATE cve SET epss=?, epss_pct=?, epss_at=? WHERE id=?",
                                    [(float(got[c]["epss"]) if c in got else None,
                                      float(got[c]["percentile"]) if c in got else None, now(), c) for c in chunk])
        source_ok(self.db, "epss", len(everything))
        # Exploit-chance history and GitHub proof-of-concept repos, for the
        # CVEs in briefings and CISA items (not every CVE in an Ubuntu notice).
        try:
            await X.refresh_series(self.db, self.session, sorted(detailed))
            source_ok(self.db, "epss-history", len(detailed))
        except Exception as e:
            source_err(self.db, "epss-history", e)
        n = await X.refresh_poc(self.db, self.session, sorted(detailed), log)
        source_ok(self.db, "poc", n)
        # Ubuntu's priority for every CVE in a notice, via OSV (reliable, fast).
        marks = ",".join("?" * len(everything)) or "''"
        todo = [r["id"] for r in self.db.execute(
            f"SELECT id FROM cve WHERE id IN ({marks}) AND (ubuntu_at IS NULL OR ubuntu_at < ?)"
            " ORDER BY ubuntu_at IS NOT NULL, id DESC LIMIT 2500",
            (*everything, now() - 7 * 86400))]
        sem = asyncio.Semaphore(8)

        async def one(c):
            async with sem:
                return c, await self.osv_priority(c)
        results = await asyncio.gather(*(one(c) for c in todo if c not in detailed))
        with batch(self.db):
            self.db.executemany("UPDATE cve SET ubuntu_priority=?, ubuntu_at=? WHERE id=?",
                                [(prio, now(), c) for c, prio in results if prio is not False])
        if todo:
            source_ok(self.db, "osv", len(todo))
        # NVD + Ubuntu tracker: per CVE, only for briefings and KEV items. NVD
        # allows 5 requests / 30 s without a key, so space them out.
        todo = [r["id"] for r in self.db.execute(
            f"SELECT id FROM cve WHERE id IN ({marks_detailed})"
            " AND (nvd_at IS NULL OR nvd_at < ?) ORDER BY nvd_at IS NOT NULL, id DESC LIMIT 40",
            (*sorted(detailed), now() - 24 * 3600))]
        for c in todo:
            await self.nvd_one(c)
        todo = [r["id"] for r in self.db.execute(
            f"SELECT id FROM cve WHERE id IN ({marks_detailed})"
            " AND (ubuntu_at IS NULL OR ubuntu_at < ?) LIMIT 60",
            (*sorted(detailed), now() - 6 * 3600))]
        failures = 0
        for c in todo:
            failures = 0 if await self.ubuntu_one(c) else failures + 1
            if failures >= 3:
                log("[ubuntu-cve] tracker is failing; trying again next round")
                break
            await asyncio.sleep(1)

    async def nvd_one(self, cve_id):
        wait = self.nvd_last + 7 - now()
        if wait > 0:
            await asyncio.sleep(wait)
        self.nvd_last = now()
        try:
            data = await self.get(NVD, params={"cveId": cve_id}, as_json=True)
        except Exception as e:
            source_err(self.db, "nvd", e)
            return
        score = severity = vector = None
        for v in data.get("vulnerabilities") or []:
            metrics = v["cve"].get("metrics") or {}
            for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
                entries = sorted(metrics.get(key) or [], key=lambda m: m.get("type") != "Primary")
                if entries:
                    d = entries[0]["cvssData"]
                    score, vector = d.get("baseScore"), d.get("vectorString")
                    severity = d.get("baseSeverity") or entries[0].get("baseSeverity")
                    break
        self.db.execute("UPDATE cve SET cvss=?, severity=?, vector=?, nvd_at=? WHERE id=?",
                        (score, severity, vector, now(), cve_id))
        source_ok(self.db, "nvd", 1)

    async def osv_priority(self, cve_id):
        try:
            async with self.session.get(OSV.format(cve_id)) as r:
                if r.status == 404:
                    prio = "not-in-ubuntu"
                elif r.status != 200:
                    return False
                else:
                    d = await r.json(content_type=None)
                    prio = next((s["score"] for s in d.get("severity") or [] if s.get("type") == "Ubuntu"), None)
        except Exception as e:
            log(f"[osv] {cve_id}: {e!r}")
            return False
        return prio

    async def ubuntu_one(self, cve_id):
        """True when the tracker answered (found or not), False when it failed."""
        try:
            async with self.session.get(UBUNTU_CVE.format(cve_id), timeout=ClientTimeout(total=20)) as r:
                if r.status == 404:
                    self.db.execute("UPDATE cve SET ubuntu_priority='not-in-ubuntu', ubuntu_status='[]',"
                                    " ubuntu_at=? WHERE id=?", (now(), cve_id))
                    return True
                if r.status != 200:
                    raise RuntimeError(f"HTTP {r.status} for {cve_id}")
                d = await r.json(content_type=None)
        except Exception as e:
            source_err(self.db, "ubuntu-cve", e)
            return False
        status = []
        for p in d.get("packages") or []:
            per = {s["release_codename"]: s["status"] for s in p.get("statuses") or []
                   if s.get("release_codename") in UBUNTU_RELEASES}
            if any(v not in ("DNE", "not-affected") for v in per.values()):
                status.append({"package": p["name"], "releases": per})
        self.db.execute("UPDATE cve SET ubuntu_priority=?, ubuntu_status=?, ubuntu_at=? WHERE id=?",
                        (d.get("priority"), json.dumps(status[:6]), now(), cve_id))
        source_ok(self.db, "ubuntu-cve", 1)
        return True


# --- auth ---------------------------------------------------------------------

def read_admin_hash():
    if DEV:
        return os.environ.get("HU_DEV_ADMIN_HASH", "")
    try:
        return (CREDS / "admin-hash").read_text().strip()
    except OSError:
        return ""


def session_user(request):
    """The signed-in user (dict with username, name, role) or None."""
    token = request.cookies.get(COOKIE)
    if not token:
        return None
    row = request.app["db"].execute(
        "SELECT u.username, u.name, u.role FROM sessions s JOIN users u ON u.username = s.username"
        " WHERE s.token_hash=? AND s.expires>? AND u.disabled=0",
        (hashlib.sha256(token.encode()).hexdigest(), now())).fetchone()
    return dict(row) if row else None


def need_user(request):
    user = session_user(request)
    if not user:
        raise web.HTTPUnauthorized(text="Sign in first")
    return user


def need_admin(request):
    user = need_user(request)
    if user["role"] != "admin":
        raise web.HTTPForbidden(text="Only admins can do that")
    return user


# --- web ------------------------------------------------------------------------

SECURITY_HEADERS = {
    "Content-Security-Policy": ("default-src 'self'; img-src 'self' data:; style-src 'self'; "
                                "script-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
                                "form-action 'self'"),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
    "X-Frame-Options": "DENY",
}


@web.middleware
async def guard(request, handler):
    if request.method == "POST":
        site = request.headers.get("Sec-Fetch-Site")
        origin = request.headers.get("Origin")
        ok = site in ("same-origin", "none") if site is not None else \
            origin is not None and origin.split("://", 1)[-1] == request.host
        if not ok:
            raise web.HTTPForbidden(text="Bad origin")
    resp = await handler(request)
    for k, v in SECURITY_HEADERS.items():
        resp.headers.setdefault(k, v)
    if request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    elif request.path == "/" or request.path.startswith("/static/"):
        # Re-check with the server every time (cheap: ETag), so a deploy never
        # leaves a browser running an old script against a new page.
        resp.headers["Cache-Control"] = "no-cache"
    return resp


RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "negligible": 0}


def item_row(r, cves, triage):
    category = r["category"]
    if r["source"] == "ubuntu":
        levels = [cves.get(c, {}).get("ubuntuPriority") for c in json.loads(r["cves"] or "[]")]
        category = max(levels, key=lambda p: RANK.get(p, -1), default="") if levels else ""
        category = category if category in RANK else ""
    return {
        "id": r["id"], "source": r["source"], "title": r["title"], "link": r["link"],
        "published": r["published"], "updated": r["updated"], "category": category,
        "headline": r["headline"], "summary": r["summary"], "body": r["body"],
        "cves": [cves.get(c, {"id": c}) for c in json.loads(r["cves"] or "[]")],
        "tags": json.loads(r["tags"] or "[]"), "extra": json.loads(r["extra"] or "{}"),
        "firstSeen": r["first_seen"], "changedAt": r["changed_at"],
        "triage": triage.get(r["id"]),
    }


def build_state(db):
    kev = {r["cve"]: dict(r) for r in db.execute("SELECT cve, added, due, ransomware FROM kev")}
    cves = {}
    for r in db.execute("SELECT * FROM cve"):
        cves[r["id"]] = {
            "id": r["id"], "epss": r["epss"], "epssPct": r["epss_pct"], "cvss": r["cvss"],
            "severity": r["severity"], "vector": r["vector"],
            "ubuntuPriority": r["ubuntu_priority"],
            "ubuntu": json.loads(r["ubuntu_status"]) if r["ubuntu_status"] else None,
            "kev": kev.get(r["id"]),
            "epssSeries": json.loads(r["epss_series"]) if r["epss_series"] else None,
            "poc": json.loads(r["poc"]) if r["poc"] is not None else None,
        }
    for cve_id, info in MS.cve_info(db, cves).items():
        cves[cve_id]["msrc"] = info
    for cve_id, info in VC.cve_info(db, cves).items():
        cves[cve_id]["vulncheck"] = info
    for cve_id, ex in X.exploit_rows(db, cves).items():
        cves[cve_id]["edb"] = ex["edb"][:5]
        cves[cve_id]["msf"] = ex["msf"][:5]
    triage = {r["item_id"]: {"state": r["state"], "note": r["note"], "by": r["by"], "at": r["at"]}
              for r in db.execute("SELECT * FROM triage")}
    items = [item_row(r, cves, triage) for r in
             db.execute("SELECT * FROM items WHERE active=1 ORDER BY updated DESC, published DESC")]
    sources = {r["name"]: dict(r) for r in db.execute("SELECT * FROM sources")}
    return {"items": items, "sources": sources, "kevTotal": len(kev),
            "vulns": V.build(items, UBUNTU_RELEASES)}


async def api_state(request):
    state = build_state(request.app["db"])
    user = session_user(request)
    return compressed(request, {
        "version": VERSION, "now": now(), "user": user,
        "canSignIn": request.app["users"].count() > 0, "releases": UBUNTU_RELEASES,
        "webhooksAvailable": request.app["hooks"].box is not None,
        **state,
    })


def compressed(request, payload):
    # zlib_executor_size: compress big bodies in a worker thread, not on the event loop
    resp = web.Response(text=json.dumps(payload), content_type="application/json", zlib_executor_size=32768)
    if "gzip" in request.headers.get("Accept-Encoding", ""):
        resp.enable_compression()
    return resp


async def announce_patch_tuesday(app):
    """Tell webhooks once when a new month's Microsoft updates appear."""
    db = app["db"]
    latest = next(iter(MS.summary(db)), None)
    if not latest:
        return
    row = db.execute("SELECT value FROM meta WHERE key='msrc_announced'").fetchone()
    db.execute("INSERT OR REPLACE INTO meta VALUES('msrc_announced', ?)", (latest["release"],))
    if row is None or row[0] == latest["release"]:
        return  # first run records what's already out; same month: nothing new
    log(f"alerts: patch tuesday {latest['release']}")
    await app["hooks"].send_note("patch", f"Microsoft {latest['label']} security updates", (
        f"{latest['total']} fixes: {latest['critical']} critical, {latest['exploited']} already exploited, "
        f"{latest['disclosed']} publicly disclosed, {latest['likely']} rated exploitation more likely."),
        [("Exploited (zero-days)", str(latest["exploited"])), ("Critical", str(latest["critical"])),
         ("Publicly disclosed", str(latest["disclosed"])), ("Patch first", ", ".join(f["cve"] for f in latest["first"][:5]) or "–")],
        f"{app['hooks'].base_url}/")


async def notify_changes(app):
    hooks = app["hooks"]
    # On a fresh install, the whole first round only records what exists, so
    # sources arriving one after another don't look like a flood of news.
    record_only = app["fresh"] and app["fetcher"].rounds == 0
    events = hooks.detect(build_state(app["db"])["vulns"], record_only=record_only)
    if events:
        log("alerts: " + ", ".join(f"{e}:{v['id']}" for e, v, _ in events))
    await hooks.send(events)


def background(app, coro):
    task = asyncio.get_running_loop().create_task(coro)
    app["tasks"].add(task)
    task.add_done_callback(app["tasks"].discard)


async def api_webhooks(request):
    need_admin(request)
    hooks = request.app["hooks"]
    return web.json_response({"available": hooks.box is not None, "kinds": W.KINDS, "events": W.EVENTS,
                              "defaultEvents": W.DEFAULT_EVENTS, "webhooks": hooks.list()})


async def api_webhook_save(request):
    user = need_admin(request)
    try:
        wid = request.app["hooks"].save(await request.json(), user["name"])
    except ValueError as e:
        return web.json_response({"error": str(e)}, status=400)
    return web.json_response({"id": wid})


async def api_webhook_delete(request):
    user = need_admin(request)
    request.app["hooks"].delete(str((await request.json()).get("id") or ""), user["name"])
    return web.json_response({})


async def api_webhook_test(request):
    need_admin(request)
    try:
        ok, detail = await request.app["hooks"].test(str((await request.json()).get("id") or ""))
    except ValueError as e:
        return web.json_response({"error": str(e)}, status=400)
    return web.json_response({"ok": ok, "detail": detail})


async def api_charts(request):
    db = request.app["db"]
    state = build_state(db)
    out = C.build(db, state["vulns"], state["items"])
    radar, at = C.radar_data(db)
    src = db.execute("SELECT * FROM sources WHERE name='radar'").fetchone()
    out["patchTuesday"] = MS.summary(db)
    out["vulncheck"] = VC.stats(db, datetime.now(timezone.utc).date().isoformat()) if secret_setting(request.app, "vulncheck_token") else None
    out["radar"] = {"configured": bool(radar_token(request.app)), "data": radar, "at": at,
                    "watch": watch_asns(request.app), "watched": C.watched_events(radar),
                    "error": src["error"] if src and src["error"] and (not src["ok_at"] or src["err_at"] > src["ok_at"]) else None}
    return compressed(request, out)


def watch_asns(app):
    row = app["db"].execute("SELECT value FROM meta WHERE key='watch_asns'").fetchone()
    return json.loads(row[0]) if row else []


async def api_settings_watch(request):
    admin = need_admin(request)
    raw = str((await request.json()).get("asns") or "")
    asns = []
    for part in raw.replace(",", " ").split():
        part = part.upper().removeprefix("AS")
        if not part.isdigit() or not 0 < int(part) < 4294967296:
            return web.json_response({"error": f"“{part}” isn't an AS number (e.g. 13335 or AS13335)"}, status=400)
        asns.append(int(part))
    asns = sorted(set(asns))[:5]
    db = request.app["db"]
    db.execute("INSERT OR REPLACE INTO meta VALUES('watch_asns', ?)", (json.dumps(asns),))
    db.execute("DELETE FROM meta WHERE key='routing_seen'")  # next check records history instead of alerting on it
    db.execute("DELETE FROM radar WHERE key LIKE 'watch%'")
    log(f"watched networks set to {asns} by {admin['username']}")
    fetcher = request.app["fetcher"]

    async def refetch():
        async with fetcher.lock:
            try:
                await fetcher.radar()
            except Exception as e:
                source_err(db, "radar", e)
    if radar_token(request.app):
        background(request.app, refetch())
    return web.json_response({"asns": asns})


async def announce_routing(app):
    """Alert webhooks about new hijacks/leaks involving watched networks."""
    db = app["db"]
    radar, _ = C.radar_data(db)
    events = C.watched_events(radar)
    row = db.execute("SELECT value FROM meta WHERE key='routing_seen'").fetchone()
    seen = set(json.loads(row[0])) if row else None
    db.execute("INSERT OR REPLACE INTO meta VALUES('routing_seen', ?)",
               (json.dumps(sorted({e["id"] for e in events} | (seen or set()))[-1000:]),))
    if seen is None:
        return  # first look after (re)setting the list: record, don't alert on history
    for e in [e for e in events if e["id"] not in seen][:5]:
        if e["kind"] == "hijack":
            title = f"Possible route hijack involving AS{e['watchedAsn']}"
            body = (f"{(e['hijacker'] or {}).get('name') or 'AS' + str(e['hijacker']['asn'])} (AS{e['hijacker']['asn']}) announced "
                    f"{e['prefixCount']} prefix(es) belonging to " + ", ".join(f"{v.get('name') or ''} (AS{v['asn']})" for v in e["victims"]) +
                    f". Cloudflare confidence {e['confidence']}." + (" Still ongoing." if e["ongoing"] else ""))
        else:
            title = f"Route leak involving AS{e['watchedAsn']}"
            body = (f"{(e['leaker'] or {}).get('name') or ''} (AS{e['leaker']['asn']}) leaked {e['routes']} routes "
                    f"along " + " → ".join(f"AS{n['asn']}" for n in e["path"]) + "." + (" Still ongoing." if e["ongoing"] else ""))
        log(f"alerts: routing {e['id']}")
        await app["hooks"].send_note("routing", title, body,
                                     [("Started", (e.get("start") or "")[:16].replace("T", " ") + " UTC"),
                                      ("Watched network", f"AS{e['watchedAsn']}")],
                                     f"{app['hooks'].base_url}/")


def radar_token(app):
    return secret_setting(app, "radar_token")


def secret_setting(app, key):
    hooks = app["hooks"]
    row = app["db"].execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    if not row or not hooks.box:
        return ""
    try:
        return hooks.box.open(bytes.fromhex(row[0]))
    except Exception:
        return ""


async def api_settings(request):
    need_admin(request)
    db = request.app["db"]
    src = db.execute("SELECT * FROM sources WHERE name='radar'").fetchone()
    vsrc = db.execute("SELECT * FROM sources WHERE name='vulncheck'").fetchone()
    return web.json_response({"watchAsns": watch_asns(request.app),
                              "radar": {"configured": bool(radar_token(request.app)),
                                        "okAt": src["ok_at"] if src else None,
                                        "error": src["error"] if src else None},
                              "vulncheck": {"configured": bool(secret_setting(request.app, "vulncheck_token")),
                                            "okAt": vsrc["ok_at"] if vsrc else None,
                                            "error": vsrc["error"] if vsrc else None,
                                            "count": vsrc["count"] if vsrc else None},
                              "canStoreSecrets": request.app["hooks"].box is not None})


async def api_settings_radar(request):
    admin = need_admin(request)
    app = request.app
    body = await request.json()
    if body.get("remove"):
        app["db"].execute("DELETE FROM meta WHERE key='radar_token'")
        app["db"].execute("DELETE FROM radar")
        app["db"].execute("DELETE FROM sources WHERE name='radar'")
        log(f"radar token removed by {admin['username']}")
        return web.json_response({})
    token = str(body.get("token") or "").strip()
    if not token or len(token) > 200 or not app["hooks"].box:
        return web.json_response({"error": "Paste the API token"}, status=400)
    fetcher = app["fetcher"]
    if fetcher.session is None:
        fetcher.session = ClientSession(headers={"User-Agent": UA}, timeout=ClientTimeout(total=60))
    try:
        await C.radar_get(fetcher.session, token, *C.RADAR_TEST)
    except Exception as e:
        return web.json_response({"error": f"Cloudflare didn't accept the token: {e}"}, status=400)
    app["db"].execute("INSERT OR REPLACE INTO meta VALUES('radar_token', ?)", (app["hooks"].box.seal(token).hex(),))
    log(f"radar token set by {admin['username']}")

    async def first_fetch():
        async with fetcher.lock:
            try:
                await fetcher.radar()
            except Exception as e:
                source_err(app["db"], "radar", e)
    background(app, first_fetch())
    return web.json_response({"ok": True})


async def api_settings_vulncheck(request):
    admin = need_admin(request)
    app = request.app
    body = await request.json()
    db = app["db"]
    if body.get("remove"):
        db.execute("DELETE FROM meta WHERE key='vulncheck_token'")
        db.execute("DELETE FROM vckev")
        retire_missing(db, "vulncheck", [])
        db.execute("DELETE FROM sources WHERE name='vulncheck'")
        log(f"vulncheck token removed by {admin['username']}")
        return web.json_response({})
    token = str(body.get("token") or "").strip()
    if not token or len(token) > 300 or not app["hooks"].box:
        return web.json_response({"error": "Paste the API token"}, status=400)
    fetcher = app["fetcher"]
    if fetcher.session is None:
        fetcher.session = ClientSession(headers={"User-Agent": UA}, timeout=ClientTimeout(total=60))
    try:
        await VC.check_token(fetcher.session, token)
    except Exception as e:
        return web.json_response({"error": f"VulnCheck didn't accept the token: {e}"}, status=400)
    db.execute("INSERT OR REPLACE INTO meta VALUES('vulncheck_token', ?)", (app["hooks"].box.seal(token).hex(),))
    log(f"vulncheck token set by {admin['username']}")

    async def first_fetch():
        # Wait for any running refresh: the big downloads must not overlap
        # (together they can exceed the service's memory limit).
        async with fetcher.lock:
            try:
                await fetcher.vulncheck()
                await notify_changes(app)
            except Exception as e:
                source_err(db, "vulncheck", e)
    background(app, first_fetch())
    return web.json_response({"ok": True})


async def api_history(request):
    rows = request.app["db"].execute(
        "SELECT * FROM triage_log WHERE item_id=? ORDER BY at DESC LIMIT 30",
        (request.match_info["id"],)).fetchall()
    return web.json_response([dict(r) for r in rows])


async def api_login(request):
    body = await request.json()
    attempts = request.app["attempts"]
    ip = request.remote or "?"
    recent = [t for t in attempts.get(ip, []) if t > now() - 600]
    if len(recent) >= 8:
        raise web.HTTPTooManyRequests(text="Too many attempts; try again in 10 minutes")
    await asyncio.sleep(0.4)
    user = request.app["users"].authenticate(str(body.get("username") or ""), str(body.get("password") or ""))
    if not user:
        attempts[ip] = recent + [now()]
        log(f"failed sign-in for {str(body.get('username') or '')[:32]!r} from {ip}")
        return web.json_response({"error": "Wrong username or password"}, status=401)
    attempts.pop(ip, None)
    token = secrets.token_urlsafe(32)
    request.app["db"].execute("INSERT INTO sessions VALUES(?,?,?)",
                              (hashlib.sha256(token.encode()).hexdigest(), user["username"],
                               now() + SESSION_DAYS * 86400))
    log(f"sign-in: {user['username']}")
    resp = web.json_response({"user": {k: user[k] for k in ("username", "name", "role")}})
    resp.set_cookie(COOKIE, token, max_age=SESSION_DAYS * 86400, httponly=True,
                    secure=not DEV, samesite="Strict", path="/")
    return resp


def user_error(e):
    return web.json_response({"error": str(e)}, status=400)


async def api_me_password(request):
    user = need_user(request)
    body = await request.json()
    try:
        request.app["users"].change_own_password(user["username"], str(body.get("current") or ""),
                                                 str(body.get("new") or ""))
    except U.UserError as e:
        return user_error(e)
    log(f"password changed: {user['username']}")
    return web.json_response({})


async def api_users(request):
    need_admin(request)
    return web.json_response({"users": request.app["users"].list(), "minPassword": U.MIN_PASSWORD})


async def api_user_create(request):
    admin = need_admin(request)
    try:
        username, password = request.app["users"].create(await request.json(), admin["username"])
    except U.UserError as e:
        return user_error(e)
    log(f"user created: {username} by {admin['username']}")
    return web.json_response({"username": username, "password": password})


async def api_user_update(request):
    admin = need_admin(request)
    body = await request.json()
    try:
        request.app["users"].update(str(body.get("username") or ""), body, admin["username"])
    except U.UserError as e:
        return user_error(e)
    log(f"user updated: {body.get('username')} by {admin['username']}")
    return web.json_response({})


async def api_user_reset(request):
    admin = need_admin(request)
    username = str((await request.json()).get("username") or "")
    try:
        password = request.app["users"].reset_password(username)
    except U.UserError as e:
        return user_error(e)
    log(f"password reset: {username} by {admin['username']}")
    return web.json_response({"password": password})


async def api_user_delete(request):
    admin = need_admin(request)
    username = str((await request.json()).get("username") or "")
    try:
        request.app["users"].delete(username, admin["username"])
    except U.UserError as e:
        return user_error(e)
    log(f"user deleted: {username} by {admin['username']}")
    return web.json_response({})


async def api_logout(request):
    token = request.cookies.get(COOKIE)
    if token:
        request.app["db"].execute("DELETE FROM sessions WHERE token_hash=?",
                                  (hashlib.sha256(token.encode()).hexdigest(),))
    resp = web.json_response({})
    resp.del_cookie(COOKIE, path="/")
    return resp


async def api_triage(request):
    user = need_user(request)["name"]
    body = await request.json()
    item_id = str(body.get("id") or "")
    state = body.get("state")
    note = str(body.get("note") or "").strip()[:1000]
    db = request.app["db"]
    if state not in STATES or not db.execute("SELECT 1 FROM items WHERE id=?", (item_id,)).fetchone():
        raise web.HTTPBadRequest(text="Bad item or state")
    t = now()
    db.execute("INSERT OR REPLACE INTO triage VALUES(?,?,?,?,?)", (item_id, state, note, user, t))
    db.execute("INSERT INTO triage_log VALUES(?,?,?,?,?)", (item_id, state, note, user, t))
    log(f"triage {item_id} -> {state} by {user}")
    v = next((x for x in build_state(db)["vulns"] if x["id"] == item_id), None)
    if v:
        background(request.app, request.app["hooks"].send(
            [("status", v, {"by": user, "state": state, "note": note})]))
    return web.json_response({"state": state, "note": note, "by": user, "at": t})


async def api_refresh(request):
    need_user(request)
    fetcher = request.app["fetcher"]
    if fetcher.lock.locked():
        return web.json_response({"busy": True})
    background(request.app, fetcher.refresh(force=True))
    return web.json_response({"ok": True})


async def index(request):
    # Versioned asset URLs, so browsers fetch new ones after every deploy.
    page = (HERE / "static" / "index.html").read_text()
    for asset in ("app.js", "charts.js", "style.css", "favicon.svg"):
        page = page.replace(f"/static/{asset}", f"/static/{asset}?v={ASSET_VERSION}")
    return web.Response(text=page, content_type="text/html")


async def ca_cert(request):
    return web.FileResponse(CA_CERT, headers={
        "Content-Type": "application/x-x509-ca-cert",
        "Content-Disposition": 'attachment; filename="heads-up-ca.crt"'})


def read_settings_key():
    if DEV:
        f = STATE / "dev-settings-key"
        if not f.exists():
            f.write_text(secrets.token_hex(32))
        return f.read_text().strip()
    try:
        return (CREDS / "settings-key").read_text().strip()
    except OSError:
        log("no settings-key credential: webhooks disabled")
        return ""


def make_app(db, fetcher):
    app = web.Application(middlewares=[guard], client_max_size=64 * 1024)
    app["db"], app["fetcher"], app["attempts"], app["tasks"] = db, fetcher, {}, set()
    app["users"] = U.Users(db)
    app["users"].sync_bootstrap_admin(read_admin_hash(), log)
    app["hooks"] = W.Webhooks(db, read_settings_key(), PUBLIC_URL)
    app["fresh"] = app["hooks"].is_empty()
    fetcher.after_refresh = lambda: notify_changes(app)
    fetcher.radar_token = lambda: radar_token(app)
    fetcher.vulncheck_token = lambda: secret_setting(app, "vulncheck_token")
    fetcher.watch_asns = lambda: watch_asns(app)
    fetcher.on_routing = lambda: announce_routing(app)
    fetcher.on_patch_tuesday = lambda: announce_patch_tuesday(app)
    app.router.add_get("/api/charts", api_charts)
    app.router.add_get("/api/settings", api_settings)
    app.router.add_post("/api/settings/radar", api_settings_radar)
    app.router.add_post("/api/settings/vulncheck", api_settings_vulncheck)
    app.router.add_post("/api/settings/watch", api_settings_watch)
    app.router.add_post("/api/me/password", api_me_password)
    app.router.add_get("/api/users", api_users)
    app.router.add_post("/api/users/create", api_user_create)
    app.router.add_post("/api/users/update", api_user_update)
    app.router.add_post("/api/users/reset", api_user_reset)
    app.router.add_post("/api/users/delete", api_user_delete)
    app.router.add_get("/api/webhooks", api_webhooks)
    app.router.add_post("/api/webhooks/save", api_webhook_save)
    app.router.add_post("/api/webhooks/delete", api_webhook_delete)
    app.router.add_post("/api/webhooks/test", api_webhook_test)
    app.router.add_get("/", index)
    app.router.add_get("/api/state", api_state)
    app.router.add_get("/api/history/{id}", api_history)
    app.router.add_post("/api/login", api_login)
    app.router.add_post("/api/logout", api_logout)
    app.router.add_post("/api/triage", api_triage)
    app.router.add_post("/api/refresh", api_refresh)
    app.router.add_get("/ca.crt", ca_cert)
    app.router.add_static("/static/", HERE / "static")
    return app


def redirect_app():
    async def to_https(request):
        if request.path == "/ca.crt":
            return await ca_cert(request)
        host = request.host.split(":")[0]
        raise web.HTTPMovedPermanently(f"https://{host}:{HTTPS_PORT}{request.path_qs}")
    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", to_https)
    return app


async def main():
    db = db_open()
    db.execute("DELETE FROM sessions WHERE expires<?", (now(),))
    fetcher = Fetcher(db)
    runners = []
    app = web.AppRunner(make_app(db, fetcher), access_log=None)
    await app.setup()
    runners.append(app)
    if DEV:
        await web.TCPSite(app, BIND, HTTP_PORT).start()
        log(f"Heads Up {VERSION} (dev) on http://{BIND}:{HTTP_PORT}")
    else:
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(TLS_CERT, CREDS / "tls-key")
        await web.TCPSite(app, BIND, HTTPS_PORT, ssl_context=ctx).start()
        plain = web.AppRunner(redirect_app(), access_log=None)
        await plain.setup()
        runners.append(plain)
        await web.TCPSite(plain, BIND, HTTP_PORT).start()
        log(f"Heads Up {VERSION} on https://{BIND}:{HTTPS_PORT} (+ http :{HTTP_PORT})")
    if os.environ.get("HU_NO_FETCH") != "1":
        asyncio.get_running_loop().create_task(fetcher.run_forever())
    await asyncio.Event().wait()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
