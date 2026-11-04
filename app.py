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
import hmac
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

import vulns as V
import webhooks as W

VERSION = "0.3.0"
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
  due TEXT, ransomware TEXT, description TEXT, action TEXT);
CREATE TABLE IF NOT EXISTS triage (
  item_id TEXT PRIMARY KEY, state TEXT, note TEXT, by TEXT, at REAL);
CREATE TABLE IF NOT EXISTS triage_log (
  item_id TEXT, state TEXT, note TEXT, by TEXT, at REAL);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY, name TEXT, expires REAL);
CREATE TABLE IF NOT EXISTS sources (
  name TEXT PRIMARY KEY, ok_at REAL, err_at REAL, error TEXT, count INTEGER);
"""


def db_open():
    STATE.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(STATE / "heads-up.db", isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript(SCHEMA)
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
                    ("enrich", 60 * 60, self.enrich)]
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
        self.db.execute("BEGIN")
        self.db.execute("DELETE FROM kev")
        self.db.executemany(
            "INSERT OR REPLACE INTO kev VALUES(?,?,?,?,?,?,?,?,?)",
            [(v["cveID"], v.get("vendorProject"), v.get("product"), v.get("vulnerabilityName"),
              v.get("dateAdded"), v.get("dueDate"), v.get("knownRansomwareCampaignUse"),
              v.get("shortDescription"), v.get("requiredAction")) for v in vulns])
        self.db.execute("COMMIT")
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
            batch = page.get("notices") or []
            notices += batch
            if not batch or (batch[-1].get("published") or "")[:10] < since.date().isoformat():
                break
            offset += 20
            await asyncio.sleep(1)
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

    async def enrich(self):
        rows = self.db.execute("SELECT source, cves FROM items WHERE active=1").fetchall()
        everything, detailed = set(), set()
        for r in rows:
            cves = json.loads(r["cves"] or "[]")
            everything.update(cves)
            if r["source"] in ("zerowire", "kev"):
                detailed.update(cves)
        everything = sorted(everything)
        for c in everything:
            self.db.execute("INSERT OR IGNORE INTO cve(id) VALUES(?)", (c,))
        # EPSS: cheap, batched, daily.
        stale = [r["id"] for r in self.db.execute(
            f"SELECT id FROM cve WHERE id IN ({','.join('?' * len(everything)) or "''"})"
            " AND (epss_at IS NULL OR epss_at < ?)", (*everything, now() - 12 * 3600))]
        for i in range(0, len(stale), 80):
            chunk = stale[i:i + 80]
            data = await self.get(EPSS, params={"cve": ",".join(chunk)}, as_json=True)
            got = {d["cve"]: d for d in data.get("data") or []}
            for c in chunk:
                d = got.get(c)
                self.db.execute("UPDATE cve SET epss=?, epss_pct=?, epss_at=? WHERE id=?",
                                (float(d["epss"]) if d else None, float(d["percentile"]) if d else None, now(), c))
        source_ok(self.db, "epss", len(everything))
        # Ubuntu's priority for every CVE in a notice, via OSV (reliable, fast).
        marks = ",".join("?" * len(everything)) or "''"
        todo = [r["id"] for r in self.db.execute(
            f"SELECT id FROM cve WHERE id IN ({marks}) AND (ubuntu_at IS NULL OR ubuntu_at < ?)"
            " ORDER BY ubuntu_at IS NOT NULL, id DESC LIMIT 2500",
            (*everything, now() - 7 * 86400))]
        sem = asyncio.Semaphore(8)

        async def one(c):
            async with sem:
                await self.osv_priority(c)
        await asyncio.gather(*(one(c) for c in todo if c not in detailed))
        if todo:
            source_ok(self.db, "osv", len(todo))
        # NVD + Ubuntu tracker: per CVE, only for briefings and KEV items. NVD
        # allows 5 requests / 30 s without a key, so space them out.
        todo = [r["id"] for r in self.db.execute(
            f"SELECT id FROM cve WHERE id IN ({','.join('?' * len(detailed)) or "''"})"
            " AND (nvd_at IS NULL OR nvd_at < ?) ORDER BY nvd_at IS NOT NULL, id DESC LIMIT 40",
            (*sorted(detailed), now() - 24 * 3600))]
        for c in todo:
            await self.nvd_one(c)
        todo = [r["id"] for r in self.db.execute(
            f"SELECT id FROM cve WHERE id IN ({','.join('?' * len(detailed)) or "''"})"
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
                    return
                else:
                    d = await r.json(content_type=None)
                    prio = next((s["score"] for s in d.get("severity") or [] if s.get("type") == "Ubuntu"), None)
        except Exception as e:
            log(f"[osv] {cve_id}: {e!r}")
            return
        self.db.execute("UPDATE cve SET ubuntu_priority=?, ubuntu_at=? WHERE id=?", (prio, now(), cve_id))

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

def read_login_hash():
    if DEV:
        return os.environ.get("HU_DEV_LOGIN_HASH", "")
    try:
        return (CREDS / "login-hash").read_text().strip()
    except OSError:
        return ""


def check_password(password, stored):
    try:
        scheme, n, r, p, salt, expected = stored.split(":")
        if scheme != "scrypt":
            return False
        actual = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt),
                                n=int(n), r=int(r), p=int(p), dklen=len(expected) // 2)
    except ValueError:
        return False
    return hmac.compare_digest(actual.hex(), expected)


def session_name(request):
    token = request.cookies.get(COOKIE)
    if not token:
        return None
    row = request.app["db"].execute(
        "SELECT name FROM sessions WHERE token_hash=? AND expires>?",
        (hashlib.sha256(token.encode()).hexdigest(), now())).fetchone()
    return row["name"] if row else None


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
        }
    triage = {r["item_id"]: {"state": r["state"], "note": r["note"], "by": r["by"], "at": r["at"]}
              for r in db.execute("SELECT * FROM triage")}
    items = [item_row(r, cves, triage) for r in
             db.execute("SELECT * FROM items WHERE active=1 ORDER BY updated DESC, published DESC")]
    sources = {r["name"]: dict(r) for r in db.execute("SELECT * FROM sources")}
    return {"items": items, "sources": sources, "kevTotal": len(kev),
            "vulns": V.build(items, UBUNTU_RELEASES)}


async def api_state(request):
    state = build_state(request.app["db"])
    user = session_name(request)
    return web.json_response({
        "version": VERSION, "now": now(), "user": user,
        "canSignIn": bool(read_login_hash()), "releases": UBUNTU_RELEASES,
        "webhooksAvailable": request.app["hooks"].box is not None,
        **state,
    })


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


def need_user(request):
    user = session_name(request)
    if not user:
        raise web.HTTPUnauthorized(text="Sign in first")
    return user


async def api_webhooks(request):
    need_user(request)
    hooks = request.app["hooks"]
    return web.json_response({"available": hooks.box is not None, "kinds": W.KINDS, "events": W.EVENTS,
                              "defaultEvents": W.DEFAULT_EVENTS, "webhooks": hooks.list()})


async def api_webhook_save(request):
    user = need_user(request)
    try:
        wid = request.app["hooks"].save(await request.json(), user)
    except ValueError as e:
        return web.json_response({"error": str(e)}, status=400)
    return web.json_response({"id": wid})


async def api_webhook_delete(request):
    user = need_user(request)
    request.app["hooks"].delete(str((await request.json()).get("id") or ""), user)
    return web.json_response({})


async def api_webhook_test(request):
    need_user(request)
    try:
        ok, detail = await request.app["hooks"].test(str((await request.json()).get("id") or ""))
    except ValueError as e:
        return web.json_response({"error": str(e)}, status=400)
    return web.json_response({"ok": ok, "detail": detail})


async def api_history(request):
    rows = request.app["db"].execute(
        "SELECT * FROM triage_log WHERE item_id=? ORDER BY at DESC LIMIT 30",
        (request.match_info["id"],)).fetchall()
    return web.json_response([dict(r) for r in rows])


async def api_login(request):
    body = await request.json()
    stored = read_login_hash()
    name = str(body.get("name") or "").strip()[:40]
    attempts = request.app["attempts"]
    ip = request.remote or "?"
    recent = [t for t in attempts.get(ip, []) if t > now() - 600]
    if len(recent) >= 8:
        raise web.HTTPTooManyRequests(text="Too many attempts; try again in 10 minutes")
    await asyncio.sleep(0.4)
    if not name or not stored or not check_password(str(body.get("password") or ""), stored):
        attempts[ip] = recent + [now()]
        return web.json_response({"error": "Wrong password" if name else "Enter your name"}, status=401)
    attempts.pop(ip, None)
    token = secrets.token_urlsafe(32)
    request.app["db"].execute("INSERT INTO sessions VALUES(?,?,?)",
                              (hashlib.sha256(token.encode()).hexdigest(), name,
                               now() + SESSION_DAYS * 86400))
    resp = web.json_response({"user": name})
    resp.set_cookie(COOKIE, token, max_age=SESSION_DAYS * 86400, httponly=True,
                    secure=not DEV, samesite="Strict", path="/")
    return resp


async def api_logout(request):
    token = request.cookies.get(COOKIE)
    if token:
        request.app["db"].execute("DELETE FROM sessions WHERE token_hash=?",
                                  (hashlib.sha256(token.encode()).hexdigest(),))
    resp = web.json_response({})
    resp.del_cookie(COOKIE, path="/")
    return resp


async def api_triage(request):
    user = session_name(request)
    if not user:
        raise web.HTTPUnauthorized(text="Sign in to change status")
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
    if not session_name(request):
        raise web.HTTPUnauthorized(text="Sign in to refresh")
    fetcher = request.app["fetcher"]
    if fetcher.lock.locked():
        return web.json_response({"busy": True})
    background(request.app, fetcher.refresh(force=True))
    return web.json_response({"ok": True})


async def index(request):
    return web.FileResponse(HERE / "static" / "index.html")


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
    app["hooks"] = W.Webhooks(db, read_settings_key(), PUBLIC_URL)
    app["fresh"] = app["hooks"].is_empty()
    fetcher.after_refresh = lambda: notify_changes(app)
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
