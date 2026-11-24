"""Node.js security releases, from the Node.js project's vulnerability blog.

The project announces each security release about a week ahead ("will release
new versions of the 26.x, 24.x, 22.x release lines on or shortly after ...",
with how many high/medium/low issues), then fills the same page in on release
day: one heading per issue, "... (CVE-2026-123864) - (high)", the release lines
each one affects, and the fixed versions under "Downloads and release details".

  feed   https://nodejs.org/en/feed/vulnerability.xml (every release, newest first)
  page   https://nodejs.org/en/blog/vulnerability/november-2026-security-releases

The feed also carries other posts (a CI incident, write-ups); a page that is
neither an announcement nor a release is noted and not read again.

The nodejs/security-wg JSON has the same data per CVE, but only weeks after the
release (November 2026 wasn't in it two weeks later), so the page is the source.

Which major lines were still supported on release day comes from the release
schedule (nodejs/Release schedule.json): a line the release leaves out is either
past end-of-life (always affected, the project says) or simply not affected.
"""
import html
import json
import re
import time
from datetime import date, datetime, timedelta
from email.utils import parsedate_to_datetime

from aiohttp import ClientTimeout

FEED = "https://nodejs.org/en/feed/vulnerability.xml"
SCHEDULE = "https://raw.githubusercontent.com/nodejs/Release/main/schedule.json"
ITEM_DAYS = 365            # releases this recent are on the list
RECHECK_DAYS = 30          # releases this recent are read again once a day (pages get updates)
RECHECK_EVERY = 86400
SCHEDULE_EVERY = 86400

SCHEMA = """
CREATE TABLE IF NOT EXISTS nodejs (
  slug TEXT PRIMARY KEY, title TEXT, link TEXT, published TEXT, status TEXT, lines TEXT,
  fixes TEXT, highest TEXT, counts TEXT, cves TEXT, issues TEXT, deps TEXT, looked REAL);
CREATE TABLE IF NOT EXISTS nodejs_probe (slug TEXT PRIMARY KEY, state TEXT, published TEXT, looked REAL);
"""
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
LEVELS = ["low", "medium", "high", "critical"]
MONTHS = "January|February|March|April|May|June|July|August|September|October|November|December"
DATE_RE = re.compile(rf"\b({MONTHS})\s+(\d{{1,2}}),\s+(\d{{4}})")
HEADING = re.compile(r"<h([1-3])\b[^>]*>(.*?)</h\1>", re.S | re.I)
ISSUE = re.compile(r"^(?P<title>.*?)\s*(?P<cves>\((?:\s*CVE-[\d-]+\s*,?\s*)+\))?\s*-\s*\((?P<sev>critical|high|medium|low)\)\s*$", re.I)
NODE_WORDS = re.compile(r"(?<![A-Za-z0-9])node(?:\.?js)?(?![A-Za-z0-9])", re.I)


def migrate(db):
    db.executescript(SCHEMA)


def one_line(fragment):
    t = html.unescape(re.sub(r"<[^>]+>", " ", fragment or "")).replace("\xa0", " ")
    t = re.sub(r"\s+", " ", t).strip()
    return re.sub(r"\(\s+", "(", re.sub(r"\s+([,.;:!?)])", r"\1", t))   # "<code>x()</code> , and" -> "x(), and"


def iso(text):
    m = DATE_RE.search(text or "")
    if not m:
        return None
    try:
        return datetime.strptime(f"{m[1]} {m[2]} {m[3]}", "%B %d %Y").date().isoformat()
    except ValueError:
        return None


def majors(text):
    """'26.x, 24.x, 22.x' / 'Node.js v24.x users' / 'Node.js 22, Node.js 24' / 'Node.js 20, 22, 24 and 25'
    -> the major lines named (not 'Node.js 24.12.0', a version)."""
    out = [int(m) for m in re.findall(r"(?<![\d.])v?(\d{1,2})\.x\b", text or "")]
    for run in re.findall(r"Node\.js\s+(v?\d{1,2}(?!\d|\.\d)(?:(?:\s*,\s*|,?\s+and\s+)v?\d{1,2}(?!\d|\.\d))*)", text or ""):
        out += [int(n) for n in re.findall(r"\d+", run)]
    return list(dict.fromkeys(out))


# --- the feed and one page -----------------------------------------------------------

def parse_feed(xml):
    """The vulnerability feed -> [(slug, link, published ISO date)]."""
    out = []
    for block in re.findall(r"<item>(.*?)</item>", xml or "", re.S):
        link = re.search(r"<link>\s*([^<\s]+)\s*</link>", block)
        when = re.search(r"<pubDate>([^<]+)</pubDate>", block)
        if not link:
            continue
        try:
            day = parsedate_to_datetime(when[1].strip()).date().isoformat() if when else None
        except (TypeError, ValueError):
            day = None
        out.append((link[1].rstrip("/").rsplit("/", 1)[-1], link[1], day))
    return out


def parse(page, slug, link, feed_date=None):
    """A blog page -> the nodejs row as a dict, or None when it isn't a security release."""
    start = page.find("<h1")
    art = page[start:] if start >= 0 else page
    end = re.search(r"<h2\b[^>]*>(?:(?!</h2>).)*Contact and future updates", art, re.S)
    art = art[:end.start()] if end else art
    plain = one_line(art)
    downloads = re.search(r"<h2\b[^>]*>(?:(?!</h2>).)*Downloads and release details.*?</h2>(.*?)(?=<h2\b|$)", art, re.S)
    announce = re.search(r"will release new versions of the (.+?) release(?:s)? lines", plain)
    if not downloads and not announce:
        return None
    h1 = HEADING.search(art)
    title = one_line(h1[2]) if h1 and h1[1] == "1" else ""
    published = iso(title) or (iso(announce and plain[announce.end():announce.end() + 80]) if announce else None) or feed_date
    # fixed versions: "Node.js v24.22.3" (older pages: "Node.js 24.13.0")
    fixes = {}
    for m in re.finditer(r"Node\.js\s+v?(\d+)\.(\d+)\.(\d+)", one_line(downloads[1]) if downloads else ""):
        fixes.setdefault(int(m[1]), f"{m[1]}.{m[2]}.{m[3]}")
    lines = majors(announce[1]) if announce else []
    lines = sorted(set(lines) | set(fixes), reverse=True)
    # the issues: "<title> (CVE-...) - (high)" headings, each with an Impact list
    heads = list(HEADING.finditer(art))
    issues = []
    for i, h in enumerate(heads):
        head = one_line(h[2])
        m = ISSUE.match(head)
        if not m or h[1] == "1":
            continue
        body = art[h.end(): heads[i + 1].start() if i + 1 < len(heads) else len(art)]
        text = one_line(body)
        im = re.search(r"(?:Impact:\s*)(.+?)(?:\s*Thank you|$)|(This vulnerability affects.+?)(?:\s*Thank you|$)", text)
        impact = (im[1] or im[2]).strip() if im else ""
        hit = majors(impact) or lines
        issues.append({"title": m["title"].strip().rstrip(":"), "cves": list(dict.fromkeys(CVE_RE.findall(head))),
                       "severity": m["sev"].lower(), "lines": hit, "impact": impact[:300]})
    counts = {}
    for x in issues:
        counts[x["severity"]] = counts.get(x["severity"], 0) + 1
    if not issues and announce:   # an announcement: "7 high severity issues", "1 medium severity issue"
        tail = plain[announce.end():]
        cut = re.search(r"\bImpact\b|The \d+\.x release line", tail)
        for n, sev in re.findall(r"(\d+)\s+(critical|high|medium|low)\s+severity issues?", tail[:cut.start()] if cut else tail[:600], re.I):
            counts[sev.lower()] = counts.get(sev.lower(), 0) + int(n)
    hm = re.search(r"highest severity issue fixed in this release is (\w+)", plain, re.I)
    found = [s for s in counts if counts[s]] + ([hm[1].lower()] if hm and hm[1].lower() in LEVELS else [])
    highest = max(found, key=LEVELS.index, default=None)
    deps = []
    dm = re.search(r"following dependency updates[^<]*</p>\s*<ul>(.*?)</ul>", art, re.S)
    if dm:
        deps = [one_line(li) for li in re.findall(r"<li\b[^>]*>(.*?)</li>", dm[1], re.S)]
    cves = list(dict.fromkeys(c for x in issues for c in x["cves"]))
    return {"slug": slug, "title": title, "link": link, "published": published,
            "status": "released" if fixes else "upcoming", "lines": lines,
            "fixes": {str(k): v for k, v in sorted(fixes.items(), reverse=True)},
            "highest": highest, "counts": counts, "cves": cves, "issues": issues, "deps": deps}


def save(db, row):
    db.execute("INSERT OR REPLACE INTO nodejs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
               (row["slug"], row["title"], row["link"], row["published"], row["status"], json.dumps(row["lines"]),
                json.dumps(row["fixes"]), row["highest"], json.dumps(row["counts"]), json.dumps(row["cves"]),
                json.dumps(row["issues"]), json.dumps(row["deps"]), time.time()))


# --- reading ---------------------------------------------------------------------------

async def _get(session, url, as_json=False):
    async with session.get(url, timeout=ClientTimeout(total=40)) as r:
        if r.status != 200:
            raise RuntimeError(f"Node.js: HTTP {r.status} from {url}")
        return await (r.json(content_type=None) if as_json else r.text(errors="replace"))


def plan(db, feed, now=None):
    """Which feed entries to read this run."""
    now = now or time.time()
    since = (date.fromtimestamp(now) - timedelta(days=ITEM_DAYS)).isoformat()
    recent = (date.fromtimestamp(now) - timedelta(days=RECHECK_DAYS)).isoformat()
    probe = {r["slug"]: (r["state"], r["looked"]) for r in db.execute("SELECT slug, state, looked FROM nodejs_probe")}
    rows = {r["slug"]: (r["status"], r["published"]) for r in db.execute("SELECT slug, status, published FROM nodejs")}
    out = []
    for slug, link, day in feed:
        if day and day < since and slug not in rows:
            continue
        state, looked = probe.get(slug, (None, 0))
        status, published = rows.get(slug, (None, None))
        if state is None:
            out.append((slug, link, day))                     # never read
        elif status == "upcoming":
            out.append((slug, link, day))                     # announced: read every run until it's out
        elif status == "released" and (published or "") >= recent and looked < now - RECHECK_EVERY:
            out.append((slug, link, day))                     # recent: once a day
    return out


async def refresh(db, session, log=print):
    """Read the feed, new and recent pages, and (daily) the release schedule; returns how many releases are stored."""
    feed = parse_feed(await _get(session, FEED))
    if not feed:
        raise RuntimeError("Node.js: the vulnerability feed has no entries")
    for slug, link, day in plan(db, feed):
        page = await _get(session, link)
        row = parse(page, slug, link, day)
        if row:
            save(db, row)
        db.execute("INSERT OR REPLACE INTO nodejs_probe VALUES(?,?,?,?)",
                   (slug, "release" if row else "other", day, time.time()))
    got = db.execute("SELECT value FROM meta WHERE key='nodejs_schedule_at'").fetchone()
    if not got or float(got[0]) < time.time() - SCHEDULE_EVERY:
        try:
            sched = await _get(session, SCHEDULE, as_json=True)
            if isinstance(sched, dict) and sched:
                db.execute("INSERT OR REPLACE INTO meta VALUES('nodejs_schedule', ?)", (json.dumps(sched),))
                db.execute("INSERT OR REPLACE INTO meta VALUES('nodejs_schedule_at', ?)", (str(time.time()),))
        except Exception as e:   # the schedule only refines version checks; the releases matter more
            log(f"nodejs: release schedule not read ({e})")
    return db.execute("SELECT COUNT(*) FROM nodejs").fetchone()[0]


# --- what the rest of Heads Up uses ------------------------------------------------------

def schedule(db):
    row = db.execute("SELECT value FROM meta WHERE key='nodejs_schedule'").fetchone()
    return json.loads(row[0]) if row else {}


def line_states(sched, on, lines):
    """For a release on day `on`: {major: 'eol' | 'active' | 'later'} for every major in the schedule
    that the release doesn't patch."""
    out = {}
    for k, s in (sched or {}).items():
        m = re.fullmatch(r"v(\d+)", k)
        if not m or int(m[1]) in lines or not isinstance(s, dict):
            continue
        start, end = s.get("start") or s.get("alpha"), s.get("end")
        if end and on and end <= on:
            out[int(m[1])] = "eol"
        elif start and on and start > on:
            out[int(m[1])] = "later"
        elif start:
            out[int(m[1])] = "active"
    return out


def recent_eol(sched, on, days=365):
    """Major lines that reached end-of-life in the year before day `on`, newest first (the ones people
    may still run: 20 and 25 for a November 2026 release, not 21 or 23)."""
    if not on:
        return []
    since = (date.fromisoformat(on) - timedelta(days=days)).isoformat()
    out = [int(k[1:]) for k, s in (sched or {}).items()
           if re.fullmatch(r"v\d+", k) and isinstance(s, dict) and since <= (s.get("end") or "") <= on]
    return sorted(out, reverse=True)


def counts_text(counts):
    return ", ".join(f"{counts[s]} {s}" for s in reversed(LEVELS) if counts.get(s))


def info(r, sched=None):
    lines = json.loads(r["lines"] or "[]")
    return {"id": r["slug"], "title": r["title"], "link": r["link"], "published": r["published"],
            "status": r["status"], "lines": lines, "fixes": json.loads(r["fixes"] or "{}"),
            "highest": r["highest"], "counts": json.loads(r["counts"] or "{}"),
            "cves": json.loads(r["cves"] or "[]"), "issues": json.loads(r["issues"] or "[]"),
            "deps": json.loads(r["deps"] or "[]"),
            "others": {str(k): v for k, v in line_states(sched, r["published"], lines).items()},
            "recentEol": recent_eol(sched, r["published"])}


def title_of(x):
    n = len(x["cves"]) or sum(x["counts"].values())
    what = f"{n} security fix{'es' if n != 1 else ''}" if n else "security release"
    lines = ", ".join(f"{m}.x" for m in x["lines"])
    if x["status"] == "upcoming":
        return f"Node.js security releases coming for {lines}" if lines else "Node.js security releases coming"
    return f"Node.js security release: {what} for {lines}" if lines else f"Node.js security release: {what}"


def summary_of(x):
    if x["status"] == "upcoming":
        c = counts_text(x["counts"])
        return (f"The Node.js project will release fixes on or shortly after {x['published']}"
                + (f" ({c} severity issues)." if c else ".") + " The details come out with the release.")
    top = sorted(x["issues"], key=lambda i: -LEVELS.index(i["severity"]))[:4]
    return "; ".join(f"{i['title']} ({i['severity']})" for i in top) or x["title"]


def items(db, today=None):
    since = ((today or date.today()) - timedelta(days=ITEM_DAYS)).isoformat()
    sched = schedule(db)
    out = []
    for r in db.execute("SELECT * FROM nodejs WHERE published >= ? ORDER BY published DESC", (since,)):
        x = info(r, sched)
        fixed = ", ".join(x["fixes"].values())
        out.append({
            "id": f"nodejs:{r['slug']}", "source": "nodejs", "title": title_of(x), "link": r["link"],
            "published": r["published"], "updated": r["published"],
            "category": r["highest"] or "",
            "headline": (f"{(r['highest'] or 'unrated').title()} · {counts_text(x['counts']) or 'no issues listed'}"
                         + (f" · fixed in {fixed}" if fixed else " · coming")),
            "summary": summary_of(x), "cves": x["cves"], "tags": ["Node.js"],
            "fingerprint": f"{r['status']}|{r['highest']}|{len(x['cves'])}|{fixed}",
            "extra": x,
        })
    return out


def cve_info(db, cve_ids):
    """CVE -> the Node.js release that fixed it (its issue title, severity and lines)."""
    want, out = set(cve_ids), {}
    sched = None
    for r in db.execute("SELECT * FROM nodejs ORDER BY published"):
        cves = want.intersection(json.loads(r["cves"] or "[]"))
        if not cves:
            continue
        sched = schedule(db) if sched is None else sched
        x = info(r, sched)
        for c in cves:
            issue = next((i for i in x["issues"] if c in i["cves"]), {})
            out[c] = {**{k: x[k] for k in ("id", "title", "link", "published", "status", "lines", "fixes", "others", "recentEol")},
                      "issue": issue.get("title"), "severity": issue.get("severity"),
                      "affects": issue.get("lines") or x["lines"]}
    return out


# --- What we run --------------------------------------------------------------------------

def is_node(entry):
    return bool(NODE_WORDS.search(" ".join([entry.get("name") or "", *(entry.get("terms") or [])])))


def versions(text):
    """'24.22.2 (Resy), 22.x, v20' -> [(24, (24, 22, 2)), (22, None), (20, None)]: None = the whole line."""
    out = []
    for m in re.finditer(r"(?<![\w.])v?(\d{1,2})((?:\.(?:\d+|x|X|\*))*)(?![\w.])", str(text or "")):
        parts = [p for p in m[2].split(".") if p]
        exact = (int(m[1]), *map(int, parts)) if len(parts) == 2 and all(p.isdigit() for p in parts) else None
        if (int(m[1]), exact) not in out:
            out.append((int(m[1]), exact))
    return out


def check(entry, rel):
    """One What we run entry against a Node.js release -> versions.check notes (one per version typed)."""
    base = {"product": entry["name"], "vendor": "Node.js", "upto": None}
    vers = versions(entry.get("version"))
    if not vers:
        return [{**base, "version": None, "state": "noversion", "fix": None}]
    fixes = {int(k): v for k, v in (rel.get("fixes") or {}).items()}
    others = {int(k): v for k, v in (rel.get("others") or {}).items()}
    notes = []
    for major, exact in vers:
        label = ".".join(map(str, exact)) if exact else f"{major}.x"
        n = {**base, "version": label, "line": str(major), "fix": None}
        fix = fixes.get(major)
        if rel.get("status") == "upcoming" and major in rel.get("lines", []):
            n.update(state="due", fix=rel.get("published"))
        elif fix and exact:
            n.update(state="fixed" if exact >= tuple(int(x) for x in fix.split(".")) else "upgrade", fix=fix)
        elif fix:
            n.update(state="line", fix=fix)
        elif others.get(major) == "eol":
            n.update(state="affectedline", eol=True)
        elif others.get(major) in ("active", "later"):
            n.update(state="notaffected")
        else:
            n.update(state="unlisted")
        notes.append(n)
    return notes
