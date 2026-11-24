"""Node.js security releases: parsing the release pages, reading the feed, version checks and the list."""
import asyncio
import json
from datetime import date

import helpers
import app  # noqa: E402
import nodejs as N  # noqa: E402
import search as SR  # noqa: E402

PAGES = {n: (helpers.FIXTURES / f"nodejs-{n}.html").read_text()
         for n in ("november-2026", "october-2026", "june-2026", "december-2025", "march-2026", "hashdos", "upcoming")}
FEED = (helpers.FIXTURES / "nodejs-feed.xml").read_text()
SCHEDULE = json.loads((helpers.FIXTURES / "nodejs-schedule.json").read_text())
BASE = "https://nodejs.org/en/blog/vulnerability/"
NODE = {"name": "Node.js", "terms": ["Node.js"]}


def rel(name, slug=None):
    slug = slug or f"{name}-security-releases"
    return N.parse(PAGES[name], slug, BASE + slug)


# --- one page ------------------------------------------------------------------------

def test_parse_november_2026():
    r = rel("november-2026")
    assert (r["published"], r["status"], r["highest"]) == ("2026-11-11", "released", "high")
    assert r["lines"] == [26, 24, 22] and r["fixes"] == {"26": "26.13.1", "24": "24.22.3", "22": "22.23.5"}
    assert r["counts"] == {"high": 7, "medium": 6, "low": 3} and len(r["cves"]) == 16
    https = next(i for i in r["issues"] if i["cves"] == ["CVE-2026-123864"])
    assert https["severity"] == "high" and https["lines"] == [22, 24, 26]
    # "<code>llhttp_execute()</code>, and": no stray space before the comma
    assert https["title"].startswith("HTTPS: a zero-length TLS write re-enters llhttp_execute(), and"), https["title"]
    h2 = next(i for i in r["issues"] if i["cves"] == ["CVE-2026-123863"])
    assert h2["lines"] == [24, 26]                       # only some lines
    assert r["deps"] == ["llhttp on 22.x, 24.x, 26.x", "undici on 24.x, 26.x", "sqlite on 22.x, 24.x"]


def test_parse_older_layouts():
    # h2 issue headings and "Node.js 20.20.0" without the v (published January 13, 2026)
    d = rel("december-2025")
    assert d["published"] == "2026-01-13" and d["fixes"]["20"] == "20.20.0" and d["lines"] == [25, 24, 22, 20]
    assert d["counts"] == {"high": 3, "medium": 4, "low": 1}
    # "affects all supported release lines: Node.js 22, Node.js 24, and Node.js 26."
    j = rel("june-2026")
    assert all(i["lines"] == [22, 24, 26] for i in j["issues"] if i["cves"] == ["CVE-2026-48933"])
    # "affects HTTP2 users on Node.js 20, 22, 24 and 25." and "affects 24.x and 25.x."
    m = rel("march-2026")
    assert next(i for i in m["issues"] if "CVE-2026-21714" in i["cves"])["lines"] == [20, 22, 24, 25]
    assert next(i for i in m["issues"] if "CVE-2026-21712" in i["cves"])["lines"] == [24, 25]
    # the same CVE twice in one heading is listed once
    assert all(len(i["cves"]) == len(set(i["cves"])) for i in m["issues"])


def test_other_posts_are_not_releases():
    assert N.parse(PAGES["hashdos"], "march-2026-hashdos", BASE + "march-2026-hashdos") is None


def test_parse_an_announcement():
    r = N.parse(PAGES["upcoming"], "january-2027-security-releases", BASE + "january-2027-security-releases")
    assert (r["status"], r["published"], r["lines"], r["fixes"], r["issues"]) == \
        ("upcoming", "2027-01-12", [26, 24, 22], {}, [])
    assert r["counts"] == {"high": 2, "medium": 3, "low": 1} and r["highest"] == "high"


def test_feed():
    feed = N.parse_feed(FEED)
    assert feed[0] == ("november-2026-security-releases", BASE + "november-2026-security-releases", "2026-11-11")
    assert len(feed) == 12


# --- reading -------------------------------------------------------------------------

class FakeResponse:
    def __init__(self, status, body):
        self.status, self.body = status, body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def text(self, errors=None):
        return self.body

    async def json(self, content_type=None):
        return json.loads(self.body)


class FakeSite:
    def __init__(self, feed=FEED, extra=None):
        self.feed, self.asked = feed, []
        self.pages = {f"{n}-security-releases": PAGES[n] for n in ("november-2026", "october-2026", "june-2026",
                                                                     "december-2025", "march-2026")}
        self.pages["march-2026-hashdos"] = PAGES["hashdos"]
        self.pages.update(extra or {})

    def get(self, url, **kw):
        self.asked.append(url)
        if url == N.FEED:
            return FakeResponse(200, self.feed)
        if url == N.SCHEDULE:
            return FakeResponse(200, json.dumps(SCHEDULE))
        slug = url.rsplit("/", 1)[-1]
        return FakeResponse(200, self.pages.get(slug, "<html><h1>Something else</h1></html>"))


def fresh():
    db = app.db_open()
    db.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
    for t in ("items", "cve", "nodejs", "nodejs_probe", "triage", "inventory", "meta"):
        db.execute(f"DELETE FROM {t}")
    return db


def at(day):
    """Pretend today is `day` for the "last 365 days" rules."""
    return __import__("datetime").datetime(*day).timestamp()


def test_refresh_reads_new_pages_once():
    db = fresh()
    real_time = N.time.time
    N.time.time = lambda: at((2026, 11, 24))
    try:
        site = FakeSite()
        n = asyncio.run(N.refresh(db, site))
        assert n == 5, n      # Nov, Oct, Jun, Mar, Dec 2025 (no July page in this fake site)
        pages = [u for u in site.asked if u.startswith(BASE)]
        # a year back from 11-24: Dec 2025's release (13 Jan 2026) and newer, not 2025's
        assert BASE + "july-2025-security-releases" not in pages and BASE + "november-2026-security-releases" in pages
        assert N.SCHEDULE in site.asked
        states = dict(db.execute("SELECT slug, state FROM nodejs_probe").fetchall())
        assert states["march-2026-hashdos"] == "other" and states["november-2026-security-releases"] == "release"
        # next run: nothing to read again yet (looked at today), no schedule either
        site2 = FakeSite()
        asyncio.run(N.refresh(db, site2))
        assert site2.asked == [N.FEED]
        # a day later: the recent release (November, within 30 days) is read again, the rest not
        N.time.time = lambda: at((2026, 11, 25, 12))
        site3 = FakeSite()
        asyncio.run(N.refresh(db, site3))
        assert [u for u in site3.asked if u.startswith(BASE)] == [BASE + "november-2026-security-releases"]
    finally:
        N.time.time = real_time


def test_an_announcement_is_read_until_it_is_out():
    db = fresh()
    real_time = N.time.time
    N.time.time = lambda: at((2027, 1, 5))
    try:
        slug = "january-2027-security-releases"
        feed = FEED.replace("<item>", f"<item><title>x</title><link>{BASE}{slug}</link><pubDate>Tue, 05 Jan 2027 00:00:00 GMT</pubDate></item><item>", 1)
        asyncio.run(N.refresh(db, FakeSite(feed, {slug: PAGES["upcoming"]})))
        assert db.execute("SELECT status FROM nodejs WHERE slug=?", (slug,)).fetchone()[0] == "upcoming"
        site = FakeSite(feed, {slug: PAGES["upcoming"]})
        asyncio.run(N.refresh(db, site))
        assert BASE + slug in site.asked                   # read again on every run
        released = PAGES["november-2026"].replace("November 11, 2026", "January 12, 2027")
        asyncio.run(N.refresh(db, FakeSite(feed, {slug: released})))
        assert db.execute("SELECT status FROM nodejs WHERE slug=?", (slug,)).fetchone()[0] == "released"
    finally:
        N.time.time = real_time


# --- What we run --------------------------------------------------------------------

def info(name):
    r = rel(name)
    N.save(fresh(), r)
    db = app.db_open()
    db.execute("INSERT OR REPLACE INTO meta VALUES('nodejs_schedule', ?)", (json.dumps(SCHEDULE),))
    return N.info(db.execute("SELECT * FROM nodejs WHERE slug=?", (r["slug"],)).fetchone(), SCHEDULE)


def states(rel_info, version):
    return [(n["version"], n["state"], n["fix"]) for n in N.check({**NODE, "version": version}, rel_info)]


def test_version_check():
    nov = info("november-2026")
    assert states(nov, "24.22.2") == [("24.22.2", "upgrade", "24.22.3")]
    assert states(nov, "24.22.3, 26.13.2") == [("24.22.3", "fixed", "24.22.3"), ("26.13.2", "fixed", "26.13.1")]
    assert states(nov, "24.x") == [("24.x", "line", "24.22.3")]
    assert states(nov, "v22") == [("22.x", "line", "22.23.5")]
    # 20 and 25 were past end-of-life on November 11: affected, no fix
    assert states(nov, "20.19.0") == [("20.19.0", "affectedline", None)]
    assert N.check({**NODE, "version": "25.2.0"}, nov)[0].get("eol")
    assert states(nov, "")[0][1] == "noversion"
    assert states(nov, "99.1.0")[0][1] == "unlisted"
    # a supported line the release leaves out isn't affected (24 and 26 only in this made-up release)
    only = {**nov, "fixes": {"26": "26.13.1", "24": "24.22.3"}, "lines": [26, 24],
            "others": {str(k): v for k, v in N.line_states(SCHEDULE, "2026-11-11", [26, 24]).items()}}
    assert states(only, "22.23.4") == [("22.23.4", "notaffected", None)]
    # announced, not out yet
    up = N.parse(PAGES["upcoming"], "january-2027-security-releases", BASE)
    up = {**up, "others": {}}
    assert states(up, "24.22.3") == [("24.22.3", "due", "2027-01-12")]
    assert not N.is_node({"name": "Node2Shell", "terms": []}) and N.is_node({"name": "Servers", "terms": ["nodejs"]})


def load(db, *names):
    db.execute("INSERT OR REPLACE INTO meta VALUES('nodejs_schedule', ?)", (json.dumps(SCHEDULE),))
    for n in names:
        N.save(db, rel(n))
    for it in N.items(db, today=date(2026, 11, 24)):
        app.upsert_item(db, {**it})
        db.executemany("INSERT OR IGNORE INTO cve(id) VALUES(?)", [(c,) for c in it["cves"]])


def vuln(db, inventory, slug="november-2026-security-releases"):
    return next(v for v in app.build_state(db, inventory)["vulns"] if v["id"] == f"nodejs:{slug}")


def why(v):
    return "".join(t for t, _ in v["why"])


def test_on_the_list_for_your_node():
    db = fresh()
    load(db, "november-2026", "october-2026")
    v = vuln(db, [{**NODE, "version": "24.22.2"}])
    assert v["group"] == "soon" and v["ours"] == ["Node.js"] and "Node.js" in v["reportedBy"]
    assert v["title"] == "Node.js security release: 16 security fixes for 26.x, 24.x, 22.x", v["title"]
    assert "Node.js security release (7 high, 6 medium, 3 low)." in why(v), why(v)
    assert "You run Node.js 24.22.2: upgrade to 24.22.3." in why(v), why(v)
    # October's release is already in 24.22.2: Done by itself
    oct_ = vuln(db, [{**NODE, "version": "24.22.2"}], "october-2026-security-releases")
    assert oct_["autoDone"] and oct_["group"] == "done"
    # end-of-life line
    v = vuln(db, [{**NODE, "version": "20.19.0"}])
    assert v["group"] == "soon" and "Node.js 20 is past end-of-life" in why(v), why(v)
    # fixed -> Done
    assert vuln(db, [{**NODE, "version": "24.22.3"}])["group"] == "done"
    # Node.js not on What we run: awareness, saying so
    v = vuln(db, [{"name": "FortiGate", "terms": ["FortiGate"], "version": "7.4.13"}])
    assert v["group"] == "aware" and "Node.js isn't on What we run." in why(v)
    assert "Fixed in 26.13.1, 24.22.3, 22.23.5." in why(v), why(v)


def test_cve_info_and_box_data():
    db = fresh()
    load(db, "november-2026")
    got = N.cve_info(db, ["CVE-2026-123863", "CVE-2026-1"])
    assert list(got) == ["CVE-2026-123863"]
    assert got["CVE-2026-123863"]["severity"] == "high" and got["CVE-2026-123863"]["affects"] == [24, 26]
    v = vuln(db, [])
    assert v["nodejs"]["fixes"]["24"] == "24.22.3" and v["nodejs"]["others"]["20"] == "eol"
    assert v["nodejs"]["recentEol"] == [25, 20]          # the card names these, not 21 or 23


def test_older_releases_are_in_search():
    db = fresh()
    load(db, "november-2026")
    db.execute("UPDATE items SET active=0 WHERE source='nodejs'")       # as if it had dropped off the list
    found = SR.search(db, "CVE-2026-123864")
    assert [e["id"] for e in found["results"]] == ["CVE-2026-123864"]
    e = found["results"][0]
    assert e["sources"] == ["nj"] and e["product"] == "Node.js" and "2026-11-11" in e["notes"][0]


class FakeHooks:
    base_url = "https://hu"

    def __init__(self):
        self.sent = []

    async def send_note(self, event, title, body, facts, link):
        self.sent.append((event, title, body, dict(facts), link))


def test_announce_when_announced_and_when_out():
    db = fresh()
    load(db, "october-2026")
    hooks = FakeHooks()
    a = {"db": db, "hooks": hooks}
    asyncio.run(app.announce_nodejs(a))
    assert hooks.sent == []                                  # first run records what's there
    db.execute("INSERT INTO inventory(id, name, terms, version, note, by, at) VALUES('nj',?,?,?,'','t',0)",
               ("Node.js", json.dumps(["Node.js"]), "24.22.2, 20.19.0"))
    slug = "november-2026-security-releases"
    up = N.parse(PAGES["upcoming"].replace("January 12, 2027", "November 11, 2026"), slug, BASE + slug)
    N.save(db, up)
    asyncio.run(app.announce_nodejs(a))
    assert len(hooks.sent) == 1
    event, title, body, facts, link = hooks.sent[0]
    assert event == "nodejs" and title == "Node.js security releases coming for 26.x, 24.x, 22.x", title
    assert facts["You run"] == "Node.js 24.22.2: fix due 2026-11-11; Node.js 20.19.0: end-of-life, no fix", facts
    N.save(db, rel("november-2026"))
    asyncio.run(app.announce_nodejs(a))
    assert len(hooks.sent) == 2
    event, title, body, facts, link = hooks.sent[1]
    assert facts["Fixed in"] == "26.13.1, 24.22.3, 22.23.5" and facts["Issues"] == "7 high, 6 medium, 3 low"
    assert facts["You run"].startswith("Node.js 24.22.2: upgrade to 24.22.3"), facts
    assert link == BASE + slug
    asyncio.run(app.announce_nodejs(a))
    assert len(hooks.sent) == 2


helpers.run_tests(globals())
