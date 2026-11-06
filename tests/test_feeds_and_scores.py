"""Cloudflare's feed format and severity scores, through the real parser, enrich() and build_state()."""
import asyncio
import json
import sqlite3
import sys

import helpers
import app  # noqa: E402
import vulns as V  # noqa: E402
import webhooks as W  # noqa: E402

FEED = (helpers.FIXTURES / "zero-wire.xml").read_text()


def fresh():
    db = app.db_open()
    for t in ("items", "cve", "msrc", "fortinet"):
        db.execute(f"DELETE FROM {t}")
    db.execute("DELETE FROM sources")
    return db


def fetcher(db, feed=FEED):
    f = app.Fetcher(db)

    async def get(*a, **k):
        return feed

    f.get = get
    return f


def why(v):
    return "".join(t for t, _ in v["why"])


def state_after_feed(feed=FEED):
    db = fresh()
    asyncio.run(fetcher(db, feed).zero_wire())
    return db, app.build_state(db)


def test_real_feed_gives_every_briefing_a_headline_and_review_date():
    db, _ = state_after_feed()
    rows = db.execute("SELECT id, headline, updated, summary, extra FROM items WHERE source='zerowire'").fetchall()
    assert len(rows) == 2
    for r in rows:
        assert r["headline"], r["id"]
        assert not r["summary"].startswith(r["headline"]), r["summary"][:60]
        assert json.loads(r["extra"])["chronology"], r["id"]
    tcp = db.execute("SELECT headline, updated FROM items WHERE id='zw:example-tcp-flaw'").fetchone()
    assert tcp["headline"] == "Prioritize patching" and tcp["updated"] == "2026-11-02", dict(tcp)


def test_page_text_has_the_advice_and_no_blank():
    _, st = state_after_feed()
    v = next(x for x in st["vulns"] if "use-after-free" in x["title"])
    assert "Cloudflare says: Prioritize patching." in why(v), why(v)
    assert v["zwHeadline"] == "Prioritize patching"


def test_guidance_alert_text():
    _, st = state_after_feed()
    v = next(x for x in st["vulns"] if "use-after-free" in x["title"])
    _, body = W.describe_event("updated", v, None)
    assert "Their advice: Prioritize patching." in body, body
    _, body = W.describe_event("updated", {**v, "zwHeadline": ""}, None)
    assert "Their advice" not in body, body


def test_chronology_stops_at_details():
    db, _ = state_after_feed()
    chron = json.loads(db.execute("SELECT extra FROM items WHERE id='zw:example-tcp-flaw'").fetchone()[0])["chronology"]
    assert chron[0]["date"] == "2026-11-01" and "fixed kernels" in chron[0]["text"] and len(chron) == 2, chron


def test_old_format_still_parses():
    old = FEED.replace("Last reviewed", "Last checked").replace("<h2>Details</h2>", "<h2>What happened</h2>")
    db, _ = state_after_feed(old)
    assert db.execute("SELECT headline FROM items WHERE id='zw:example-tcp-flaw'").fetchone()[0] == "Prioritize patching"


def test_another_format_change_is_flagged_not_blank():
    db, st = state_after_feed(FEED.replace("Last reviewed", "Reviewed on"))
    s = db.execute("SELECT error, ok_at, err_at FROM sources WHERE name='zerowire'").fetchone()
    assert "format changed" in s["error"] and s["err_at"] >= s["ok_at"], dict(s)
    v = next(x for x in st["vulns"] if "use-after-free" in x["title"])
    assert "Cloudflare says: ." not in why(v) and "Cloudflare flagged this" in why(v), why(v)


def add_item(db, item_id, source, cves, **k):
    db.execute("INSERT INTO items(id, source, title, link, published, updated, category, headline, summary, body, cves, tags, extra, fingerprint, first_seen, changed_at, active)"
               " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)",
               (item_id, source, k.get("title", item_id), "https://x/" + item_id, "2026-11-01", "2026-11-01", k.get("category", ""), "", "s", "", json.dumps(cves), json.dumps(k.get("tags", [])), "{}", item_id, 0, 0))
    for c in cves:
        db.execute("INSERT OR IGNORE INTO cve(id) VALUES(?)", (c,))


def add_ms(db, cve, cvss, severity="Important"):
    db.execute("INSERT INTO msrc(cve, release, released, title, tag, severity, impact, exploited, disclosed, likelihood, cvss, action)"
               " VALUES(?,?,?,?,?,?,?,0,0,?,?,0)", (cve, "2026-Oct", "2026-10-13", "T", "Windows Thing", severity, "RCE", "Less", cvss))


def test_microsoft_score_used_until_nvd_has_one():
    db = fresh()
    add_item(db, "ms:CVE-2026-1", "msrc", ["CVE-2026-1"], tags=["Windows Thing"])
    add_ms(db, "CVE-2026-1", 9.8)
    st = app.build_state(db)
    v = next(x for x in st["vulns"] if x["id"] == "ms:CVE-2026-1")
    assert v["cvss"] == 9.8 and v["group"] == "soon", (v["cvss"], v["group"])
    c = next(i for i in st["items"] if i["id"] == "ms:CVE-2026-1")["cves"][0]
    assert c["cvssFrom"] == "Microsoft", c.get("cvssFrom")
    db.execute("UPDATE cve SET cvss=7.1 WHERE id='CVE-2026-1'")
    st = app.build_state(db)
    v = next(x for x in st["vulns"] if x["id"] == "ms:CVE-2026-1")
    c = next(i for i in st["items"] if i["id"] == "ms:CVE-2026-1")["cves"][0]
    assert v["cvss"] == 7.1 and "cvssFrom" not in c, (v["cvss"], c.get("cvssFrom"))


def test_fortinet_score_used():
    db = fresh()
    add_item(db, "fn:FG-1", "fortinet", ["CVE-2026-2"], tags=["FortiOS"])
    db.execute("INSERT INTO fortinet(id, title, link, published, cvss, products, cves, exploited, summary) VALUES('FG-1','t','https://x/fn:FG-1','2026-11-01',8.1,?, 'CVE-2026-2',0,'s')", (json.dumps(["FortiOS"]),))
    row = db.execute("SELECT * FROM fortinet WHERE id='FG-1'").fetchone()
    db.execute("UPDATE items SET extra=? WHERE id='fn:FG-1'", (json.dumps(app.FN.info(row)),))
    st = app.build_state(db)
    c = next(i for i in st["items"] if i["id"] == "fn:FG-1")["cves"][0]
    assert c["cvss"] == 8.1 and c["cvssFrom"] == "Fortinet", c
    assert next(v for v in st["vulns"] if v["id"] == "fn:FG-1")["cvss"] == 8.1


def enrich_nvd_calls(db):
    f = app.Fetcher(db)
    calls = []

    async def nvd(c):
        calls.append(c)
        db.execute("UPDATE cve SET nvd_at=? WHERE id=?", (app.now(), c))

    async def tracker(c):
        return True

    async def noop(*a, **k):
        return 0

    async def get(*a, **k):
        return {"data": []}

    real = asyncio.sleep

    async def fast(_):
        await real(0)

    app.asyncio.sleep = fast
    app.X.refresh_series = noop
    app.X.refresh_poc = noop
    app.X.refresh_ms_poc = noop
    f.nvd_one, f.ubuntu_one, f.get, f.session = nvd, tracker, get, object()

    async def osv(c):
        return None

    f.osv_priority = osv
    asyncio.run(f.enrich())
    return calls


def test_nvd_covers_every_source_but_ubuntu_notices():
    db = fresh()
    for i, s in enumerate(("zerowire", "kev", "vulncheck", "msrc", "truenas", "fortinet", "ubuntu")):
        add_item(db, f"{s}:x", s, [f"CVE-2026-{1000 + i}"])
    calls = enrich_nvd_calls(db)
    assert set(calls) == {f"CVE-2026-{1000 + i}" for i in range(6)}, calls


def test_nvd_batch_is_capped_and_catches_up_never_looked_up_first():
    db = fresh()
    ids = [f"CVE-2026-{20000 + i}" for i in range(90)]
    for c in ids:
        add_item(db, f"vc:{c}", "vulncheck", [c])
    first = enrich_nvd_calls(db)
    second = enrich_nvd_calls(db)
    third = enrich_nvd_calls(db)
    assert len(first) == 40 and len(second) == 40 and len(third) == 10, (len(first), len(second), len(third))
    assert set(first) | set(second) | set(third) == set(ids)


def test_ubuntu_tracker_still_only_for_briefings_and_kev():
    db = fresh()
    add_item(db, "vc:y", "vulncheck", ["CVE-2026-3000"])
    f_calls = []
    f = app.Fetcher(db)

    async def nvd(c):
        pass

    async def tracker(c):
        f_calls.append(c)
        return True

    async def noop(*a, **k):
        return 0

    async def get(*a, **k):
        return {"data": []}

    async def osv(c):
        return None

    f.nvd_one, f.ubuntu_one, f.get, f.session, f.osv_priority = nvd, tracker, get, object(), osv
    asyncio.run(f.enrich())
    assert f_calls == [], f_calls


helpers.run_tests(globals())
