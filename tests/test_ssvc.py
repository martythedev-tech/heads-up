"""CISA's SSVC rating, read from the CVE records."""
import asyncio
import json

import helpers
import app  # noqa: E402
import ssvc as SSVC  # noqa: E402
import vulns as V  # noqa: E402
import webhooks as W  # noqa: E402

# real record (trimmed to its ADP containers): CVE-2024-3400, PAN-OS GlobalProtect
REC = json.loads((helpers.FIXTURES / "cve-2024-3400-record.json").read_text())
NONE = {"exploitation": "none", "automatable": "no", "impact": "partial", "at": None}


class FakeResponse:
    def __init__(self, status, body):
        self.status, self.body = status, body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def json(self, content_type=None):
        return self.body


class FakeSession:
    def __init__(self, records, status=200):
        self.records, self.status, self.asked = records, status, []

    def get(self, url, **kw):
        cve = url.rsplit("/", 1)[-1]
        self.asked.append(cve)
        if self.status != 200:
            return FakeResponse(self.status, None)
        return FakeResponse(200, self.records[cve]) if cve in self.records else FakeResponse(404, None)


def fresh():
    db = app.db_open()
    for t in ("items", "cve", "kev", "ssvc_cve"):
        db.execute(f"DELETE FROM {t}")
    return db


def why(v):
    return "".join(t for t, _ in v["why"])


def add_item(db, item_id, source, cves, title="Example Product"):
    db.execute("INSERT INTO items(id, source, title, link, published, updated, category, headline, summary, body, cves, tags, extra, fingerprint, first_seen, changed_at, active)"
               " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)",
               (item_id, source, title, "https://x/" + item_id, "2026-11-01", "2026-11-01", "", "", "s", "", json.dumps(cves),
                "[]", "{}", item_id, 0, 0))
    for c in cves:
        db.execute("INSERT OR IGNORE INTO cve(id) VALUES(?)", (c,))


def test_reads_cisas_block_from_a_real_record():
    s = SSVC.parse(REC)
    assert (s["exploitation"], s["automatable"], s["impact"]) == ("active", "yes", "total"), s
    assert s["at"].startswith("2024-04-17")


def test_record_without_cisas_block():
    assert SSVC.parse(None) is None
    assert SSVC.parse({"containers": {"cna": {}}}) is None
    other = {"containers": {"adp": [{"providerMetadata": {"shortName": "CVE"}, "metrics": [
        {"other": {"type": "ssvc", "content": {"options": [{"Exploitation": "active"}]}}}]}]}}
    assert SSVC.parse(other) is None  # only CISA's own assessment counts


def test_lookup_reads_briefing_cves_first_once_and_batches():
    db = fresh()
    s = FakeSession({"CVE-2024-3400": REC})
    n = asyncio.run(SSVC.lookup(db, s, ["CVE-2024-3400"], ["CVE-2026-5", "CVE-2026-6"], limit=2))
    assert n == 1 and s.asked == ["CVE-2024-3400", "CVE-2026-5"], s.asked   # first group first, capped
    s2 = FakeSession({})
    asyncio.run(SSVC.lookup(db, s2, ["CVE-2024-3400"], ["CVE-2026-5", "CVE-2026-6"], limit=5))
    assert s2.asked == ["CVE-2026-6"], s2.asked                              # the rest wait their turn
    db.execute("UPDATE ssvc_cve SET looked = looked - 2 * 86400")
    s3 = FakeSession({})
    asyncio.run(SSVC.lookup(db, s3, ["CVE-2024-3400"], ["CVE-2026-5", "CVE-2026-6"], limit=5))
    assert s3.asked == ["CVE-2026-5", "CVE-2026-6"], s3.asked                # misses after a day, ratings after a week
    assert SSVC.cve_info(db, ["CVE-2024-3400", "CVE-2026-5"]) == {"CVE-2024-3400": SSVC.parse(REC)}


def test_service_down_is_reported():
    db = fresh()
    try:
        asyncio.run(SSVC.lookup(db, FakeSession({}, status=503), ["CVE-2024-3400"], []))
    except RuntimeError as e:
        assert "didn't answer" in str(e)
    else:
        raise AssertionError("a lookup where every request failed should raise")
    assert db.execute("SELECT COUNT(*) FROM ssvc_cve").fetchone()[0] == 0   # nothing stored, tried again next run


def test_worst_rating_across_cves():
    a = {"exploitation": "poc", "automatable": "no", "impact": "total"}
    b = {"exploitation": "none", "automatable": "yes", "impact": "partial"}
    assert V.worst_ssvc([a, b]) == {"exploitation": "poc", "automatable": "yes", "impact": "total"}
    assert V.worst_ssvc([]) is None
    assert V.ssvc_text({"exploitation": "active", "automatable": "yes", "impact": "total"}) == \
        "exploitation active · automatable · total impact"


def test_why_and_webhooks_name_cisas_rating():
    db = fresh()
    add_item(db, "zw:a", "zerowire", ["CVE-2024-3400"])
    add_item(db, "zw:b", "zerowire", ["CVE-2026-7"])
    asyncio.run(SSVC.lookup(db, FakeSession({"CVE-2024-3400": REC}), ["CVE-2024-3400"], []))
    db.execute("INSERT INTO ssvc_cve VALUES('CVE-2026-7', ?, 0)", (json.dumps(NONE),))
    st = app.build_state(db)
    hot = next(v for v in st["vulns"] if v["id"] == "zw:a")
    calm = next(v for v in st["vulns"] if v["id"] == "zw:b")
    assert "CISA has seen attacks" in why(hot) and "CISA: attacks can be automated" in why(hot), why(hot)
    assert "Not confirmed as exploited" not in why(hot) and "Not confirmed as exploited" in why(calm), (why(hot), why(calm))
    assert "CISA" not in why(calm), why(calm)
    assert dict(W.facts(hot))["CISA rating (SSVC)"] == "Exploitation active · automatable · total impact"
    assert dict(W.facts(calm))["CISA rating (SSVC)"] == "Exploitation none · not automatable · partial impact"
    assert W.payload("generic", "act", hot, None, "https://hu.example/")["vulnerability"]["ssvc"]["exploitation"] == "active"
    c = next(i for i in st["items"] if i["id"] == "zw:a")["cves"][0]
    assert c["ssvc"]["impact"] == "total", c


def test_grouping_is_unchanged_by_the_rating():
    db = fresh()
    add_item(db, "zw:a", "zerowire", ["CVE-2024-3400"])
    before = next(v for v in app.build_state(db)["vulns"] if v["id"] == "zw:a")["group"]
    asyncio.run(SSVC.lookup(db, FakeSession({"CVE-2024-3400": REC}), ["CVE-2024-3400"], []))
    after = next(v for v in app.build_state(db)["vulns"] if v["id"] == "zw:a")["group"]
    assert before == after, (before, after)


helpers.run_tests(globals())
