"""Search across everything stored, and the GitHub exploit check for Microsoft CVEs."""
import asyncio
import json
import sqlite3
import sys

import helpers
import app  # noqa: E402
import exploits as X  # noqa: E402
import msrc as MS  # noqa: E402
import search as SR  # noqa: E402

PAINT, PAINT2, SEEN = "CVE-2026-83844", "CVE-2026-70586", "CVE-2026-98432"


def make_db():
    db = sqlite3.connect(":memory:", isolation_level=None)
    db.row_factory = sqlite3.Row
    db.executescript(app.SCHEMA)
    for mod in (MS, X):
        if hasattr(mod, "migrate"):
            mod.migrate(db)
    db.executescript(app.VC.SCHEMA)
    db.executescript(app.FN.SCHEMA)

    def ms(cve, title, tag, sev, exploited=0, disclosed=0, cvss=8.1):
        db.execute("INSERT INTO msrc(cve, release, released, title, tag, severity, impact, exploited, disclosed, likelihood, cvss, action)"
                   " VALUES(?,?,?,?,?,?,?,?,?,?,?,0)",
                   (cve, "2026-Oct", "2026-10-13", title, tag, sev, "Remote Code Execution", exploited, disclosed, "Exploitation Less Likely", cvss))

    ms(PAINT, "Windows Paint Remote Code Execution Vulnerability", "Windows Paint", "Important")
    ms(PAINT2, "Windows Paint Remote Code Execution Vulnerability", "Windows Paint", "Critical", cvss=8.8)
    ms("CVE-2026-10001", "Windows Kernel Zero Day", "Windows Kernel", "Important", exploited=1)
    ms("CVE-2026-10002", "Moderate Thing", "Windows Foo", "Moderate")
    db.execute("INSERT INTO kev(cve, vendor, product, name, added, description) VALUES('CVE-2010-0028','Microsoft','Windows','Old CISA paint','2020-01-01','x')")
    db.execute("INSERT INTO vckev(cve, vendor, product, name, added, description) VALUES('CVE-2010-0029','Microsoft','Windows','MS Paint Integer Overflow','2012-10-18','x')")
    db.execute("INSERT INTO exploit_index VALUES('CVE-2011-1111', ?, '[]')", (json.dumps([{"id": "1", "title": "Paint 100% crash"}]),))
    db.execute("INSERT INTO items(id, source, title, cves, active) VALUES('zw:x','zerowire','Linux TCP',?,1)", (json.dumps([SEEN]),))
    db.execute("INSERT INTO cve(id) VALUES(?)", (SEEN,))
    return db


def ids(res):
    return [e["id"] for e in res["results"]]


def test_microsoft_paint_finds_cves_without_the_word_microsoft():
    r = SR.search(make_db(), "Microsoft Paint")
    assert PAINT in ids(r) and PAINT2 in ids(r), ids(r)


def test_newest_cve_first_and_old_sources_found():
    got = ids(SR.search(make_db(), "paint"))
    assert got == [PAINT, PAINT2, "CVE-2011-1111", "CVE-2010-0029", "CVE-2010-0028"], got


def test_every_word_must_match():
    assert ids(SR.search(make_db(), "paint kernel")) == []


def test_cve_number_is_case_insensitive_and_partial():
    assert ids(SR.search(make_db(), "cve-2026-83844")) == [PAINT]
    assert ids(SR.search(make_db(), "83844")) == [PAINT]


def test_exact_cve_comes_first_above_newer_cves_that_mention_it():
    db = make_db()
    db.execute("INSERT INTO kev(cve, vendor, product, name, added, description) VALUES('CVE-2021-45046','Apache','Log4j2','Newer','2021-12-14','incomplete fix for CVE-2021-44228')")
    db.execute("INSERT INTO kev(cve, vendor, product, name, added, description) VALUES('CVE-2021-44228','Apache','Log4j2','Log4Shell','2021-12-10','x')")
    assert ids(SR.search(db, "cve-2021-44228")) == ["CVE-2021-44228", "CVE-2021-45046"]


def test_main_list_cve_is_not_repeated_and_is_flagged():
    r = SR.search(make_db(), SEEN)
    assert ids(r) == [] and r["onMain"] is True


def test_like_wildcards_are_literal():
    assert ids(SR.search(make_db(), "100%")) == ["CVE-2011-1111"]
    assert ids(SR.search(make_db(), "%")) == ["CVE-2011-1111"]
    assert ids(SR.search(make_db(), "_")) == [], ids(SR.search(make_db(), "_"))


def test_injection_text_is_only_data():
    db = make_db()
    assert ids(SR.search(db, "'; DROP TABLE msrc; --")) == []
    assert db.execute("SELECT COUNT(*) FROM msrc").fetchone()[0] == 4


def test_result_carries_exploit_code_counts():
    db = make_db()
    db.execute("INSERT INTO cve(id, poc) VALUES(?, ?)", (PAINT, json.dumps([{"name": "a/b"}])))
    e = next(x for x in SR.search(db, "paint")["results"] if x["id"] == PAINT)
    assert e["exploitCode"]["poc"] == 1 and e["severity"] == "Important" and e["link"].startswith("https://msrc.")


def add_fortinet(db, fid, cves, link="https://fortiguard.example/" ):
    # Same storage as fortinet.py: products JSON, cves comma-separated.
    db.execute("INSERT INTO fortinet(id, title, link, published, cvss, products, cves, exploited, summary) VALUES(?,?,?,?,?,?,?,0,?)",
               (fid, f"FortiOS bug {fid}", link + fid, "2026-05-01", 7.5, json.dumps(["FortiOS"]), cves, "summary"))


def test_fortinet_rows_in_their_stored_format():
    db = make_db()
    add_fortinet(db, "FG-IR-1", "CVE-2026-20001,CVE-2026-20002")
    add_fortinet(db, "FG-IR-2", "")
    got = ids(SR.search(db, "fortios"))
    assert got == ["CVE-2026-20002", "CVE-2026-20001", "FG-IR-2"], got
    e = SR.search(db, "fortinet FG-IR-2")["results"][0]
    assert e["cvss"] == 7.5 and e["link"].endswith("FG-IR-2") and e["sources"] == ["fn"]


def test_fortinet_advisory_on_the_main_list_is_left_out():
    db = make_db()
    add_fortinet(db, "FG-IR-3", "CVE-2026-20003")
    db.execute("INSERT INTO items(id, source, title, link, cves, active) VALUES('fn:x','fortinet','x','https://fortiguard.example/FG-IR-3','[]',1)")
    assert ids(SR.search(db, "FG-IR-3")) == []


def test_cve_on_main_with_a_fortinet_statement_does_not_crash():
    db = make_db()
    add_fortinet(db, "FG-IR-4", SEEN)
    r = SR.search(db, SEEN)
    assert ids(r) == [] and r["onMain"] is True


class Resp:
    def __init__(self, status, body):
        self.status, self.body = status, body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def json(self, content_type=None):
        return self.body

    async def text(self):
        return json.dumps(self.body)


class Session:
    """Fake GitHub: Paint and a Moderate CVE are listed; `repos` is what each file holds."""

    def __init__(self, listed=None, truncated=False, status=200):
        self.listed = listed if listed is not None else [PAINT, "CVE-2026-10002"]
        self.truncated, self.status, self.calls = truncated, status, []

    def get(self, url, **k):
        self.calls.append(url)
        if url.endswith("/trees/master"):
            return Resp(self.status, {"tree": [{"path": "2026", "sha": "abc"}, {"path": "2019", "sha": "zzz"}]})
        if url.endswith("/trees/abc"):
            return Resp(200, {"truncated": self.truncated, "tree": [{"path": f"{c}.json"} for c in self.listed]})
        cve = url.rsplit("/", 1)[1].removesuffix(".json")
        return Resp(200, [{"full_name": "x/" + cve, "html_url": "https://github.com/x", "stargazers_count": 1, "created_at": "2026-11-06"}])


def items_by_id(db):
    return {i["id"]: i for i in MS.zero_day_items(db)}


def fast_sleep():
    real = asyncio.sleep

    async def s(_):
        await real(0)

    X.asyncio.sleep = s


def test_ms_poc_check_downloads_only_listed_serious_cves():
    fast_sleep()
    db, s = make_db(), Session()
    assert asyncio.run(X.refresh_ms_poc(db, s, lambda *_: None)) == 1
    assert [u for u in s.calls if u.endswith(".json")] == [X.POC_JSON.format(year="2026", cve=PAINT)], s.calls
    assert not any("zzz" in u for u in s.calls)  # only years Microsoft has CVEs for
    assert db.execute("SELECT 1 FROM cve WHERE id='CVE-2026-10002'").fetchone() is None  # Moderate: left out


def test_poc_item_joins_main_list_labelled_and_exploited_items_keep_their_fingerprint():
    fast_sleep()
    db = make_db()
    assert "ms:" + PAINT not in items_by_id(db)
    asyncio.run(X.refresh_ms_poc(db, Session(), lambda *_: None))
    items = items_by_id(db)
    it = items["ms:" + PAINT]
    assert it["category"] == "Public exploit code" and "unverified" in it["summary"] and it["fingerprint"].endswith("|poc")
    assert "ms:" + PAINT2 not in items
    assert items["ms:CVE-2026-10001"]["fingerprint"] == "2026-Oct|1|0"  # unchanged, so no false "updated" alerts
    assert "already being exploited" in items["ms:CVE-2026-10001"]["summary"]


def test_repo_taken_down_removes_the_item():
    fast_sleep()
    db = make_db()
    asyncio.run(X.refresh_ms_poc(db, Session(), lambda *_: None))
    asyncio.run(X.refresh_ms_poc(db, Session(listed=[]), lambda *_: None))
    assert "ms:" + PAINT not in items_by_id(db)


def test_github_failures_raise_and_change_nothing():
    db = make_db()
    for s in (Session(status=403), Session(truncated=True)):
        try:
            asyncio.run(X.refresh_ms_poc(db, s, lambda *_: None))
        except RuntimeError:
            pass
        else:
            raise AssertionError("should have raised")
    assert db.execute("SELECT COUNT(*) FROM cve WHERE poc IS NOT NULL").fetchone()[0] == 0


def nvd_fetcher(body=None, error=None):
    f = app.Fetcher(make_db())
    f.session = object()
    f.calls = 0

    async def get(url, **k):
        f.calls += 1
        if error:
            raise error
        return body

    f.get = get
    return f


def test_nvd_lookup_found_cached_and_rate_limited():
    fast_sleep()
    app.asyncio.sleep = X.asyncio.sleep
    body = {"vulnerabilities": [{"cve": {"published": "2026-01-02T00:00", "descriptions": [{"lang": "en", "value": "bad"}],
                                         "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL", "vectorString": "v"}}]}}}]}
    f = nvd_fetcher(body)
    a = asyncio.run(f.nvd_lookup("CVE-2026-1"))
    assert a == {"found": True, "cvss": 9.8, "severity": "CRITICAL", "published": "2026-01-02", "description": "bad"}, a
    asyncio.run(f.nvd_lookup("CVE-2026-1"))
    assert f.calls == 1
    f.nvd_last = app.now() + 60
    assert "busy" in asyncio.run(f.nvd_lookup("CVE-2026-2"))["error"]


def test_nvd_lookup_not_found_and_errors_not_cached():
    fast_sleep()
    app.asyncio.sleep = X.asyncio.sleep
    assert asyncio.run(nvd_fetcher({"vulnerabilities": []}).nvd_lookup("CVE-2026-3")) == {"found": False}
    f = nvd_fetcher(error=TimeoutError())
    assert "TimeoutError" in asyncio.run(f.nvd_lookup("CVE-2026-4"))["error"]
    assert "CVE-2026-4" not in f.nvd_cache


helpers.run_tests(globals())
