"""Broadcom VMware security advisories (VMSAs): parsing, finding new ones, and what the list does with them."""
import asyncio
import json

import helpers
import app  # noqa: E402
import vmsa as S  # noqa: E402
import vmware as VM  # noqa: E402
import versions as VS  # noqa: E402

PAGE = {n: (helpers.FIXTURES / f"broadcom-{n}.html").read_text() for n in (39626, 39625, 39445, 38017, 39627, 37454, 37513)}
CHALLENGE = (helpers.FIXTURES / "broadcom-challenge.html").read_text()
VC = {"name": "Broadcom VMware vCenter", "terms": ["VMware vCenter", "vCenter"]}
ESX = {"name": "Broadcom VMware ESXi", "terms": ["VMware ESXi", "VMware ESX", "ESXi"]}


def test_classify_pages():
    assert S.classify(200, PAGE[39626]) == "vmsa"
    assert S.classify(200, PAGE[39625]) == "vmsa"
    assert S.classify(200, PAGE[39627]) == "none"           # "Content not found!"
    assert S.classify(403, CHALLENGE) == "blocked"          # Cloudflare's browser check
    assert S.classify(200, "<html><body>Mainframe advisory MFDSA39664</body></html>") == "other"
    assert S.classify(500, "oops") is None


def test_parse_vmsa_2026_0011():
    r = S.parse(PAGE[39626], 39626)
    assert (r["id"], r["rev"], r["published"], r["updated"]) == ("VMSA-2026-0011", "VMSA-2026-0011", "2026-11-24", "2026-11-24")
    assert r["title"] == "VMware ESX, vCenter, Workstation, Fusion, Tools, and Avi Load Balancer updates address multiple vulnerabilities"
    assert r["severity"] == "Critical" and r["cvss"] == 9.8 and not r["exploited"]
    assert "VMware vCenter" in r["products"] and "VMware ESX" in r["products"]
    assert len(r["cves"]) == 23 and r["cves"][0] == "CVE-2026-123903"
    sec = {s["ref"]: s for s in r["sections"]}
    assert len(sec) == 21
    assert sec["3a"]["cves"] == ["CVE-2026-123903"] and sec["3a"]["cvss"] == 9.8
    assert sec["3a"]["title"] == "vCenter authentication-bypass vulnerability"
    assert sec["3c"]["cves"] == ["CVE-2026-123905", "CVE-2026-123906", "CVE-2026-123907"]
    assert sec["3q"]["cvss"] == 3.4 and sec["3q"]["severity"] == "Low"   # an empty <h2> anchor sits inside it
    rows = {(x["kind"], tuple(x["line"]), x["upto"]) for x in r["ranges"]}
    assert ("vcenter", (8, 0), "8.0 U3m") in rows
    assert ("esxi", (8, 0), "ESXi80U3m-25926933") in rows
    assert ("esxi", (9, 0), None) in rows                  # "Patch Pending" for two CVEs
    assert ("vcenter", (7, 0), None) in rows                # "Contact Broadcom Support"
    assert not any("Telco" in x["product"] for x in r["ranges"])
    auth = [x for x in r["ranges"] if x["kind"] == "vcenter" and x["line"] == [8, 0]][0]
    assert "CVE-2026-123903" in auth["cves"]


def test_parse_revisions_and_third_party_advisories():
    r = S.parse(PAGE[38017], 38017)
    assert (r["id"], r["rev"], r["updated"]) == ("VMSA-2026-0006", "VMSA-2026-0006.2", "2026-08-19")   # title still says .1
    fixes = {x["upto"] for x in r["ranges"]}
    assert "9.1.0.0300" in fixes                            # "[1] 9.1.0.0300": footnote dropped
    assert not any("KB" in (f or "") for f in fixes)        # "Async Patching Guide: KB88287" is no version
    r = S.parse(PAGE[39445], 39445)
    assert r["rev"] == "VMSA-2026-0008.3" and r["published"] == "2026-10-27" and r["updated"] == "2026-11-24"
    assert r["cves"] == ["CVE-2026-111497"] and r["cvss"] == 9.8
    r = S.parse(PAGE[39625], 39625)
    assert r["title"].startswith("Apache HTTP Server") and r["products"][0] == "VMware Cloud Foundation"


def test_older_page_layouts():
    # one unlettered section "3.", headings in <strong>, "(CVE-a, CVE-b and CVE-c)" in the synopsis
    r = S.parse(PAGE[37454], 37454)
    assert r["products"] == ["VMware Fusion"] and r["title"] == "VMware Fusion updates address privilege escalation vulnerability"
    assert [(s["ref"], s["cvss"], s["cves"]) for s in r["sections"]] == [("3", 7.8, ["CVE-2026-41702"])]
    r = S.parse(PAGE[37513], 37513)
    assert r["title"] == "VMware Cloud Foundation Operations updates address multiple vulnerabilities"
    assert "VMware Aria Operations" in r["products"] and r["sections"][0]["cvss"] == 8.0


def test_exploited_note():
    page = PAGE[39626].replace("Broadcom would like to thank mochazz",
                               "Broadcom has information to suggest that exploitation of CVE-2026-123903 has occurred in the wild. Broadcom would like to thank mochazz")
    r = S.parse(page, 39626)
    assert r["exploited"] and [s["ref"] for s in r["sections"] if s["exploited"]] == ["3a"]


def esx_check(version, page=39626):
    ranges = [{k: v for k, v in x.items() if k != "cves"} for x in S.parse(PAGE[page], page)["ranges"]]
    return VM.check({**ESX, "version": version}, ranges)


def test_fixes_by_update_branch():
    # VMSA-2026-0006 lists 8.0 U3k and the 8.0 U2f express patch: your branch decides
    assert esx_check("8.0 U3k build 25595708", 38017)["state"] == "fixed"
    n = esx_check("8.0 U2e build 25000000", 38017)
    assert (n["state"], n["fix"]) == ("upgrade", "ESXi80U2f-25626445")
    n = esx_check("8.0 U3j build 25429389", 38017)
    assert (n["state"], n["fix"]) == ("upgrade", "ESXi80U3k-25595708")
    # VMSA-2026-0011: the 8.0 fix is U3m; 9.0 still has a patch pending for two CVEs
    n = esx_check("8.0 U3k build 25595708")
    assert (n["state"], n["fix"]) == ("upgrade", "ESXi80U3m-25926933")
    assert esx_check("ESXi80U3m-25926933")["state"] == "fixed"
    assert esx_check("9.0.2.0200")["state"] == "affectedline"


# --- finding advisories -------------------------------------------------------------

class FakeResponse:
    def __init__(self, status, body):
        self.status, self.body = status, body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def text(self, errors=None):
        return self.body


class FakePortal:
    def __init__(self, pages):
        self.pages, self.asked = pages, []

    def get(self, url, **kw):
        n = int(url.rsplit("/", 1)[-1])
        self.asked.append(n)
        status, body = self.pages.get(n, (200, PAGE[39627]))
        return FakeResponse(status, body)


def fresh():
    db = app.db_open()
    db.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
    for t in ("items", "cve", "vmsa", "vmsa_probe", "vmware_cve", "triage", "inventory", "meta"):
        db.execute(f"DELETE FROM {t}")
    return db


def test_refresh_reads_ahead_and_stops():
    db = fresh()
    S.KNOWN[:] = [39626]
    portal = FakePortal({39626: (200, PAGE[39626]), 39630: (403, CHALLENGE), 39640: (200, PAGE[38017].replace("38017", "39640"))})
    assert asyncio.run(S.refresh(db, portal, pause=0)) == 2
    assert portal.asked[0] == 39626 and 39640 in portal.asked
    assert max(portal.asked) == 39640 + S.AHEAD_STOP       # 40 unused numbers after the newest: stop
    states = dict(db.execute("SELECT num, state FROM vmsa_probe").fetchall())
    assert states[39630] == "blocked" and states[39631] == "none"
    # next run: nothing known is read again today; only the numbers ahead
    portal2 = FakePortal({})
    asyncio.run(S.refresh(db, portal2, pause=0))
    assert portal2.asked[0] == 39641 and len(portal2.asked) == S.AHEAD_STOP
    # a day later the recent advisories are read again (revisions), and unused numbers below the newest
    db.execute("UPDATE vmsa SET looked = looked - 2 * 86400")
    db.execute("UPDATE vmsa_probe SET looked = looked - 2 * 86400")
    db.execute("UPDATE vmsa SET updated = date('now') WHERE num = 39626")
    portal3 = FakePortal({})
    asyncio.run(S.refresh(db, portal3, pause=0))
    assert portal3.asked[0] == 39626
    assert 39639 in portal3.asked and 39630 not in portal3.asked   # browser-check pages aren't pushed


def test_refresh_when_everything_wants_a_browser_check():
    db = fresh()
    S.KNOWN[:] = [39626]
    portal = FakePortal({n: (403, CHALLENGE) for n in range(39600, 39800)})
    try:
        asyncio.run(S.refresh(db, portal, pause=0))
        raise AssertionError("expected an error")
    except RuntimeError as e:
        assert "browser check" in str(e)
    assert db.execute("SELECT COUNT(*) FROM vmsa_probe WHERE state='blocked'").fetchone()[0] == 0
    assert len(portal.asked) < 10


# --- on the list --------------------------------------------------------------------

def load(db, *nums, exploited=False):
    for n in nums:
        page = PAGE[n]
        if exploited:
            page = page.replace("Broadcom would like to thank mochazz",
                                "Broadcom has information to suggest that exploitation of CVE-2026-123903 has occurred in the wild. thanks")
        S.save(db, S.parse(page, n))
    for it in S.items(db, today=__import__("datetime").date(2026, 11, 24)):
        app.upsert_item(db, {**it})
        db.executemany("INSERT OR IGNORE INTO cve(id) VALUES(?)", [(c,) for c in it["cves"]])


def vuln(db, inventory):
    return next(v for v in app.build_state(db, inventory)["vulns"] if v["id"] == "vmsa:VMSA-2026-0011")


def test_on_the_list_for_your_vmware():
    db = fresh()
    load(db, 39626)
    v = vuln(db, [{**ESX, "version": "8.0 U3k build 25595708"}, {**VC, "version": "8.0.3.01200"}])
    assert v["group"] == "soon" and set(v["ours"]) == {"Broadcom VMware ESXi", "Broadcom VMware vCenter"}
    why = "".join(t for t, _ in v["why"])
    assert "VMware advisory VMSA-2026-0011 (Critical, up to CVSS 9.8)." in why, why
    assert "upgrade to ESXi80U3m-25926933" in why, why
    assert v["cvss"] == 9.8 and "Broadcom" in v["reportedBy"]
    # everything fixed -> Done by itself
    v = vuln(db, [{**ESX, "version": "ESXi80U3m-25926933"}, {**VC, "version": "8.0.3.01200"}])
    assert v["autoDone"] and v["group"] == "done"
    # no VMware on What we run: awareness, saying so
    v = vuln(db, [{"name": "FortiGate", "terms": ["FortiGate", "FortiOS"], "version": "7.4.13"}])
    assert v["group"] == "aware" and "Not one of your VMware products" in "".join(t for t, _ in v["why"])
    # empty list: the usual severity rule (CVSS 9.8 -> Patch soon)
    assert vuln(db, [])["group"] == "soon"


def test_exploited_goes_to_act_now():
    db = fresh()
    load(db, 39626, exploited=True)
    v = vuln(db, [{**VC, "version": "8.0 U3k"}])
    assert v["exploited"] and v["exploitedBy"] == "Broadcom" and v["group"] == "act"


def test_cve_info_scores_each_cve():
    db = fresh()
    load(db, 39626)
    info = S.cve_info(db, ["CVE-2026-123903", "CVE-2026-123923", "CVE-2026-1"])
    assert info["CVE-2026-123903"]["cvss"] == 9.8 and info["CVE-2026-123923"]["cvss"] == 3.4
    assert "CVE-2026-1" not in info
    st = app.build_state(db, [])
    item = next(i for i in st["items"] if i["id"] == "vmsa:VMSA-2026-0011")
    c = next(c for c in item["cves"] if c["id"] == "CVE-2026-123923")
    assert c["cvss"] == 3.4 and c.get("cvssFrom") == "Broadcom"


class FakeHooks:
    base_url = "https://hu"

    def __init__(self):
        self.sent = []

    async def send_note(self, event, title, body, facts, link):
        self.sent.append((event, title, body, dict(facts), link))


def test_announce_new_advisories_once():
    db = fresh()
    load(db, 38017)
    hooks = FakeHooks()
    a = {"db": db, "hooks": hooks}
    asyncio.run(app.announce_vmsa(a))
    assert hooks.sent == []                                  # first run records what's there
    load(db, 39626)
    db.execute("INSERT INTO inventory(id, name, terms, version, note, by, at) VALUES('esx',?,?,?,'','t',0)",
               ("Broadcom VMware ESXi", json.dumps(ESX["terms"]), "8.0 U3k"))
    asyncio.run(app.announce_vmsa(a))
    assert len(hooks.sent) == 1
    event, title, body, facts, link = hooks.sent[0]
    assert event == "vmware" and title.startswith("VMware VMSA-2026-0011:")
    assert facts["You run"] == "Broadcom VMware ESXi", facts
    assert facts["Highest CVSS"] == "9.8" and "vCenter authentication-bypass vulnerability (9.8)" in body
    asyncio.run(app.announce_vmsa(a))
    assert len(hooks.sent) == 1


helpers.run_tests(globals())
