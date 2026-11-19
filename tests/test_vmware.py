"""VMware vCenter / ESXi versions on What we run against the ranges in VMware's CVE records."""
import asyncio
import json

import helpers
import app  # noqa: E402
import versions as VS  # noqa: E402
import vmware as VM  # noqa: E402

# real records (trimmed): CVE-2026-123890 = vCenter auth bypass, CVE-2026-47876 = ESX
VC_REC = json.loads((helpers.FIXTURES / "vmware-CVE-2026-123890.json").read_text())
ESX_REC = json.loads((helpers.FIXTURES / "vmware-CVE-2026-47876.json").read_text())
VC = {"name": "Broadcom VMware vCenter", "terms": ["VMware vCenter", "vCenter"]}
ESX = {"name": "Broadcom VMware ESXi", "terms": ["VMware ESXi", "VMware ESX", "ESXi"]}


def note(entry, version, record):
    return VM.check({**entry, "version": version}, VM.parse_ranges(record))


def st(entry, version, record):
    n = note(entry, version, record)
    return n["state"], n["fix"]


def test_ranges_from_the_cve_record():
    vc = VM.parse_ranges(VC_REC)
    assert [(r["kind"], r["line"], r["upto"]) for r in vc] == [
        ("vcenter", [9, 1], "9.1.1.0200"), ("vcenter", [9, 0], "9.0.2.0200"),
        ("vcenter", [8, 0], "8.0 U3m"), ("vcenter", [5], "5.2.5")]
    esx = VM.parse_ranges(ESX_REC)
    assert ("esxi", [8, 0], "ESXi80U3k-25595708") in [(r["kind"], r["line"], r["upto"]) for r in esx]
    assert all(r["kind"] == "esxi" for r in esx)   # Cloud Foundation / Telco rows left out
    assert VM.parse_ranges(None) == [] and VM.parse_ranges({}) == []


def test_vcenter_update_letters_and_appliance_numbers():
    assert st(VC, "8.0.3.01200", VC_REC) == ("fixed", "8.0 U3m")      # what we run: 8.0 U3m
    assert st(VC, "8.0.3.01200 (U3m)", VC_REC)[0] == "fixed"
    assert st(VC, "8.0 U3m", VC_REC)[0] == "fixed"
    assert st(VC, "8.0 Update 3m", VC_REC)[0] == "fixed"
    assert st(VC, "8.0U3m", VC_REC)[0] == "fixed"
    assert st(VC, "8.0 U3k", VC_REC) == ("upgrade", "8.0 U3m")
    assert st(VC, "8.0.3.01000", VC_REC) == ("upgrade", "8.0 U3m")    # U3k
    assert st(VC, "8.0.3.00600", VC_REC)[0] == "upgrade"              # U3g (there was no U3f)
    assert st(VC, "8.0 U2e", VC_REC)[0] == "upgrade"                  # older update branch


def test_vcenter_never_guesses():
    assert st(VC, "8.0.3.01100", VC_REC) == ("line", "8.0 U3m")       # not in the table: check by hand
    assert st(VC, "8.0", VC_REC) == ("line", "8.0 U3m")
    assert st(VC, "8.0 U4", VC_REC)[0] == "line"                      # newer branch, not listed
    assert st(VC, "7.0 U3s", VC_REC) == ("unlisted", None)


def test_vcenter_9_compares_numbers():
    assert st(VC, "9.1.1.0200", VC_REC)[0] == "fixed"
    assert st(VC, "9.1.0.0300", VC_REC) == ("upgrade", "9.1.1.0200")
    assert st(VC, "9.0.2.0200", VC_REC)[0] == "fixed"


def test_esxi_build_numbers():
    assert st(ESX, "8.0 U3k build 25595708", ESX_REC) == ("fixed", "ESXi80U3k-25595708")
    assert st(ESX, "ESXi80U3k-25595708", ESX_REC)[0] == "fixed"
    assert st(ESX, "8.0 build 25700000", ESX_REC)[0] == "fixed"
    assert st(ESX, "8.0 U3j build 25429389", ESX_REC)[0] == "upgrade"
    assert st(ESX, "8.0 U3k", ESX_REC)[0] == "fixed"                  # letters when there's no build
    assert st(ESX, "8.0 U3j", ESX_REC)[0] == "upgrade"
    assert st(ESX, "9.0.2.0100", ESX_REC)[0] == "fixed"
    # a bare build can't say which line (9.0 and 8.0 builds overlap): asks for it
    n = note(ESX, "25595708", ESX_REC)
    assert n["state"] == "needline"
    text = "".join(t for t, _ in VS.why({"fixed": False, "notes": [n]}))
    assert "add the release line" in text and "8.0 U3k build 25595708" in text, text


def test_only_the_matching_product():
    assert note(ESX, "8.0 U3k build 25595708", VC_REC) is None      # vCenter record, ESXi entry
    assert note({"name": "FortiGate", "terms": ["FortiOS"], "version": "7.4.13"}, "7.4.13", VC_REC) is None
    assert note(VC, "", VC_REC)["state"] == "noversion"


def test_check_and_why():
    vm = VM.parse_ranges(VC_REC)
    r = VS.check([{**VC, "version": "8.0.3.01200"}], [], [], [], vm)
    assert r["fixed"]
    assert "Broadcom VMware vCenter 8.0.3.01200 (fix 8.0 U3m)" in "".join(t for t, _ in VS.why_done(r))
    r = VS.check([{**VC, "version": "8.0 U3k"}], [], [], [], vm)
    assert not r["fixed"]
    assert "".join(t for t, _ in VS.why(r)) == " You run Broadcom VMware vCenter 8.0 U3k: upgrade to 8.0 U3m."
    r = VS.check([{**VC, "version": "8.0"}], [], [], [], vm)
    assert "check it's on 8.0 U3m or later" in "".join(t for t, _ in VS.why(r))
    r = VS.check([{**VC, "version": "7.0 U3s"}], [], [], [], vm)
    assert "VMware lists no fix for the 7.0 line" in "".join(t for t, _ in VS.why(r))


# --- the lookup and build_state ------------------------------------------------------

def fresh():
    db = app.db_open()
    for t in ("items", "cve", "vmware_cve", "triage", "inventory"):
        db.execute(f"DELETE FROM {t}")
    db.execute("INSERT INTO items(id, source, title, link, published, updated, category, headline, summary, body, cves, tags, extra, fingerprint, first_seen, changed_at, active)"
               " VALUES('vc:CVE-2026-123890','vulncheck','VMware vCenter','https://x/1','2026-11-19','2026-11-19','','','auth bypass','','[\"CVE-2026-123890\"]','[\"telco_cloud_infrastructure\"]','{}','x',0,0,1)")
    db.execute("INSERT INTO items(id, source, title, link, published, updated, category, headline, summary, body, cves, tags, extra, fingerprint, first_seen, changed_at, active)"
               " VALUES('kev:CVE-2026-1','kev','Microsoft Windows','https://x/2','2026-11-19','2026-11-19','','','x','','[\"CVE-2026-1\"]','[\"Windows\"]','{}','x',0,0,1)")
    db.execute("INSERT OR IGNORE INTO cve(id) VALUES('CVE-2026-123890')")
    return db


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
    def __init__(self, records):
        self.records, self.asked = records, []

    def get(self, url, **kw):
        cve = url.rsplit("/", 1)[-1]
        self.asked.append(cve)
        return FakeResponse(200, self.records[cve]) if cve in self.records else FakeResponse(404, None)


def test_lookup_only_vmware_items_and_only_once():
    db = fresh()
    s = FakeSession({"CVE-2026-123890": VC_REC})
    assert asyncio.run(VM.lookup(db, s)) == 1
    assert s.asked == ["CVE-2026-123890"]          # the Windows item isn't asked about
    s2 = FakeSession({})
    asyncio.run(VM.lookup(db, s2))
    assert s2.asked == []                           # read again only after a week
    db.execute("UPDATE vmware_cve SET looked = looked - 8 * 86400")
    asyncio.run(VM.lookup(db, s2))
    assert s2.asked == ["CVE-2026-123890"]
    # a record with nothing for us is kept as a miss; the earlier ranges are replaced
    assert VM.cve_ranges(db, ["CVE-2026-123890"]) == {}


def test_build_state_closes_the_item():
    db = fresh()
    asyncio.run(VM.lookup(db, FakeSession({"CVE-2026-123890": VC_REC})))
    v = next(v for v in app.build_state(db, [{**VC, "version": "8.0.3.01200"}])["vulns"] if v["id"] == "vc:CVE-2026-123890")
    assert v["autoDone"] and v["group"] == "done", v["group"]
    v = next(v for v in app.build_state(db, [{**VC, "version": "8.0 U3k"}])["vulns"] if v["id"] == "vc:CVE-2026-123890")
    assert not v["autoDone"] and v["group"] != "done"
    assert "upgrade to 8.0 U3m" in "".join(t for t, _ in v["why"])


helpers.run_tests(globals())
