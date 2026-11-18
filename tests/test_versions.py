"""The versions on What we run against Fortinet's and TrueNAS's fixed versions."""
import json

import helpers
import app  # noqa: E402
import versions as VS  # noqa: E402

FIXES = ["FortiAnalyzer 8.0: Upgrade to 8.0.2 or above",
         "FortiAnalyzer 7.6: Upgrade to 7.6.8 or above",
         "FortiAnalyzer 7.4: Upgrade to upcoming 7.4.12 or above",
         "FortiAnalyzer 7.2: Migrate to a fixed release",
         "FortiAnalyzer Cloud 7.6: Upgrade to 7.6.9 or above"]
FAZ = {"name": "FortiAnalyzer", "terms": ["FortiAnalyzer"]}


def run(version, fixes=FIXES, entry=FAZ):
    return VS.check([{**entry, "version": version}], VS.fortinet_fixes(fixes))


def states(r):
    return [(n["version"], n["state"], n["fix"]) for n in r["notes"]]


def test_parse_versions():
    assert VS.parse("7.4.8, 7.6.3") == ["7.4.8", "7.6.3"]
    assert VS.parse("v7.4.8 build 2795; 7.4.8") == ["7.4.8"]
    assert VS.parse("") == [] and VS.parse("latest") == []
    assert VS.parse("25.10.2.1") == ["25.10.2.1"]


def test_fortinet_lines_parse():
    f = VS.fortinet_fixes(FIXES + ["something else entirely"])
    assert len(f) == 5
    assert f[2] == {"product": "FortiAnalyzer", "line": (7, 4), "fixed": "7.4.12", "upcoming": True,
                    "migrate": False, "vendor": "Fortinet"}
    assert f[3]["migrate"] and f[3]["fixed"] is None
    assert f[4]["product"] == "FortiAnalyzer Cloud"


def test_fixed_when_at_or_above_the_fix():
    assert run("7.6.8")["fixed"] and run("7.6.10")["fixed"]
    assert states(run("7.6.10")) == [("7.6.10", "fixed", "7.6.8")]


def test_numbers_compare_as_numbers_not_text():
    assert not run("7.6.7")["fixed"]
    assert run("7.6.10")["fixed"]          # 10 > 8, though "10" < "8" as text


def test_older_upcoming_migrate_and_unlisted_stay_open():
    assert states(run("7.6.3")) == [("7.6.3", "upgrade", "7.6.8")]
    assert states(run("7.4.8")) == [("7.4.8", "upcoming", "7.4.12")]
    assert states(run("7.2.9")) == [("7.2.9", "migrate", None)]
    assert states(run("7.0.1")) == [("7.0.1", "unlisted", None)]
    for v in ("7.6.3", "7.4.8", "7.2.9", "7.0.1"):
        assert not run(v)["fixed"], v


def test_every_version_must_be_fixed():
    assert not run("7.6.9, 7.4.8")["fixed"]
    assert run("7.6.9, 8.0.2")["fixed"]


def test_cloud_line_is_not_yours():
    # the FortiAnalyzer Cloud line must not stand in for FortiAnalyzer
    assert states(run("7.6.8")) == [("7.6.8", "fixed", "7.6.8")]


def test_no_version_or_no_fix_data_decides_nothing():
    assert run("") is None
    assert VS.check([{**FAZ, "version": "7.6.9"}], VS.fortinet_fixes(["FortiOS 7.6: Upgrade to 7.6.5 or above"])) is None


def test_other_matched_product_without_data_keeps_it_open():
    linux = {"name": "Linux", "terms": ["Linux"], "version": "6.8.0"}
    r = VS.check([{**FAZ, "version": "7.6.9"}, linux], VS.fortinet_fixes(FIXES))
    assert not r["fixed"]


def test_fortigate_entry_matches_fortios_lines():
    fg = {"name": "FortiGate", "terms": ["FortiGate", "FortiOS"], "version": "7.4.9"}
    assert VS.check([fg], VS.fortinet_fixes(["FortiOS 7.4: Upgrade to 7.4.9 or above"]))["fixed"]


def test_truenas_fixed_in():
    f = VS.truenas_fixes("TrueNAS SCALE 25.10.8 and later (25.10 train)")
    assert f == [{"product": "TrueNAS", "line": (25, 10), "fixed": "25.10.8", "upcoming": False,
                  "migrate": False, "vendor": "TrueNAS"}]
    tn = {"name": "TrueNAS", "terms": ["TrueNAS"]}
    assert VS.check([{**tn, "version": "25.10.8.1"}], f)["fixed"]
    assert not VS.check([{**tn, "version": "25.10.2"}], f)["fixed"]
    assert states(VS.check([{**tn, "version": "25.04.2"}], f)) == [("25.04.2", "unlisted", None)]


# --- through build_state, as the page and the webhooks see it ----------------------

def fresh():
    db = app.db_open()
    for t in ("items", "cve", "fortinet", "truenas", "triage", "inventory"):
        db.execute(f"DELETE FROM {t}")
    db.execute("INSERT INTO items(id, source, title, link, published, updated, category, headline, summary, body, cves, tags, extra, fingerprint, first_seen, changed_at, active)"
               " VALUES('fn:FG-1','fortinet','FortiAnalyzer: SQL injection','https://x/1','2026-11-01','2026-11-01','','','s','','[\"CVE-2026-7\"]','[\"FortiAnalyzer\"]','{}','x',0,0,1)")
    db.execute("INSERT OR IGNORE INTO cve(id) VALUES('CVE-2026-7')")
    db.execute("INSERT INTO fortinet(id, title, link, published, cvss, products, cves, exploited, summary, fixes, kind)"
               " VALUES('FG-1','t','https://x/1','2026-11-01',8.1,?,'CVE-2026-7',0,'s',?,'advisory')",
               (json.dumps(["FortiAnalyzer"]), json.dumps(FIXES)))
    row = db.execute("SELECT * FROM fortinet WHERE id='FG-1'").fetchone()
    db.execute("UPDATE items SET extra=? WHERE id='fn:FG-1'", (json.dumps(app.FN.info(row)),))
    return db


def vuln(db, version):
    inv = [{**FAZ, "version": version}]
    return next(v for v in app.build_state(db, inv)["vulns"] if v["id"] == "fn:FG-1")


def why(v):
    return "".join(t for t, _ in v["why"])


def test_fixed_version_moves_to_done_with_reason():
    v = vuln(fresh(), "7.6.9")
    assert v["group"] == "done" and v["autoDone"], v["group"]
    assert why(v) == "Fixed in the version you run: FortiAnalyzer 7.6.9 (fix 7.6.8).", why(v)


def test_older_version_stays_open_and_says_what_to_do():
    v = vuln(fresh(), "7.6.3")
    assert v["group"] == "soon" and not v["autoDone"], v["group"]
    assert "You run FortiAnalyzer 7.6.3: upgrade to 7.6.8." in why(v), why(v)
    assert "Fortinet fix:" not in why(v)


def test_no_version_keeps_the_old_behaviour():
    v = vuln(fresh(), "")
    assert v["group"] == "soon" and v["versionCheck"] is None
    assert "Fortinet fix: FortiAnalyzer 8.0: Upgrade to 8.0.2 or above." in why(v), why(v)


def test_a_status_someone_set_wins():
    db = fresh()
    db.execute("INSERT INTO triage VALUES('fn:FG-1','investigating','','camron',0)")
    v = vuln(db, "7.6.9")
    assert v["group"] != "done" and not v["autoDone"]
    db.execute("UPDATE triage SET state='untriaged'")
    assert vuln(db, "7.6.9")["group"] == "done"


helpers.run_tests(globals())
