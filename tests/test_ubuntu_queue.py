"""Heads Up: tracker lookups must not starve behind CVEs that hang. Runs the real enrich()."""
import asyncio
import json
import sqlite3
import sys

import helpers
import app  # noqa: E402

TARGET = "CVE-2026-98432"
HANGING = [f"CVE-2026-{n}" for n in range(11000, 11026)]  # sort before the target


def make_fetcher(failing, target_source="zerowire"):
    db = sqlite3.connect(":memory:", isolation_level=None)
    db.row_factory = sqlite3.Row
    db.executescript(app.SCHEMA)

    def add_item(item_id, source, cve):
        db.execute("INSERT INTO items(id, source, cves, active) VALUES(?,?,?,1)", (item_id, source, json.dumps([cve])))

    for c in HANGING:
        add_item(f"kev:{c}", "kev", c)
    add_item("target", target_source, TARGET)

    f = app.Fetcher(db)
    calls = []

    async def lookup(c):
        calls.append(c)
        if c in failing:
            return False
        db.execute("UPDATE cve SET ubuntu_at=? WHERE id=?", (app.now(), c))
        return True

    async def noop(*a, **k):
        return 0

    async def get(*a, **k):
        return {"data": []}

    f.ubuntu_one = lookup
    f.nvd_one = noop
    f.get = get
    f.session = object()
    app.X.refresh_series = noop
    app.X.refresh_poc = noop
    real_sleep = asyncio.sleep

    async def fast_sleep(_):
        await real_sleep(0)

    app.asyncio.sleep = fast_sleep
    return f, calls


def rounds(f, calls, n=1):
    seen = []
    for _ in range(n):
        calls.clear()
        asyncio.run(f.enrich())
        seen.append(list(calls))
    return seen


def test_briefing_is_looked_up_first_despite_hanging_cves():
    f, calls = make_fetcher(set(HANGING))
    first = rounds(f, calls)[0]
    assert first[0] == TARGET, first[:3]


def test_failed_cves_go_to_the_back_so_every_cve_gets_reached():
    # Target not briefed and sorts last, so this is the original starvation case.
    f, calls = make_fetcher(set(HANGING), target_source="kev")
    seen = {c for r in rounds(f, calls, 4) for c in r}
    assert TARGET in seen, sorted(seen)[-3:]
    assert seen == set(HANGING) | {TARGET}


def test_stops_after_ten_failures_in_a_row():
    f, calls = make_fetcher(set(HANGING) | {TARGET})
    assert len(rounds(f, calls)[0]) == 10


def test_a_success_resets_the_failure_count_and_clears_the_record():
    f, calls = make_fetcher(set())
    f.ubuntu_failed[TARGET] = app.now()
    rounds(f, calls)
    assert TARGET not in f.ubuntu_failed
    assert TARGET in calls


def test_blank_errors_get_a_name():
    db = sqlite3.connect(":memory:", isolation_level=None)
    db.executescript(app.SCHEMA)
    app.source_err(db, "x", TimeoutError())
    assert db.execute("SELECT error FROM sources").fetchone()[0] == "TimeoutError"
    app.source_err(db, "x", RuntimeError("HTTP 500"))
    assert db.execute("SELECT error FROM sources").fetchone()[0] == "HTTP 500"


helpers.run_tests(globals())
