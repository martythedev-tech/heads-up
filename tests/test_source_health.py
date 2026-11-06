"""When a source counts as down, and that each incident alerts once."""
import asyncio
import json
import os
import sqlite3
import sys

import helpers
import app
import health as H
import users as U
import webhooks as W

KEY = "00" * 32
T = 1_800_000_000
HOUR = 3600


def fresh():
    db = app.db_open()
    U.Users(db)  # creates the meta table, as the app does at start
    db.execute("DELETE FROM sources")
    db.execute("DELETE FROM meta WHERE key IN ('source_health', 'source_event_adopted')")
    return db


def set_source(db, name, ok_at=None, err_at=None, error=None):
    db.execute("INSERT OR REPLACE INTO sources(name, ok_at, err_at, error, count) VALUES(?,?,?,?,1)", (name, ok_at, err_at, error))


def test_healthy_source_is_quiet():
    db = fresh()
    set_source(db, "zerowire", ok_at=T - 60)
    assert H.update(db, T) == ({}, {})


def test_one_failure_doesnt_alert_but_one_that_lasts_does():
    db = fresh()
    set_source(db, "zerowire", ok_at=T - 10, err_at=T, error="timeout")
    assert H.update(db, T)[0] == {}
    set_source(db, "zerowire", ok_at=T - 10, err_at=T + HOUR - 10, error="timeout")
    assert H.update(db, T + HOUR - 10)[0] == {}
    newly, _ = H.update(db, T + HOUR)
    assert "zerowire" in newly and "timeout" in newly["zerowire"], newly


def test_slow_sources_get_a_retry_before_alerting():
    db = fresh()
    set_source(db, "msrc", ok_at=T - 100, err_at=T, error="blip")
    H.update(db, T)
    assert H.update(db, T + 8 * HOUR)[0] == {}
    assert "msrc" in H.update(db, T + 9 * HOUR)[0]


def test_failure_that_clears_resets_the_clock():
    db = fresh()
    set_source(db, "zerowire", ok_at=T - 10, err_at=T, error="blip")
    H.update(db, T)
    set_source(db, "zerowire", ok_at=T + 900, err_at=T)
    H.update(db, T + 900)
    set_source(db, "zerowire", ok_at=T + 900, err_at=T + 1000, error="blip")
    H.update(db, T + 1000)
    assert H.update(db, T + 1000 + HOUR - 60)[0] == {}


def test_format_change_counts_as_failing_even_though_the_fetch_worked():
    # zero_wire records success then the error, in the same moment.
    db = fresh()
    set_source(db, "zerowire", ok_at=T, err_at=T, error="Cloudflare's feed format changed")
    H.update(db, T)
    newly, _ = H.update(db, T + HOUR)
    assert "format changed" in newly["zerowire"], newly


def test_gone_quiet_alerts():
    db = fresh()
    set_source(db, "kev", ok_at=T)
    assert H.update(db, T + 6 * HOUR)[0] == {}
    newly, _ = H.update(db, T + 7 * HOUR)
    assert "no update for 7 hours" in newly["kev"], newly


def test_on_demand_sources_can_be_quiet():
    db = fresh()
    set_source(db, "nvd", ok_at=T - 100 * HOUR)
    set_source(db, "poc", ok_at=T - 100 * HOUR)
    assert H.update(db, T) == ({}, {})


def test_alerts_once_then_says_when_it_recovers():
    db = fresh()
    set_source(db, "kev", ok_at=T - 10 * HOUR)
    assert "kev" in H.update(db, T)[0]
    assert H.update(db, T + 60) == ({}, {})
    set_source(db, "kev", ok_at=T + 120)
    newly, recovered = H.update(db, T + 120)
    assert not newly and "kev" in recovered


def test_state_survives_a_restart():
    db = fresh()
    set_source(db, "kev", ok_at=T - 10 * HOUR)
    H.update(db, T)
    db.close()
    assert H.update(app.db_open(), T + 60) == ({}, {})


def test_removed_optional_source_recovers_instead_of_alerting_forever():
    db = fresh()
    set_source(db, "vulncheck", ok_at=T - 100 * HOUR)
    assert "vulncheck" in H.update(db, T)[0]
    db.execute("DELETE FROM sources WHERE name='vulncheck'")
    assert "vulncheck" in H.update(db, T + 60)[1]


def test_per_cve_lookups_never_alert():
    db = fresh()
    set_source(db, "ubuntu-cve", ok_at=T - 100 * HOUR, err_at=T, error="CVE-1: TimeoutError")
    set_source(db, "enrich", err_at=T - 100 * HOUR, error="old")
    H.update(db, T)
    assert H.update(db, T + 100 * HOUR) == ({}, {})


def test_message_words():
    title, body = H.message({"kev": "CISA: no update for 7 hours"}, {})
    assert title == "Heads Up: CISA stopped working" and "last good data" in body
    title, _ = H.message({}, {"kev": "x"})
    assert title == "Heads Up: CISA working again"
    assert H.message({}, {}) is None


def fake_app(db):
    class Fetcher:
        rounds = 1

    hooks = W.Webhooks(db, KEY, "https://example.invalid")
    sent = []

    async def post(row, event, title, body):
        sent.append((event, title))
        return True, "HTTP 200"

    hooks.post = post
    db.execute("DELETE FROM webhooks")
    return {"db": db, "hooks": hooks, "fetcher": Fetcher()}, sent, hooks


def add_hook(db, hooks, events):
    return hooks.save({"name": "x", "kind": "json", "url": "https://example.invalid/x", "events": events}, "test")


def test_check_sources_sends_to_webhooks_that_want_it():
    db = fresh()
    a, sent, hooks = fake_app(db)
    add_hook(db, hooks, ["source"])
    add_hook(db, hooks, ["act"])
    set_source(db, "kev", ok_at=app.now() - 10 * HOUR)
    asyncio.run(app.check_sources(a))
    assert sent == [("source", "Heads Up: CISA stopped working")], sent
    asyncio.run(app.check_sources(a))
    assert len(sent) == 1, sent


def test_check_sources_waits_out_the_first_round():
    db = fresh()
    a, sent, hooks = fake_app(db)
    add_hook(db, hooks, ["source"])
    a["fetcher"].rounds = 0
    set_source(db, "kev", ok_at=app.now() - 10 * HOUR)
    asyncio.run(app.check_sources(a))
    assert not sent


def test_existing_webhooks_adopt_the_event_once_and_unticking_sticks():
    db = fresh()
    _, _, hooks = fake_app(db)
    wid = add_hook(db, hooks, ["act"])
    hooks.adopt_source_event()
    events = lambda: json.loads(db.execute("SELECT events FROM webhooks WHERE id=?", (wid,)).fetchone()[0])
    assert events() == ["act", "source"], events()
    db.execute("UPDATE webhooks SET events='[\"act\"]' WHERE id=?", (wid,))
    hooks.adopt_source_event()
    assert events() == ["act"], events()


def test_new_webhooks_get_it_by_default():
    assert "source" in W.DEFAULT_EVENTS and "source" in W.EVENTS and "source" in W.ICONS and "source" in W.COLORS


helpers.run_tests(globals())
