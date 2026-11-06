"""The nightly copy is usable, private, pruned, and never replaced by a bad one."""
import os
import sqlite3
import stat
import tempfile
from datetime import date, timedelta
from pathlib import Path

import helpers
import app
import backups as BK


opened = []


def setup():
    for old in opened:  # as stopping the service would
        old.close()
    opened.clear()
    db = app.db_open()
    opened.append(db)
    db.execute("DELETE FROM triage")
    db.execute("INSERT INTO triage VALUES('zw:x', 'patched', 'done', 'Someone', 1.0)")
    return db, app.STATE / "heads-up.db", Path(tempfile.mkdtemp(prefix="heads-up-backup-"))


def test_copy_contains_the_data_and_passes_a_check():
    db, path, out = setup()
    BK.run(path, out, today=date(2026, 11, 6))
    copy = sqlite3.connect(out / "heads-up-2026-11-06.db")
    assert copy.execute("SELECT state FROM triage WHERE item_id='zw:x'").fetchone()[0] == "patched"
    assert copy.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def test_includes_writes_not_yet_checkpointed():
    db, path, out = setup()
    db.execute("INSERT OR REPLACE INTO triage VALUES('zw:y', 'investigating', '', 'Someone', 2.0)")
    assert Path(str(path) + "-wal").exists()
    BK.run(path, out, today=date(2026, 11, 6))
    assert sqlite3.connect(out / "heads-up-2026-11-06.db").execute("SELECT 1 FROM triage WHERE item_id='zw:y'").fetchone()


def test_copies_are_private():
    _, path, out = setup()
    BK.run(path, out, today=date(2026, 11, 6))
    assert stat.S_IMODE(os.stat(out / "heads-up-2026-11-06.db").st_mode) == 0o600


def test_keeps_seven_and_drops_the_oldest():
    _, path, out = setup()
    start = date(2026, 11, 1)
    for i in range(10):
        kept = BK.run(path, out, today=start + timedelta(days=i))
    names = sorted(p.name for p in out.glob("*.db"))
    assert kept == 7 and len(names) == 7, names
    assert names[0] == "heads-up-2026-11-04.db" and names[-1] == "heads-up-2026-11-10.db", names


def test_same_day_replaces_rather_than_piling_up():
    _, path, out = setup()
    BK.run(path, out, today=date(2026, 11, 6))
    assert BK.run(path, out, today=date(2026, 11, 6)) == 1


def test_a_failed_backup_leaves_the_last_good_one():
    _, path, out = setup()
    BK.run(path, out, today=date(2026, 11, 6))
    bad = out / "not-a-database"
    bad.write_bytes(b"this is not sqlite" * 400)
    try:
        BK.run(bad, out, today=date(2026, 11, 7))
    except sqlite3.DatabaseError:
        pass
    else:
        raise AssertionError("should have failed")
    assert sorted(p.name for p in out.glob("heads-up-*")) == ["heads-up-2026-11-06.db"]


def test_restoring_gives_back_the_statuses():
    db, path, out = setup()
    BK.run(path, out, today=date(2026, 11, 6))
    db.execute("DELETE FROM triage")
    db.close()
    opened.clear()
    for suffix in ("-wal", "-shm"):
        Path(str(path) + suffix).unlink(missing_ok=True)
    path.write_bytes((out / "heads-up-2026-11-06.db").read_bytes())
    assert app.db_open().execute("SELECT state FROM triage WHERE item_id='zw:x'").fetchone()[0] == "patched"


helpers.run_tests(globals())
