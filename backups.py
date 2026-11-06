"""Nightly copy of the database: statuses, their history, users and settings.

Each copy is made with SQLite's backup API (safe while the app is writing),
checked, and only then moved into place, so a bad copy never replaces a good
one. Stored secrets stay encrypted, and restoring needs the same settings key.
"""
import os
import sqlite3
from datetime import date
from pathlib import Path

KEEP = 7
PREFIX = "heads-up-"


def run(db_path, directory, keep=KEEP, today=None):
    """Make today's copy and drop the oldest beyond `keep`. Returns how many are kept."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    final = directory / f"{PREFIX}{(today or date.today()).isoformat()}.db"
    temp = final.with_suffix(".tmp")
    temp.unlink(missing_ok=True)
    source = sqlite3.connect(db_path)
    copy = sqlite3.connect(temp)
    try:
        os.chmod(temp, 0o600)
        source.backup(copy)
        result = copy.execute("PRAGMA quick_check").fetchone()[0]
        if result != "ok":
            raise RuntimeError(f"backup failed its check: {result}")
    except Exception:
        copy.close()
        temp.unlink(missing_ok=True)
        raise
    finally:
        source.close()
    copy.close()
    os.replace(temp, final)
    copies = sorted(directory.glob(f"{PREFIX}*.db"))
    for old in copies[:-keep]:
        old.unlink()
    return min(len(copies), keep)
