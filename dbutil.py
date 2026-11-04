"""SQLite helpers.

batch(db): run a block of writes as one transaction (a SAVEPOINT, so blocks
can nest). Without it, every INSERT/UPDATE is its own transaction and waits
for the disk; on a slow disk thousands of those stall the whole server.
Never hold a batch open across an `await`: other requests would then share
(and on error, lose) the open transaction.
"""
import itertools
from contextlib import contextmanager

_names = itertools.count(1)


@contextmanager
def batch(db):
    name = f"sp{next(_names)}"
    db.execute(f"SAVEPOINT {name}")
    try:
        yield
    except BaseException:
        db.execute(f"ROLLBACK TO {name}")
        db.execute(f"RELEASE {name}")
        raise
    db.execute(f"RELEASE {name}")
