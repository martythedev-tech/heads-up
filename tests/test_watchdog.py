"""The down alert, against a fake health page and a fake webhook receiver."""
import hashlib
import hmac
import json
import sqlite3
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import helpers
import watchdog as D
import webhooks as W

KEY = "11" * 32
T = 1_800_000_000
received, health_body = [], [{"ok": True, "lastFetch": T}]
deliver_ok = [True]


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/broken":
            self.send_response(500)
            self.end_headers()
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(json.dumps(health_body[0]).encode())

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        received.append((self.path, dict(self.headers), body))
        self.send_response(200 if deliver_ok[0] else 500)
        self.end_headers()

    def log_message(self, *a):
        pass


server = HTTPServer(("127.0.0.1", 0), Handler)
PORT = server.server_address[1]
threading.Thread(target=server.serve_forever, daemon=True).start()
UP = f"http://127.0.0.1:{PORT}/api/health"
DOWN = "http://127.0.0.1:1/api/health"
LINK = "https://example.invalid"


def setup(events=("source",), enabled=1, secret=None, kind="json"):
    received.clear()
    health_body[0] = {"ok": True, "lastFetch": T}
    deliver_ok[0] = True
    d = Path(tempfile.mkdtemp(prefix="heads-up-watchdog-"))
    db = sqlite3.connect(d / "heads-up.db")
    db.executescript(W.SCHEMA)
    box = W.Box(KEY)
    db.execute("INSERT INTO webhooks(id, name, kind, url_enc, secret_enc, events, enabled) VALUES('w1','n',?,?,?,?,?)",
               (kind, box.seal(f"http://127.0.0.1:{PORT}/hook"), box.seal(secret) if secret else None, json.dumps(list(events)), enabled))
    db.commit()
    db.close()
    return d / "heads-up.db", d / "state.json"


def run(url, db, state, t=T):
    return D.run(url, db, KEY, state, LINK, t=t)


def titles():
    return [json.loads(b)["title"] for _, _, b in received]


def test_healthy_says_nothing():
    db, state = setup()
    assert run(UP, db, state) == {"fails": 0, "alerted": False}
    assert not received


def test_one_failed_check_stays_quiet_so_updates_dont_alert():
    db, state = setup()
    assert run(DOWN, db, state)["fails"] == 1 and not received
    assert run(UP, db, state) == {"fails": 0, "alerted": False} and not received


def test_two_failed_checks_alert_once_then_recovery():
    db, state = setup()
    run(DOWN, db, state)
    assert run(DOWN, db, state)["alerted"] is True
    run(DOWN, db, state)
    assert titles() == ["Heads Up is down"], titles()
    assert run(UP, db, state) == {"fails": 0, "alerted": False}
    assert titles() == ["Heads Up is down", "Heads Up is back up"], titles()


def test_server_errors_count_as_down():
    db, state = setup()
    url = f"http://127.0.0.1:{PORT}/broken"
    run(url, db, state)
    run(url, db, state)
    assert "HTTP 500" in json.loads(received[0][2])["text"]


def test_app_that_stopped_fetching_counts_as_down():
    db, state = setup()
    health_body[0] = {"ok": True, "lastFetch": T - 5 * 3600}
    run(UP, db, state)
    run(UP, db, state)
    assert "hasn't fetched anything for 5 hours" in json.loads(received[0][2])["text"]


def test_no_fetching_yet_is_fine():
    db, state = setup()
    health_body[0] = {"ok": True, "lastFetch": None}
    assert run(UP, db, state)["fails"] == 0


def test_only_webhooks_that_want_it():
    db, state = setup(events=("act",))
    run(DOWN, db, state)
    run(DOWN, db, state)
    assert not received
    db, state = setup(enabled=0)
    run(DOWN, db, state)
    run(DOWN, db, state)
    assert not received


def test_signed_like_every_other_alert():
    db, state = setup(secret="signing-secret")
    run(DOWN, db, state)
    run(DOWN, db, state)
    _, headers, body = received[0]
    headers = {k.lower(): v for k, v in headers.items()}
    want = "sha256=" + hmac.new(b"signing-secret", body, hashlib.sha256).hexdigest()
    assert headers["x-headsup-signature"] == want and headers["x-headsup-event"] == "source"


def test_each_chat_format_builds():
    for kind in W.KINDS:
        db, state = setup(kind=kind)
        run(DOWN, db, state)
        run(DOWN, db, state)
        assert len(received) == 1, kind


def test_failed_delivery_is_tried_again_at_the_next_check():
    db, state = setup()
    deliver_ok[0] = False
    run(DOWN, db, state)
    assert run(DOWN, db, state)["alerted"] is False
    deliver_ok[0] = True
    assert run(DOWN, db, state)["alerted"] is True


def test_failed_recovery_message_is_tried_again():
    db, state = setup()
    run(DOWN, db, state)
    run(DOWN, db, state)
    deliver_ok[0] = False
    assert run(UP, db, state)["alerted"] is True
    deliver_ok[0] = True
    assert run(UP, db, state)["alerted"] is False
    assert titles().count("Heads Up is back up") == 2


def test_reads_the_database_when_the_app_is_stopped_and_on_a_read_only_disk():
    db, state = setup()
    path = Path(db)
    path.parent.chmod(0o500)
    try:
        run(DOWN, db, Path(tempfile.mkdtemp()) / "state.json")
        s2 = Path(tempfile.mkdtemp()) / "state.json"
        run(DOWN, db, s2)
        run(DOWN, db, s2)
        assert titles() == ["Heads Up is down"], titles()
    finally:
        path.parent.chmod(0o700)


def test_works_while_the_app_has_the_database_open_in_wal_mode():
    db, state = setup()
    live = sqlite3.connect(db)
    live.execute("PRAGMA journal_mode=WAL")
    live.execute("UPDATE webhooks SET name='changed'")
    live.commit()
    run(DOWN, db, state)
    run(DOWN, db, state)
    assert titles() == ["Heads Up is down"], titles()
    live.close()


def test_corrupt_state_file_starts_over():
    db, state = setup()
    state.write_text("not json")
    assert run(UP, db, state)["fails"] == 0


helpers.run_tests(globals())
