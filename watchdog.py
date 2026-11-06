#!/usr/bin/env python3
"""Tells people when Heads Up itself is down, which Heads Up can't do for itself.

Runs on a systemd timer as its own short-lived process, so it works when the
app has crashed or hung. It reads the webhook list directly and only reads the
database. Alerts after two failed checks in a row, so a restart during an
update stays quiet, and once more on recovery. It runs on the same machine, so
it can't report that machine being off: point an outside monitor at
/api/health for that.
"""
import hashlib
import hmac
import json
import os
import sqlite3
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import webhooks as W

EVENT = "source"
FAILS_BEFORE_ALERT = 2
STALE_FETCH = 3 * 3600  # the app answers, but stopped fetching


def check(url, t):
    """None when healthy, otherwise what's wrong in plain words."""
    context = ssl.create_default_context()
    context.check_hostname = False  # its own certificate, on this machine
    context.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(url, timeout=20, context=context) as r:
            body = json.load(r)
    except urllib.error.HTTPError as e:
        return f"it answered with an error (HTTP {e.code})"
    except Exception as e:
        return f"it isn't answering ({str(e) or type(e).__name__})"
    last = body.get("lastFetch")
    if last and t - last > STALE_FETCH:
        return f"it's running but hasn't fetched anything for {round((t - last) / 3600)} hours"
    return None


def open_db(path):
    # A clean shutdown leaves no WAL files, and a read-only connection can't
    # recreate them; with the app stopped, the file can't change under us.
    try:
        db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        db.execute("SELECT 1 FROM webhooks LIMIT 1")
    except sqlite3.OperationalError:
        db = sqlite3.connect(f"file:{path}?immutable=1", uri=True)
    db.row_factory = sqlite3.Row
    return db


def send(db_path, key, title, body, link):
    """Send to every webhook that wants it. True when none failed."""
    db = open_db(db_path)
    rows = [r for r in db.execute("SELECT * FROM webhooks WHERE enabled=1")
            if EVENT in json.loads(r["events"] or "[]")]
    db.close()
    box, ok = W.Box(key), True
    for row in rows:
        data = json.dumps(W.note_payload(row["kind"], EVENT, title, body, [], link)).encode()
        headers = {"Content-Type": "application/json", "X-HeadsUp-Event": EVENT, "User-Agent": "heads-up-webhook"}
        if row["kind"] == "json" and row["secret_enc"]:
            signature = hmac.new(box.open(row["secret_enc"]).encode(), data, hashlib.sha256).hexdigest()
            headers["X-HeadsUp-Signature"] = f"sha256={signature}"
        try:
            request = urllib.request.Request(box.open(row["url_enc"]), data=data, headers=headers)
            urllib.request.urlopen(request, timeout=15).close()
            print(f"sent to webhook {row['id']}", flush=True)
        except Exception as e:
            ok = False
            print(f"webhook {row['id']} failed: {str(e) or type(e).__name__}", flush=True)
    return ok


def run(url, db_path, key, state_path, link, t=None):
    """One check. Returns the state it saved."""
    t = t or time.time()
    state_path = Path(state_path)
    try:
        state = json.loads(state_path.read_text())
    except (OSError, ValueError):
        state = {"fails": 0, "alerted": False}
    problem = check(url, t)
    if problem:
        state["fails"] += 1
        print(f"check failed ({state['fails']}): {problem}", flush=True)
        if state["fails"] >= FAILS_BEFORE_ALERT and not state["alerted"]:
            state["alerted"] = send(db_path, key, "Heads Up is down", f"{problem[0].upper()}{problem[1:]}. Check it with: "
                                    "systemctl status heads-up; journalctl -u heads-up", link)
    else:
        if state["alerted"] and not send(db_path, key, "Heads Up is back up", "It's answering normally again.", link):
            state["fails"] = 0
            state_path.write_text(json.dumps(state))
            return state  # recovery message not delivered: try again next check
        state = {"fails": 0, "alerted": False}
    state_path.write_text(json.dumps(state))
    return state


def main():
    port = os.environ.get("HU_HTTPS_PORT", "9443")
    url = os.environ.get("HU_WATCHDOG_URL", f"https://127.0.0.1:{port}/api/health")
    db_path = os.environ.get("HU_WATCHDOG_DB", "/var/lib/private/heads-up/heads-up.db")
    server = os.environ.get("SERVER_NAME", "")
    link = os.environ.get("HU_PUBLIC_URL") or (f"https://{server}:{port}" if server else "")
    try:
        key = (Path(os.environ["CREDENTIALS_DIRECTORY"]) / "settings-key").read_text().strip()
    except (KeyError, OSError):
        sys.exit("no settings-key credential")
    run(url, db_path, key, Path(os.environ.get("STATE_DIRECTORY", ".")) / "state.json", link)


if __name__ == "__main__":
    main()
