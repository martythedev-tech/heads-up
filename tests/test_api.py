"""The whole app as a running server: accounts, statuses, What we run, webhooks,
alerts, search, health, backups and restarts. Starts its own copy on a local port
with a throwaway database and a fake webhook receiver; nothing leaves this machine.
"""
import asyncio
import hashlib
import hmac
import json
import os
import secrets
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from datetime import date, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer

import helpers
import app
import users as U
import aiohttp

STATE = os.environ["STATE_DIRECTORY"]
DB = f"{STATE}/heads-up.db"
ADMIN_PW = "T-" + secrets.token_urlsafe(18)
ADMIN_HASH = U.hash_password(ADMIN_PW)  # one value: a different hash at start means "reset the password"
results = []
received = []


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


PORT = free_port()
B = f"http://127.0.0.1:{PORT}"


class Receiver(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
        received.append({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}, "body": body})
        self.send_response(500 if self.path.startswith("/500") else 400 if self.path.startswith("/rc-denied") else 200)
        self.end_headers()
        if self.path.startswith("/rc-denied"):
            self.wfile.write(b'{"success":false,"error":"error-not-allowed"}')

    def log_message(self, *a):
        pass


rx = HTTPServer(("127.0.0.1", 0), Receiver)
HOOK = f"http://127.0.0.1:{rx.server_address[1]}"
threading.Thread(target=rx.serve_forever, daemon=True).start()


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(("  ok    " if ok else "  FAIL  ") + name + (f"  [{detail}]" if detail and not ok else ""), flush=True)


def seed():
    db = app.db_open()
    recent = (date.today() - timedelta(days=2)).isoformat()
    for i in range(10):
        cve = f"CVE-2026-{50000 + i}"
        db.execute("INSERT INTO kev(cve, vendor, product, name, added, description) VALUES(?,?,?,?,?,?)",
                   (cve, "Fortinet", "FortiOS", f"Example flaw {i}", recent, "x"))
        app.upsert_item(db, {"id": f"kev:{cve}", "source": "kev", "title": "Fortinet FortiOS", "link": f"https://example.invalid/{cve}",
                             "published": recent, "updated": recent, "category": "Known exploited", "headline": f"Example flaw {i}",
                             "summary": "x", "body": "", "cves": [cve], "tags": ["Fortinet", "FortiOS"], "fingerprint": cve, "extra": {}})
    app.upsert_item(db, {"id": "zw:example", "source": "zerowire", "title": "Example briefing", "link": "https://example.invalid/zw",
                         "published": recent, "updated": recent, "category": "Needs attention", "headline": "Prioritize patching",
                         "summary": "x", "body": "", "cves": ["CVE-2026-60000"], "tags": [], "fingerprint": "zw@1", "extra": {}})
    db.execute("INSERT INTO msrc(cve, release, released, title, tag, severity, impact, exploited, disclosed, likelihood, cvss, action) "
               "VALUES('CVE-2026-70000','2026-Oct','2026-10-13','Windows Paint Remote Code Execution Vulnerability','Windows Paint','Important','RCE',0,0,'Less',8.1,0)")
    db.close()


server = {}


def start():
    env = dict(os.environ, HU_DEV="1", HU_HTTP_PORT=str(PORT), HU_BIND="127.0.0.1", HU_PUBLIC_URL=B, HU_NO_FETCH="1",
               HU_DEV_ADMIN_HASH=ADMIN_HASH, PYTHONDONTWRITEBYTECODE="1", PYTHONUNBUFFERED="1")
    server["p"] = subprocess.Popen([sys.executable, str(helpers.ROOT / "app.py")], cwd=helpers.ROOT, env=env,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


async def wait_up():
    for _ in range(100):
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(B + "/api/health") as r:
                    if r.status == 200:
                        return await r.json()
        except aiohttp.ClientError:
            await asyncio.sleep(0.1)
    raise RuntimeError("server didn't start")


class C:
    def __init__(self):
        self.s = aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True), headers={"Origin": B})

    async def post(self, path, body=None):
        async with self.s.post(B + path, json=body if body is not None else {}) as r:
            text = await r.text()
            try:
                return r.status, json.loads(text), r.headers
            except ValueError:
                return r.status, text, r.headers

    async def get(self, path):
        async with self.s.get(B + path) as r:
            text = await r.text()
            try:
                return r.status, json.loads(text)
            except ValueError:
                return r.status, text

    async def login(self, u, p):
        return await self.post("/api/login", {"username": u, "password": p})

    async def close(self):
        await self.s.close()


def event_of(r):
    return r["headers"].get("x-headsup-event")


async def accounts():
    a, m = C(), C()
    st, body, hdr = await a.login("admin", ADMIN_PW)
    check("admin can sign in", st == 200 and body["user"]["role"] == "admin", st)
    cookie = hdr.get("Set-Cookie", "")
    check("session cookie is HttpOnly and SameSite=Strict", "HttpOnly" in cookie and "SameSite=Strict" in cookie, cookie[:80])
    x = C()
    st, _, _ = await x.login("ADMIN", ADMIN_PW)
    check("usernames aren't case-sensitive", st == 200, st)
    st, body, _ = await x.login("admin", "wrong-password-here")
    check("wrong password gets a plain message", st == 401 and body.get("error") == "Wrong username or password", body)
    await x.close()

    st, body, _ = await a.post("/api/users/create", {"username": "jsmith", "name": "J Smith", "role": "member"})
    pw = body.get("password") if isinstance(body, dict) else None
    check("empty password generates a strong one", st == 200 and pw and len(pw) >= 16, body)
    st, body, _ = await a.post("/api/users/create", {"username": "jsmith", "name": "x", "role": "member"})
    check("duplicate username refused", st == 400, body)
    st, body, _ = await a.post("/api/users/create", {"username": "Bad Name!", "name": "x", "role": "member"})
    check("bad username refused", st == 400, body)
    st, body, _ = await a.post("/api/users/create", {"username": "shorty", "name": "x", "role": "member", "password": "short"})
    check("password under 10 characters refused", st == 400, body)

    st, _, _ = await m.login("jsmith", pw)
    check("new member can sign in", st == 200, st)
    for path in ("/api/users", "/api/webhooks", "/api/settings"):
        st, _ = await m.get(path)
        check(f"member can't read {path}", st == 403, st)
    for path, body in (("/api/users/create", {"username": "evil1", "name": "e", "role": "admin"}),
                       ("/api/webhooks/save", {"kind": "json", "url": HOOK + "/x", "events": ["act"]}),
                       ("/api/inventory/save", {"name": "x"}),
                       ("/api/settings/watch", {"asns": "13335"}),
                       ("/api/settings/radar", {"token": "x"}),
                       ("/api/settings/vulncheck", {"token": "x"})):
        st, _, _ = await m.post(path, body)
        check(f"member can't POST {path}", st == 403, st)
    st, body = await m.get("/api/inventory")
    check("member reads What we run but can't edit", st == 200 and body["canEdit"] is False, body if st != 200 else "")

    st, body, _ = await a.post("/api/users/update", {"username": "admin", "role": "member"})
    check("can't remove your own admin rights", st == 400, body)
    st, body, _ = await a.post("/api/users/update", {"username": "admin", "disabled": True})
    check("can't turn off your own account", st == 400, body)
    st, body, _ = await a.post("/api/users/delete", {"username": "admin"})
    check("can't delete your own account", st == 400, body)

    st, _, _ = await a.post("/api/users/update", {"username": "jsmith", "name": "Jo Smith"})
    st2, body = await a.get("/api/users")
    check("rename works", st == 200 and any(u.get("name") == "Jo Smith" for u in body["users"]), body)
    st, _, _ = await a.post("/api/users/update", {"username": "jsmith", "role": "admin"})
    st2, _ = await m.get("/api/users")
    check("promotion takes effect at once", st == 200 and st2 == 200, (st, st2))
    st, _, _ = await a.post("/api/users/update", {"username": "jsmith", "role": "member"})
    st2, _ = await m.get("/api/users")
    check("demotion takes effect at once", st == 200 and st2 == 403, (st, st2))

    st, body, _ = await a.post("/api/users/reset", {"username": "jsmith"})
    new = body.get("password")
    st2, _ = await m.get("/api/inventory")
    check("New password signs them out everywhere", st == 200 and st2 == 401, (st, st2))
    st, _, _ = await m.login("jsmith", pw)
    check("old password stops working", st == 401, st)
    st, _, _ = await m.login("jsmith", new)
    check("new password works", st == 200, st)

    st, _, _ = await a.post("/api/users/update", {"username": "jsmith", "disabled": True})
    st2, _ = await m.get("/api/inventory")
    check("turning an account off ends its session", st == 200 and st2 == 401, (st, st2))
    st, _, _ = await m.login("jsmith", new)
    check("turned-off account can't sign in", st == 401, st)
    await a.post("/api/users/update", {"username": "jsmith", "disabled": False})
    st, _, _ = await m.login("jsmith", new)
    check("turning it back on works", st == 200, st)

    st, body, _ = await m.post("/api/me/password", {"current": "wrong-current-pass", "new": "another-long-pass"})
    check("own password: wrong current refused", st == 400, body)
    st, body, _ = await m.post("/api/me/password", {"current": new, "new": "short"})
    check("own password: too short refused", st == 400, body)
    st, body, _ = await m.post("/api/me/password", {"current": new, "new": "another-long-pass"})
    check("own password: change works", st == 200, body)
    z = C()
    st, _, _ = await z.login("jsmith", "another-long-pass")
    check("own password: the new one signs in", st == 200, st)
    await z.post("/api/logout")
    st, _ = await z.get("/api/inventory")
    check("sign out ends the session", st == 401, st)
    await z.close()
    return a, m


async def anonymous():
    anon = C()
    st, state = await anon.get("/api/state")
    check("anyone can read the page data", st == 200 and state["user"] is None, st)
    st, _ = await anon.get("/api/charts")
    check("anyone can read charts", st == 200, st)
    st, h = await anon.get("/api/health")
    check("anyone can read health", st == 200 and h["ok"] is True and h["version"] == app.VERSION, h)
    check("health gives away nothing else", set(h) == {"ok", "version", "lastFetch"}, h)
    for path in ("/api/users", "/api/webhooks", "/api/settings", "/api/inventory"):
        st, _ = await anon.get(path)
        check(f"anonymous can't read {path}", st == 401, st)
    st, _, _ = await anon.post("/api/triage", {"id": "x", "state": "patched"})
    check("anonymous can't set a status", st == 401, st)
    st, _, _ = await anon.post("/api/refresh")
    check("anonymous can't refresh", st == 401, st)
    async with aiohttp.ClientSession(headers={"Origin": "https://evil.example"}) as evil:
        async with evil.post(B + "/api/login", json={}) as r:
            check("cross-site POST refused", r.status == 403, r.status)
    await anon.close()
    return state


async def statuses(member, state):
    vid = next(v for v in state["vulns"] if v["group"] in ("act", "soon"))["id"]
    st, _, _ = await member.post("/api/triage", {"id": vid, "state": "banana"})
    check("bad status refused", st == 400, st)
    st, _, _ = await member.post("/api/triage", {"id": "no-such-item", "state": "patched"})
    check("status on an unknown item refused", st == 400, st)
    for s_, done in (("investigating", False), ("not_affected", True), ("patched", True)):
        st, body, _ = await member.post("/api/triage", {"id": vid, "state": s_, "note": "n " * 700})
        _, state = await member.get("/api/state")
        v = next(x for x in state["vulns"] if x["id"] == vid)
        check(f"{s_}: saved under the person's name", st == 200 and body["by"] == "Jo Smith" and v["triage"]["state"] == s_, body)
        check(f"{s_}: {'moves to Done' if done else 'stays in its group'}", (v["group"] == "done") == done, v["group"])
        check(f"{s_}: note capped at 1000", len(body["note"]) <= 1000, len(body["note"]))
    st, hist = await member.get(f"/api/history/{vid}")
    check("every change is logged", st == 200 and len(hist) == 3 and all(h["by"] == "Jo Smith" for h in hist), hist)
    await member.post("/api/triage", {"id": vid, "state": "investigating"})
    return vid


async def what_we_run(admin):
    st, body, _ = await admin.post("/api/inventory/preview", {"terms": "Fort"})
    check("'Fort' doesn't match FortiOS (whole words)", st == 200 and body["count"] == 0, body)
    st, body2, _ = await admin.post("/api/inventory/preview", {"terms": "FortiOS"})
    check("'FortiOS' matches", st == 200 and body2["count"] == 10, body2)
    st, body, _ = await admin.post("/api/inventory/save", {"name": "ForTest", "terms": ["FortiOS", "FortiOS", "x"], "version": "7.4"})
    eid = body.get("id") if isinstance(body, dict) else None
    check("admin can add an entry", st == 200 and eid, body)
    before = len(received)
    _, state = await admin.get("/api/state")
    ours = [v for v in state["vulns"] if "ForTest" in (v.get("ours") or [])]
    check("matching entries are marked", len(ours) == 10, len(ours))
    bad = [v["title"] for v in ours if v["exploited"] and v["group"] not in ("act", "done")]
    check("ours and exploited goes to Act now", not bad, bad[:4])
    await asyncio.sleep(1)
    check("editing the list sends no alerts", len(received) == before, len(received) - before)
    _, inv = await admin.get("/api/inventory")
    e = next(x for x in inv["entries"] if x["name"] == "ForTest")
    check("duplicate and too-short words dropped", e["terms"] == ["FortiOS"], e["terms"])
    await admin.post("/api/inventory/delete", {"id": eid})
    _, state = await admin.get("/api/state")
    check("delete removes the marks", not any("ForTest" in (v.get("ours") or []) for v in state["vulns"]))


async def webhooks(admin):
    _, meta = await admin.get("/api/webhooks")
    check("5 webhook types offered", set(meta["kinds"]) == {"rocketchat", "slack", "teams", "discord", "json"}, meta["kinds"])
    documented = {"act", "soon", "updated", "status", "patch", "routing", "truenas", "fortinet", "source"}
    check("all documented events offered", documented == set(meta["events"]), meta["events"])
    for body, why in (({"name": "x", "kind": "json", "url": "ftp://nope", "events": ["act"]}, "bad URL"),
                      ({"name": "x", "kind": "json", "url": HOOK + "/x", "events": []}, "no events"),
                      ({"name": "x", "kind": "nope", "url": HOOK + "/x", "events": ["act"]}, "bad type")):
        st, res, _ = await admin.post("/api/webhooks/save", body)
        check(f"{why} refused", st == 400, res)

    ids = {}
    for kind in ("rocketchat", "slack", "teams", "discord", "json"):
        body_ = {"name": kind, "kind": kind, "url": f"{HOOK}/{kind}?token=SECRETTOKEN", "events": ["status"]}
        if kind == "json":
            body_["secret"] = "signing-secret-1"
            body_["events"] = ["act", "soon", "status", "updated", "source"]
        st, body, _ = await admin.post("/api/webhooks/save", body_)
        check(f"add {kind} webhook", st == 200 and body.get("id"), body)
        ids[kind] = body.get("id")
    _, listing = await admin.get("/api/webhooks")
    check("webhook URLs never sent back to the browser", "SECRETTOKEN" not in json.dumps(listing))
    db = sqlite3.connect(DB, timeout=30)
    raw = [bytes(r[0]) for r in db.execute("select url_enc from webhooks")]
    db.close()
    check("webhook URLs encrypted in the database", raw and not any(b"SECRETTOKEN" in r or b"http" in r for r in raw))

    shapes = {"rocketchat": "text", "slack": "text", "discord": "embeds", "teams": "attachments", "json": "event"}
    for kind, wid in ids.items():
        n = len([r for r in received if r["path"].startswith(f"/{kind}")])
        st, body, _ = await admin.post("/api/webhooks/test", {"id": wid})
        got = [r for r in received if r["path"].startswith(f"/{kind}")]
        check(f"Send test: {kind}", st == 200 and body.get("ok") and len(got) == n + 1, body)
        payload = json.loads(got[-1]["body"]) if got else {}
        check(f"{kind} message has the right shape", shapes[kind] in payload or ("content" in payload and kind == "discord"), list(payload)[:6])
    last = [r for r in received if r["path"].startswith("/json")][-1]
    want = "sha256=" + hmac.new(b"signing-secret-1", last["body"].encode(), hashlib.sha256).hexdigest()
    check("JSON signature is correct", last["headers"].get("x-headsup-signature") == want)
    check("JSON event header", bool(event_of(last)))

    st, body, _ = await admin.post("/api/webhooks/save", {"name": "rc", "kind": "rocketchat", "url": HOOK + "/rc-denied", "events": ["act"]})
    st, res, _ = await admin.post("/api/webhooks/test", {"id": body["id"]})
    check("Rocket.Chat error-not-allowed gets a plain reason", res.get("ok") is False and "channel" in str(res.get("detail")).lower(), res)
    _, listing = await admin.get("/api/webhooks")
    check("last result shown under the webhook", "not-allowed" in json.dumps(next(w for w in listing["webhooks"] if w["id"] == body["id"])))
    await admin.post("/api/webhooks/delete", {"id": body["id"]})
    st, body, _ = await admin.post("/api/webhooks/save", {"name": "dead", "kind": "json", "url": "http://127.0.0.1:1/none", "events": ["act"]})
    await admin.post("/api/webhooks/delete", {"id": body["id"]})
    return ids


async def alerts(admin, member, vid):
    n = len(received)
    await member.post("/api/triage", {"id": vid, "state": "investigating", "note": "looking"})
    await asyncio.sleep(1)
    check("status change alert sent", any(event_of(r) == "status" for r in received[n:]), [event_of(r) for r in received[n:]])

    async def round_():
        for _ in range(100):
            st, body, _ = await member.post("/api/refresh")
            if isinstance(body, dict) and body.get("ok"):
                break
            await asyncio.sleep(0.2)
        for _ in range(150):
            await asyncio.sleep(0.2)
            st, body, _ = await member.post("/api/refresh")
            if isinstance(body, dict) and body.get("ok"):
                await asyncio.sleep(1.5)  # that one started a new round: let it finish
                return

    def forget(ids):
        db = sqlite3.connect(DB, timeout=30)
        db.execute(f"DELETE FROM vuln_seen WHERE id IN ({','.join('?' * len(ids))})", ids)
        db.commit()
        db.close()

    await round_()
    check("a member can refresh sources", True)
    _, state = await admin.get("/api/state")
    act = [v["id"] for v in state["vulns"] if v["group"] == "act"]
    check("alerts test has enough Act now entries", len(act) >= 8, len(act))
    n = len(received)
    forget(act[:2])
    await round_()
    events = [event_of(r) for r in received[n:] if r["path"].startswith("/json")]
    check("up to four alerts arrive individually", events.count("act") == 2, events)
    n = len(received)
    forget(act[2:8])
    await round_()
    events = [event_of(r) for r in received[n:] if r["path"].startswith("/json")]
    check("more than four arrive as one summary", events.count("summary") == 1 and "act" not in events, events)

    backups = sorted(p.name for p in (helpers.Path(STATE) / "backups").glob("*.db"))
    check("a refresh round makes the backup", len(backups) == 1 and date.today().isoformat() in backups[0], backups)
    st, h = await member.get("/api/health")
    check("health shows the last fetch once fetching has run", h["lastFetch"] is not None, h)


async def settings(admin):
    st, body, _ = await admin.post("/api/settings/watch", {"asns": "AS13335, 15169"})
    check("watched networks: both number forms accepted", st == 200 and body["asns"] == [13335, 15169], body)
    st, body, _ = await admin.post("/api/settings/watch", {"asns": "1 2 3 4 5 6 7"})
    check("watched networks: at most five", st == 200 and len(body["asns"]) == 5, body)
    st, body, _ = await admin.post("/api/settings/watch", {"asns": "abc"})
    check("watched networks: nonsense refused", st == 400, body)
    await admin.post("/api/settings/watch", {"asns": ""})


async def search():
    anon = C()
    for q in ("a", "x" * 500):
        st, body = await anon.get(f"/api/search?q={q}")
        check(f"search: odd input {q[:5]!r}", st == 200 and body["results"] == [], (st, str(body)[:80]))
    st, _ = await anon.get("/api/search?q=%27%3B%20DROP%20TABLE%20msrc%3B--")
    st2, body = await anon.get("/api/search?q=microsoft%20paint")
    check("search: SQL text is harmless", st == 200 and st2 == 200, (st, st2))
    check("search: finds Microsoft Paint outside the main list", [e["id"] for e in body["results"]] == ["CVE-2026-70000"], body)
    check("search: says when it's on the main list", (await anon.get("/api/search?q=CVE-2026-50000"))[1]["onMain"] is True)
    _, body = await anon.get("/api/search?q=CVE-2099-99999")
    check("search: unknown CVE goes to NVD", "nvd" in body and body["nvd"]["id"] == "CVE-2099-99999", body)
    await anon.close()


async def restart_keeps_everything(admin):
    await admin.post("/api/me/password", {"current": ADMIN_PW, "new": "a-changed-admin-pass"})
    _, u1 = await admin.get("/api/users")
    _, w1 = await admin.get("/api/webhooks")
    _, s1 = await admin.get("/api/state")
    tri = {v["id"]: v["triage"]["state"] for v in s1["vulns"] if v.get("triage")}
    check("restart test has a status to keep", bool(tri))
    server["p"].terminate()
    server["p"].wait(timeout=10)
    start()
    await wait_up()
    st, u2 = await admin.get("/api/users")
    check("restart: still signed in", st == 200, st)
    check("restart: users kept", {u["username"] for u in u1["users"]} == {u["username"] for u in u2["users"]}, u2)
    _, w2 = await admin.get("/api/webhooks")
    check("restart: webhooks kept", [w["id"] for w in w1["webhooks"]] == [w["id"] for w in w2["webhooks"]])
    _, s2 = await admin.get("/api/state")
    check("restart: statuses kept", tri == {v["id"]: v["triage"]["state"] for v in s2["vulns"] if v.get("triage")})
    st, res, _ = await admin.post("/api/webhooks/test", {"id": w2["webhooks"][0]["id"]})
    check("restart: webhooks still decrypt and send", res.get("ok") is True, res)
    x = C()
    st, _, _ = await x.login("admin", "a-changed-admin-pass")
    check("restart: a changed admin password is kept", st == 200, st)
    st, _, _ = await x.login("admin", ADMIN_PW)
    check("restart: the old admin password stays dead", st == 401, st)
    await x.close()


async def last_admin(admin):
    st, _, _ = await admin.post("/api/users/create", {"username": "second", "name": "Second", "role": "admin", "password": "second-admin-pass"})
    s = C()
    await s.login("second", "second-admin-pass")
    st, _, _ = await admin.post("/api/users/delete", {"username": "second"})
    check("an admin can delete another admin", st == 200, st)
    st, _ = await s.get("/api/users")
    check("a deleted admin loses access at once", st == 401, st)
    _, body = await admin.get("/api/users")
    admins = [u for u in body["users"] if u["role"] == "admin"]
    check("the last admin remains and can't remove themselves", len(admins) == 1 and (await admin.post("/api/users/delete", {"username": admins[0]["username"]}))[0] == 400)
    await s.close()


async def lockout():
    x = C()
    for _ in range(8):
        await x.login("nobody", "wrong-password-here")
    st, _, _ = await x.login("nobody", "wrong-password-here")
    check("after 8 wrong tries sign-in pauses", st == 429, st)
    await x.close()


async def main():
    seed()
    start()
    try:
        health = await wait_up()
        check("server starts and reports healthy", health["ok"] is True, health)
        check("no fetching yet means no last fetch", health["lastFetch"] is None, health)
        admin, member = await accounts()
        state = await anonymous()
        vid = await statuses(member, state)
        await what_we_run(admin)
        await webhooks(admin)
        await settings(admin)
        await search()
        await alerts(admin, member, vid)
        await restart_keeps_everything(admin)
        await last_admin(admin)
        await lockout()
        await admin.close()
        await member.close()
    finally:
        server["p"].terminate()
    bad = [r for r in results if not r[1]]
    print(f"{len(results) - len(bad)} passed, {len(bad)} failed")
    sys.exit(1 if bad else 0)


asyncio.run(main())
