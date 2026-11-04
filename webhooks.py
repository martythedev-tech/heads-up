"""Webhooks: tell chat (or anything that takes an HTTP POST) when something changes.

Formats: Rocket.Chat, Slack, Microsoft Teams (Workflows), Discord, and plain
JSON (optionally signed with HMAC-SHA256). Webhook URLs carry their own
secret token, so they are stored encrypted (AES-GCM, key from the
`settings-key` systemd credential) and never sent back to the browser.

Events:
  act      a vulnerability is new in, or moved into, "Act now"
  soon     a vulnerability is new in "Patch soon" (or moved up from "For awareness")
  updated  Cloudflare changed its guidance on an open Act now / Patch soon item
  status   someone set a status (Investigating, Not affected, Patched)
"""
import asyncio
import hashlib
import hmac
import json
import os
import secrets
import time
from urllib.parse import urlsplit

from aiohttp import ClientSession, ClientTimeout

import vulns as V
from dbutil import batch

KINDS = {"rocketchat": "Rocket.Chat", "slack": "Slack", "teams": "Microsoft Teams",
         "discord": "Discord", "json": "Plain JSON"}
EVENTS = {"act": "New in Act now", "soon": "New in Patch soon",
          "updated": "Cloudflare updated its guidance", "status": "Status changed",
          "patch": "Patch Tuesday is out"}
DEFAULT_EVENTS = ["act", "updated"]
COLORS = {"act": "#d93a40", "soon": "#d26a00", "updated": "#e8730c", "status": "#23885a", "test": "#2f6fed", "patch": "#0e7a55"}
ICONS = {"act": "🔴", "soon": "🟠", "updated": "📝", "status": "✅", "test": "👋", "patch": "🩹"}
BATCH_LIMIT = 4   # more events than this for one webhook in one go -> one summary message

SCHEMA = """
CREATE TABLE IF NOT EXISTS webhooks (
  id TEXT PRIMARY KEY, name TEXT, kind TEXT, url_enc BLOB, secret_enc BLOB,
  events TEXT, enabled INTEGER, created REAL, created_by TEXT,
  last_at REAL, last_ok INTEGER, last_detail TEXT);
CREATE TABLE IF NOT EXISTS deliveries (
  webhook_id TEXT, at REAL, event TEXT, title TEXT, ok INTEGER, detail TEXT);
CREATE TABLE IF NOT EXISTS vuln_seen (
  id TEXT PRIMARY KEY, grp TEXT, zw_changed REAL, first_seen REAL);
"""


def log(*args):
    print(*args, flush=True)


# --- encryption ------------------------------------------------------------------------

class Box:
    def __init__(self, key_hex):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        self.aead = AESGCM(bytes.fromhex(key_hex))

    def seal(self, text):
        if not text:
            return None
        nonce = os.urandom(12)
        return nonce + self.aead.encrypt(nonce, text.encode(), b"heads-up-webhook")

    def open(self, blob):
        if not blob:
            return ""
        return self.aead.decrypt(blob[:12], blob[12:], b"heads-up-webhook").decode()


def mask(url):
    try:
        u = urlsplit(url)
        return f"{u.scheme}://{u.hostname}{':' + str(u.port) if u.port else ''}/…"
    except ValueError:
        return "…"


def valid_url(url):
    try:
        u = urlsplit(url)
    except ValueError:
        return False
    return u.scheme in ("http", "https") and bool(u.hostname) and len(url) <= 2000


# --- message formats -------------------------------------------------------------------

def facts(v):
    out = []
    if v["usnPrimary"]:
        out.append(("Ubuntu priority", (v["ubuntuPriority"] or "").capitalize()))
        out.append(("Fixes", f"{v['cveCount']} CVEs"))
    else:
        out.append(("Severity", V.severity_text(v["cvss"]) or "Not scored yet"))
        out.append(("Exploited", f"Yes ({v.get('exploitedBy') or 'CISA'}, {V.short_date(v['kevLast'])})" if v["exploited"] else "Not confirmed"))
    if not v["usnPrimary"]:
        out.append(("Public exploit", {"metasploit": "Yes, Metasploit module", "exploitdb": "Yes, Exploit-DB",
                                       "poc": "Proof-of-concept on GitHub"}.get(v.get("exploit"), "None known")))
    if v["reportedBy"]:
        out.append(("Reported by", ", ".join(v["reportedBy"])))
    if not v["usnPrimary"]:
        if v["ubuntu"]["fixed"]:
            out.append(("Ubuntu", "Fix out for " + ", ".join(v["ubuntu"]["fixed"])))
        elif v["ubuntu"]["pending"]:
            out.append(("Ubuntu", "Fix pending"))
    return out


def describe_event(event, v, extra):
    """-> (headline, body text) in plain words."""
    if event == "status":
        t = extra or {}
        body = f"{t.get('by')} marked this {V.STATE_LABEL.get(t.get('state'), t.get('state'))}."
        if t.get("note"):
            body += f" Note: {t['note']}"
        return f"{ICONS['status']} Status changed", body
    if event == "updated":
        latest = v.get("zwLatest") or {}
        body = f"Their advice: {v.get('zwHeadline')}."
        if latest.get("text"):
            body = f"What changed ({V.short_date(latest.get('date'))}): {latest['text']} " + body
        return f"{ICONS['updated']} Cloudflare updated its guidance", body
    return f"{ICONS[event]} {EVENTS[event]}", V.why_text(v)


def payload(kind, event, v, extra, link, name="Heads Up"):
    head, body = describe_event(event, v, extra)
    desc = (v.get("desc") or "")[:300]
    fs = facts(v)
    color = COLORS[event]
    if kind in ("rocketchat", "slack"):
        attachment = {"title": v["title"], "title_link": link, "text": f"{body}\n{desc}".strip(),
                      "color": color, "fields": [{"title": k, "value": val, "short": True} for k, val in fs]}
        # No alias/emoji for Rocket.Chat: setting them needs the
        # message-impersonate permission (else HTTP 400 error-not-allowed).
        # The name and avatar come from the integration's own settings.
        return {"text": f"*{head}*", "attachments": [attachment]}
    if kind == "discord":
        return {"username": name, "content": f"**{head}**", "embeds": [{
            "title": v["title"][:250], "url": link, "description": f"{body}\n\n{desc}"[:3500],
            "color": int(color[1:], 16),
            "fields": [{"name": k, "value": val[:1000], "inline": True} for k, val in fs]}]}
    if kind == "teams":
        return {"type": "message", "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard", "version": "1.4",
                "body": [
                    {"type": "TextBlock", "text": head, "weight": "Bolder", "size": "Medium"},
                    {"type": "TextBlock", "text": v["title"], "weight": "Bolder", "wrap": True},
                    {"type": "TextBlock", "text": body, "wrap": True},
                    {"type": "TextBlock", "text": desc, "wrap": True, "isSubtle": True},
                    {"type": "FactSet", "facts": [{"title": k, "value": val} for k, val in fs]},
                ],
                "actions": [{"type": "Action.OpenUrl", "title": "Open in Heads Up", "url": link}],
            }}]}
    return {"event": event, "headline": head, "text": body, "link": link,
            "vulnerability": {k: v.get(k) for k in ("id", "group", "title", "desc", "cvss", "epss",
                                                     "exploited", "kevLast", "ubuntu", "reportedBy")},
            "status": extra if event == "status" else None}


SUMMARY_LINES = 15


def summary_payload(kind, events, base_url, name="Heads Up"):
    # Act now first; at most SUMMARY_LINES lines, so chat services accept the message.
    order = {"act": 0, "soon": 1, "updated": 2, "status": 3}
    ranked = sorted(events, key=lambda e: order.get(e[0], 9))
    lines = [(event, v, f"{base_url}/#{v['id']}") for event, v, _extra in ranked[:SUMMARY_LINES]]
    more = len(events) - len(lines)
    head = f"🛡️ {len(events)} new alerts" + (f" (showing {len(lines)}; open Heads Up for the rest)" if more else "")
    if kind in ("rocketchat", "slack"):
        text = "\n".join(f"{ICONS[e]} {EVENTS[e]}: <{l}|{v['title']}>" for e, v, l in lines)
        return {"text": f"*{head}*\n{text}"}
    if kind == "discord":
        text = "\n".join(f"{ICONS[e]} {EVENTS[e]}: [{v['title']}]({l})" for e, v, l in lines)
        return {"username": name, "content": f"**{head}**\n{text}"[:1900]}
    if kind == "teams":
        return {"type": "message", "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard", "version": "1.4",
                        "body": [{"type": "TextBlock", "text": head, "weight": "Bolder", "size": "Medium"}] + [
                            {"type": "TextBlock", "wrap": True,
                             "text": f"{ICONS[e]} {EVENTS[e]}: [{v['title']}]({l})"} for e, v, l in lines]}}]}
    return {"event": "summary", "headline": head,
            "items": [{"event": e, "id": v["id"], "title": v["title"], "link": l} for e, v, l in lines]}


def note_payload(kind, event, title, body, facts, link, name="Heads Up"):
    """A message that isn't about one vulnerability (e.g. Patch Tuesday)."""
    head = f"{ICONS[event]} {EVENTS[event]}"
    color = COLORS[event]
    if kind in ("rocketchat", "slack"):
        return {"text": f"*{head}*", "attachments": [{"title": title, "title_link": link, "text": body, "color": color,
                                                      "fields": [{"title": k, "value": v, "short": True} for k, v in facts]}]}
    if kind == "discord":
        return {"username": name, "content": f"**{head}**", "embeds": [{"title": title[:250], "url": link, "description": body[:3500],
                "color": int(color[1:], 16), "fields": [{"name": k, "value": v[:1000], "inline": True} for k, v in facts]}]}
    if kind == "teams":
        return {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4",
            "body": [{"type": "TextBlock", "text": head, "weight": "Bolder", "size": "Medium"},
                     {"type": "TextBlock", "text": title, "weight": "Bolder", "wrap": True},
                     {"type": "TextBlock", "text": body, "wrap": True},
                     {"type": "FactSet", "facts": [{"title": k, "value": v} for k, v in facts]}],
            "actions": [{"type": "Action.OpenUrl", "title": "Open in Heads Up", "url": link}]}}]}
    return {"event": event, "headline": head, "title": title, "text": body, "link": link, "facts": dict(facts)}


TEST_VULN = {
    "id": "test", "group": "act", "title": "Test message from Heads Up",
    "desc": "If you can read this, the webhook works. Real alerts look like this one.",
    "why": [["This is only a test.", True]], "cvss": 9.8, "epss": 0.9, "exploited": True,
    "kevLast": None, "ubuntu": {"fixed": ["24.04"], "pending": []}, "usnPrimary": False,
    "ubuntuPriority": None, "cveCount": 1, "reportedBy": ["Cloudflare", "CISA", "Ubuntu"],
    "zwHeadline": None,
}


def hint(kind, status, text):
    """Plain-words explanation for errors chat services commonly return."""
    if kind == "rocketchat":
        if "error-not-allowed" in text:
            return (" (Rocket.Chat: the integration's “Post as” user isn't allowed to post in its channel. "
                    "For a private channel, add that user to it; also check the channel isn't read-only.)")
        if "invalid-channel" in text or "error-invalid-room" in text:
            return " (Rocket.Chat: the integration's channel doesn't exist. Check “Post to Channel”.)"
        if status == 404:
            return " (Rocket.Chat: no such integration. Is it enabled, and is the URL complete?)"
    if status in (401, 403, 404):
        return " (Check the URL; the webhook may have been deleted or turned off.)"
    return ""


# --- the service ---------------------------------------------------------------------------

class Webhooks:
    def __init__(self, db, key_hex, base_url):
        self.db = db
        self.box = Box(key_hex) if key_hex else None
        self.base_url = base_url.rstrip("/")
        self.session = None
        db.executescript(SCHEMA)

    async def http(self):
        if self.session is None or self.session.closed:
            self.session = ClientSession(timeout=ClientTimeout(total=15),
                                         headers={"User-Agent": "heads-up-webhook"})
        return self.session

    # storage
    def list(self):
        out = []
        for r in self.db.execute("SELECT * FROM webhooks ORDER BY created"):
            try:
                url = self.box.open(r["url_enc"]) if self.box else ""
            except Exception:
                url = ""
            recent = [dict(d) for d in self.db.execute(
                "SELECT at, event, title, ok, detail FROM deliveries WHERE webhook_id=? ORDER BY at DESC LIMIT 6",
                (r["id"],))]
            out.append({"id": r["id"], "name": r["name"], "kind": r["kind"], "url": mask(url) if url else "(unreadable)",
                        "hasSecret": bool(r["secret_enc"]), "events": json.loads(r["events"] or "[]"),
                        "enabled": bool(r["enabled"]), "createdBy": r["created_by"],
                        "lastAt": r["last_at"], "lastOk": r["last_ok"], "lastDetail": r["last_detail"],
                        "recent": recent})
        return out

    def save(self, body, user):
        if not self.box:
            raise ValueError("Webhooks are not available: the server has no settings key")
        name = str(body.get("name") or "").strip()[:60] or "Webhook"
        kind = body.get("kind")
        if kind not in KINDS:
            raise ValueError("Pick a type")
        events = [e for e in body.get("events") or [] if e in EVENTS]
        if not events:
            raise ValueError("Pick at least one thing to be told about")
        url = str(body.get("url") or "").strip()
        secret = str(body.get("secret") or "").strip()
        wid = str(body.get("id") or "")
        row = self.db.execute("SELECT * FROM webhooks WHERE id=?", (wid,)).fetchone() if wid else None
        if wid and not row:
            raise ValueError("That webhook no longer exists")
        if url and not valid_url(url):
            raise ValueError("The URL must start with https:// or http://")
        if not row and not url:
            raise ValueError("Paste the webhook URL")
        enabled = 1 if body.get("enabled", True) else 0
        if row:
            self.db.execute(
                "UPDATE webhooks SET name=?, kind=?, events=?, enabled=?"
                + (", url_enc=?" if url else "") + (", secret_enc=?" if secret or body.get("clearSecret") else "")
                + " WHERE id=?",
                (name, kind, json.dumps(events), enabled,
                 *([self.box.seal(url)] if url else []),
                 *([self.box.seal(secret)] if secret or body.get("clearSecret") else []), wid))
        else:
            wid = secrets.token_hex(8)
            self.db.execute("INSERT INTO webhooks(id, name, kind, url_enc, secret_enc, events, enabled, created, created_by)"
                            " VALUES(?,?,?,?,?,?,?,?,?)",
                            (wid, name, kind, self.box.seal(url), self.box.seal(secret), json.dumps(events),
                             enabled, time.time(), user))
        log(f"webhook {wid} ({kind}) saved by {user}")
        return wid

    def delete(self, wid, user):
        self.db.execute("DELETE FROM webhooks WHERE id=?", (wid,))
        self.db.execute("DELETE FROM deliveries WHERE webhook_id=?", (wid,))
        log(f"webhook {wid} deleted by {user}")

    # sending
    async def post(self, row, event_label, title, body):
        url = self.box.open(row["url_enc"])
        data = json.dumps(body).encode()
        headers = {"Content-Type": "application/json", "X-HeadsUp-Event": event_label}
        if row["kind"] == "json" and row["secret_enc"]:
            sig = hmac.new(self.box.open(row["secret_enc"]).encode(), data, hashlib.sha256).hexdigest()
            headers["X-HeadsUp-Signature"] = f"sha256={sig}"
        ok, detail = False, ""
        for attempt in (1, 2):
            try:
                s = await self.http()
                async with s.post(url, data=data, headers=headers) as r:
                    text = (await r.text())[:200]
                    ok = 200 <= r.status < 300
                    detail = f"HTTP {r.status}" + ("" if ok else f": {text}") + ("" if ok else hint(row["kind"], r.status, text))
                    if ok or r.status < 500:
                        break
            except Exception as e:
                detail = f"{type(e).__name__}: {e}"[:200]
            if attempt == 1:
                await asyncio.sleep(20)
        t = time.time()
        self.db.execute("INSERT INTO deliveries VALUES(?,?,?,?,?,?)", (row["id"], t, event_label, title, int(ok), detail))
        self.db.execute("DELETE FROM deliveries WHERE webhook_id=? AND at < (SELECT MIN(at) FROM "
                        "(SELECT at FROM deliveries WHERE webhook_id=? ORDER BY at DESC LIMIT 50))",
                        (row["id"], row["id"]))
        self.db.execute("UPDATE webhooks SET last_at=?, last_ok=?, last_detail=? WHERE id=?", (t, int(ok), detail, row["id"]))
        if not ok:
            log(f"webhook {row['id']} failed: {detail}")
        return ok, detail

    async def test(self, wid):
        row = self.db.execute("SELECT * FROM webhooks WHERE id=?", (wid,)).fetchone()
        if not row:
            raise ValueError("That webhook no longer exists")
        body = payload(row["kind"], "act", TEST_VULN, None, self.base_url + "/")
        if row["kind"] in ("rocketchat", "slack"):
            body["text"] = f"*{ICONS['test']} Test from Heads Up*"
        elif row["kind"] == "discord":
            body["content"] = f"**{ICONS['test']} Test from Heads Up**"
        elif row["kind"] == "json":
            body["event"] = "test"
        return await self.post(row, "test", TEST_VULN["title"], body)

    async def send(self, events):
        """events: [(event, vuln, extra)] -> deliver to every webhook that wants them."""
        if not events or not self.box:
            return
        for row in self.db.execute("SELECT * FROM webhooks WHERE enabled=1").fetchall():
            wanted = set(json.loads(row["events"] or "[]"))
            mine = [e for e in events if e[0] in wanted]
            if not mine:
                continue
            if len(mine) > BATCH_LIMIT:
                await self.post(row, "summary", f"{len(mine)} alerts", summary_payload(row["kind"], mine, self.base_url))
                continue
            for event, v, extra in mine:
                await self.post(row, event, v["title"],
                                payload(row["kind"], event, v, extra, f"{self.base_url}/#{v['id']}"))

    async def send_note(self, event, title, body, facts, link):
        if not self.box:
            return
        for row in self.db.execute("SELECT * FROM webhooks WHERE enabled=1").fetchall():
            if event in set(json.loads(row["events"] or "[]")):
                await self.post(row, event, title, note_payload(row["kind"], event, title, body, facts, link))

    # change detection
    def is_empty(self):
        return self.db.execute("SELECT 1 FROM vuln_seen LIMIT 1").fetchone() is None

    def detect(self, vulns, record_only=False):
        """Compare with what we saw last time; returns events. A first run only records."""
        seen = {r["id"]: r for r in self.db.execute("SELECT * FROM vuln_seen")}
        baseline = record_only or not seen
        events, t = [], time.time()
        with batch(self.db):
            for v in vulns:
                prev = seen.get(v["id"])
                g = v["group"]
                if not baseline:
                    if prev is None:
                        if g in ("act", "soon"):
                            events.append((g, v, None))
                    elif prev["grp"] != g:
                        if g == "act" or (g == "soon" and prev["grp"] == "aware"):
                            events.append((g, v, None))
                    elif (g in ("act", "soon") and v["zwChanged"] and prev["zw_changed"]
                          and v["zwChanged"] > prev["zw_changed"]):
                        events.append(("updated", v, None))
                self.db.execute("INSERT INTO vuln_seen VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET grp=excluded.grp,"
                                " zw_changed=excluded.zw_changed", (v["id"], g, v["zwChanged"], prev["first_seen"] if prev else t))
        if baseline and not seen:
            log(f"webhooks: recorded {len(vulns)} vulnerabilities as already known (no alerts on first run)")
        return events
