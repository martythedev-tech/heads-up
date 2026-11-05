"""What we run: the products your organisation uses, so the list can say "this affects us".

Each entry has a display name and the words that identify it in the feeds
("FortiGate" -> FortiGate, FortiOS). A word matches whole words only, case
insensitive, against the product fields of each source (CISA/VulnCheck
vendor and product, Microsoft product, Fortinet products, TrueNAS, Ubuntu
packages, Cloudflare's title and topics), never against free text, so
"Exchange" doesn't match a description that mentions "key exchange".
Versions are kept as notes only: the feeds don't give versions in a form
that could be compared reliably.
"""
import json
import re
import secrets
import time
from collections import Counter

SCHEMA = """
CREATE TABLE IF NOT EXISTS inventory (
  id TEXT PRIMARY KEY, name TEXT, terms TEXT, version TEXT, note TEXT, by TEXT, at REAL);
"""
MAX_ENTRIES = 200
MAX_TERMS = 10


class InventoryError(ValueError):
    pass


def migrate(db):
    db.executescript(SCHEMA)


def clean(s, n):
    return re.sub(r"\s+", " ", str(s or "")).strip()[:n]


def entries(db):
    return [{"id": r["id"], "name": r["name"], "terms": json.loads(r["terms"] or "[]"), "version": r["version"] or "",
             "note": r["note"] or "", "by": r["by"], "at": r["at"]}
            for r in db.execute("SELECT * FROM inventory ORDER BY name COLLATE NOCASE")]


def save(db, body, user):
    name = clean(body.get("name"), 60)
    if not name:
        raise InventoryError("Give it a name, e.g. FortiGate")
    raw = body.get("terms")
    terms = raw if isinstance(raw, list) else str(raw or "").split(",")
    terms = list(dict.fromkeys(t for t in (clean(t, 40) for t in terms) if len(t) >= 2))[:MAX_TERMS] or [name]
    eid = str(body.get("id") or "")
    if eid and not db.execute("SELECT 1 FROM inventory WHERE id=?", (eid,)).fetchone():
        raise InventoryError("That entry no longer exists")
    if not eid and db.execute("SELECT COUNT(*) FROM inventory").fetchone()[0] >= MAX_ENTRIES:
        raise InventoryError(f"The list is full ({MAX_ENTRIES} entries)")
    dup = db.execute("SELECT id FROM inventory WHERE lower(name)=lower(?) AND id!=?", (name, eid)).fetchone()
    if dup:
        raise InventoryError(f"“{name}” is already on the list")
    eid = eid or secrets.token_hex(6)
    db.execute("INSERT OR REPLACE INTO inventory VALUES(?,?,?,?,?,?,?)",
               (eid, name, json.dumps(terms), clean(body.get("version"), 60), clean(body.get("note"), 200), user, time.time()))
    return eid


def delete(db, eid):
    db.execute("DELETE FROM inventory WHERE id=?", (eid,))


class Matcher:
    def __init__(self, items):
        self.rules = []
        for e in items:
            pats = [re.compile(r"(?<![A-Za-z0-9])" + re.escape(t) + r"(?![A-Za-z0-9])", re.I) for t in e["terms"]]
            self.rules.append((e["name"], pats))

    def __bool__(self):
        return bool(self.rules)

    def match(self, text):
        return [name for name, pats in self.rules if any(p.search(text) for p in pats)]


def product_text(it):
    """The words that name the product an item is about (not its description)."""
    src, tags, extra = it["source"], it.get("tags") or [], it.get("extra") or {}
    if src in ("kev", "vulncheck"):
        parts = [it.get("title"), tags[0] if tags else ""]
    elif src == "msrc":
        parts = ["Microsoft", *tags]
    elif src == "fortinet":
        parts = ["Fortinet", *(extra.get("products") or tags)]
    elif src == "truenas":
        parts = [] if extra.get("level") == "none" else ["TrueNAS"]   # TrueNAS says it's not affected
    elif src == "ubuntu":
        parts = [it.get("title"), *(extra.get("packages") or [])]
    elif src == "zerowire":
        parts = [it.get("title"), *tags]
    else:
        parts = [it.get("title")]
    return " | ".join(str(p) for p in parts if p)


def suggestions(items, limit=400):
    """Product names seen in the feeds, most common first (for the name box)."""
    c = Counter()
    for it in items:
        src, tags, extra = it["source"], it.get("tags") or [], it.get("extra") or {}
        if src in ("kev", "vulncheck") and it.get("title"):
            c[it["title"]] += 1
            if tags and not tags[0].startswith("CWE-"):
                c[tags[0]] += 1
        elif src == "msrc":
            c.update(t for t in tags)
        elif src == "fortinet":
            c.update(extra.get("products") or [])
        elif src == "truenas":
            c["TrueNAS"] += 1
    return [n for n, _ in c.most_common(limit) if 2 <= len(n) <= 60]
