"""VMware (Broadcom) fixed versions, for the versions on What we run.

Broadcom's advisories are a JavaScript portal, but every VMware CVE record
(cveawg.mitre.org, the official CVE JSON API) carries the same response matrix
as affected ranges in VMware's own notation:

  vCenter  {"version": "8.0",     "lessThan": "8.0 U3m"}
           {"version": "9.1.x",   "lessThan": "9.1.1.0200"}
  ESX      {"version": "8.0",     "lessThan": "ESXi80U3k-25595708"}
           {"version": "9.0.x.x", "lessThan": "ESXi-9.0.2.0100-25595025"}

Each VMware CVE on the list is looked up once; records are read again after a
week (Broadcom adds fixes for other lines), misses after a day.

Versions you can type on What we run:
  vCenter  "8.0 U3m", "8.0 Update 3m", "8.0U3m" or the appliance version "8.0.3.01200"
  ESXi     "8.0 U3k build 25595708", "ESXi80U3k-25595708", "8.0 build 25595708"
           (the build number decides; "8.0 U3k" alone compares by update letter)
"""
import asyncio
import json
import re
import time

from aiohttp import ClientTimeout

CVE_API = "https://cveawg.mitre.org/api/cve/"
SCHEMA = """
CREATE TABLE IF NOT EXISTS vmware_cve (cve TEXT PRIMARY KEY, ranges TEXT, looked REAL);
"""
RECHECK_HIT = 7 * 86400
RECHECK_MISS = 86400
PRODUCT_WORDS = re.compile(r"VMware|\bESXi?\b|vCenter|vSphere", re.I)

# vCenter 8.0 Update 3 appliance versions -> update letter (Broadcom KB 326316 and the
# 8.0 U3m release notes). There was no U3f, so the numbers and letters drift apart;
# a letter or number missing here is never guessed.
VC_DOTTED = {(8, 0, 3, 0): "", (8, 0, 3, 100): "a", (8, 0, 3, 200): "b", (8, 0, 3, 300): "c",
             (8, 0, 3, 400): "d", (8, 0, 3, 500): "e", (8, 0, 3, 600): "g", (8, 0, 3, 700): "h",
             (8, 0, 3, 800): "i", (8, 0, 3, 900): "j", (8, 0, 3, 1000): "k", (8, 0, 3, 1200): "m"}


def migrate(db):
    db.executescript(SCHEMA)


def kind(text):
    """'VMware vCenter' -> 'vcenter', 'ESX' / 'VMware ESXi' -> 'esxi', anything else -> None."""
    t = (text or "").lower()
    if "vcenter" in t:
        return "vcenter"
    if re.search(r"\besxi?\b", t):
        return "esxi"
    return None


def entry_kind(entry):
    return kind(" ".join([entry.get("name") or "", *(entry.get("terms") or [])]))


def numbers(s):
    return tuple(int(x) for x in re.findall(r"\d+", s or ""))


def parse_ranges(record):
    """A CVE record -> [{kind, product, line, upto, all}] for vCenter and ESXi."""
    out = []
    for a in ((record or {}).get("containers") or {}).get("cna", {}).get("affected") or []:
        if "vmware" not in (a.get("vendor") or "").lower():
            continue
        k = kind(a.get("product"))
        if not k:
            continue
        for v in a.get("versions") or []:
            if v.get("status") != "affected":
                continue
            line = numbers(re.sub(r"\.x\b.*", "", v.get("version") or ""))[:2]
            if not line:
                continue
            upto = v.get("lessThan")
            out.append({"kind": k, "product": a.get("product"), "line": list(line), "upto": upto, "all": not upto})
    return out


def parse(text, k):
    """What you run -> {line, update, letter, dotted, build, label} (None when nothing parses).
    line: (8, 0); update/letter: 3, 'm' from "U3m" / "Update 3m" / "ESXi80U3m";
    dotted: (8, 0, 3, 1200) from "8.0.3.01200"; build: 25595708 (ESXi)."""
    s = (text or "").strip()
    if not s:
        return None
    out = {"line": None, "update": None, "letter": None, "dotted": None, "build": None, "label": s}
    m = re.search(r"ESXi(\d)(\d)U(\d+)([a-z]?)", s, re.I)  # ESXi80U3k-25595708
    if m:
        out.update(line=(int(m[1]), int(m[2])), update=int(m[3]), letter=m[4].lower())
    m = re.search(r"(?<![\d.])(\d+)\.(\d+)(?:\.\d+)?\s*(?:U|Update\s*)(\d+)([a-z]?)\b", s, re.I)
    if m:
        out.update(line=(int(m[1]), int(m[2])), update=int(m[3]), letter=m[4].lower())
    m = re.search(r"(?<![\d.])(\d+)\.(\d+)\.(\d+)\.(\d+)(?![\d.])", s)  # 8.0.3.01200 / ESXi-9.0.2.0100-...
    if m:
        out["dotted"] = tuple(int(x) for x in m.groups())
        out["line"] = out["line"] or out["dotted"][:2]
        if out["update"] is None and k == "vcenter" and out["dotted"] in VC_DOTTED:
            out["update"], out["letter"] = out["dotted"][2], VC_DOTTED[out["dotted"]]
    if k == "esxi":
        b = re.findall(r"(?<![\d.])(\d{7,9})(?![\d.])", s)
        out["build"] = int(b[-1]) if b else None
    if out["line"] is None:
        m = re.search(r"(?<![\d.])(\d+)\.(\d+)(?![\d])", s)
        if m:
            out["line"] = (int(m[1]), int(m[2]))
    if out["line"] is None and out["build"] is None:
        return None
    return out


def compare(mine, fix, k):
    """1 = mine has the fix, 0 = it doesn't, None = can't tell from what was typed."""
    if k == "esxi" and mine["build"] and fix["build"]:
        return int(mine["build"] >= fix["build"])
    if mine["update"] is not None and fix["update"] is not None and mine["letter"] is not None \
            and fix["letter"] is not None:
        if mine["update"] != fix["update"]:
            # another update branch: only an older update is known not to have it
            return 0 if mine["update"] < fix["update"] else None
        return int(mine["letter"] >= fix["letter"])
    if mine["dotted"] and fix["dotted"]:  # 9.x: "9.1.1.0200", "ESXi-9.0.2.0100-..."
        return int(mine["dotted"] >= fix["dotted"])
    return None


def check(entry, ranges):
    """One What we run entry against an item's VMware ranges -> a versions.check note, or None
    when the item has nothing for this product."""
    k = entry_kind(entry)
    mine_r = [r for r in ranges if r["kind"] == k] if k else []
    if not mine_r:
        return None
    base = {"product": entry["name"], "vendor": "VMware", "upto": None}
    mine = parse(entry.get("version"), k)
    if not mine:
        return {**base, "version": None, "state": "noversion", "fix": None}
    base["version"] = mine["label"]
    base["line"] = ".".join(map(str, mine["line"])) if mine["line"] else None
    if mine["line"] is None:
        return {**base, "state": "needline", "fix": None}
    on_line = [r for r in mine_r if tuple(r["line"]) == mine["line"][:len(r["line"])]]
    if not on_line:
        return {**base, "state": "unlisted", "fix": None}
    depth = max(len(r["line"]) for r in on_line)
    on_line = [r for r in on_line if len(r["line"]) == depth]
    if any(r["all"] for r in on_line):   # some CVE has no fix on this line (yet)
        return {**base, "state": "affectedline", "fix": None}
    # One line can list several fixes: per CVE (U3m for one, U3k for another) and per update
    # branch (8.0 U3m and the 8.0 U2f express patch). The fixes for your branch count; you
    # need every one of them, so the worst verdict wins.
    fixes = [(r["upto"], parse(r["upto"], k)) for r in on_line]
    same = [f for f in fixes if f[1] and mine["update"] is not None and f[1]["update"] == mine["update"]]
    verdicts = [(compare(mine, fx, k) if fx else None, upto, fx) for upto, fx in (same or fixes)]
    rank = {0: 0, None: 1, 1: 2}
    worst = min(rank[v] for v, _, _ in verdicts)
    picked = [x for x in verdicts if rank[x[0]] == worst]
    v, upto, _ = picked[0]
    if worst != 2:
        # the newest fix among the ones you lack
        v, upto, _ = max(picked, key=lambda x: ((x[2] or {}).get("update") or 0, (x[2] or {}).get("letter") or "",
                                               (x[2] or {}).get("build") or 0, (x[2] or {}).get("dotted") or ()))
    state = {1: "fixed", 0: "upgrade", None: "line"}[v]
    return {**base, "state": state, "fix": upto}


def candidates(db, limit):
    """CVEs of VMware items on the list that need (re)reading."""
    fresh = {r[0] for r in db.execute(
        "SELECT cve FROM vmware_cve WHERE (ranges != '[]' AND looked > ?) OR (ranges = '[]' AND looked > ?)",
        (time.time() - RECHECK_HIT, time.time() - RECHECK_MISS))}
    out = []
    for r in db.execute("SELECT title, tags, cves FROM items WHERE active=1 ORDER BY published DESC"):
        if not PRODUCT_WORDS.search(f"{r['title']} {r['tags']}"):
            continue
        for c in json.loads(r["cves"] or "[]"):
            if c not in fresh and c not in out:
                out.append(c)
    return out[:limit]


async def lookup(db, session, limit=40):
    """Read the CVE record of each VMware CVE on the list; returns how many have ranges."""
    found = 0
    for cve in candidates(db, limit):
        try:
            async with session.get(CVE_API + cve, timeout=ClientTimeout(total=30)) as r:
                if r.status == 404:
                    record = None
                elif r.status != 200:
                    continue
                else:
                    record = await r.json(content_type=None)
        except Exception:
            continue
        ranges = parse_ranges(record)
        db.execute("INSERT OR REPLACE INTO vmware_cve VALUES(?,?,?)", (cve, json.dumps(ranges), time.time()))
        found += bool(ranges)
        await asyncio.sleep(0.3)
    return found


def cve_ranges(db, cve_ids):
    """CVE -> its vCenter/ESXi ranges."""
    out, ids = {}, list(cve_ids)
    for i in range(0, len(ids), 500):
        chunk = ids[i:i + 500]
        marks = ",".join("?" * len(chunk))
        for r in db.execute(f"SELECT cve, ranges FROM vmware_cve WHERE ranges != '[]' AND cve IN ({marks})", chunk):
            out[r["cve"]] = json.loads(r["ranges"])
    return out
