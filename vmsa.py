"""VMware security advisories (VMSAs) from Broadcom's support portal.

Broadcom posts a VMSA hours or days before the CVE records behind it go live
(VMSA-2026-0011's CVEs were still RESERVED when it came out), so the advisory
itself is the first place a new VMware bug shows up.

The advisory list is a JavaScript portal with no feed, but each advisory is a
plain page under one running notification number shared by every Broadcom
division (VMware, Mainframe, ...):

  .../SecurityAdvisories/0/39626   VMSA-2026-0011
  .../SecurityAdvisories/0/39627   "Content not found!" (not used yet)

So Heads Up reads the numbers after the newest one it knows, and stops after a
run of numbers that don't exist yet. Pages of other divisions sometimes answer
with Cloudflare's browser check (HTTP 403): those are noted as "someone else's
advisory" and never pushed through. If the check shows up for everything, the
source reports an error instead of guessing.

From each VMSA: the products, each section's CVEs, CVSS and severity, any
"exploited in the wild" note, and the response matrix as vCenter/ESXi fixed
versions (same shape as vmware.parse_ranges, so What we run can check them).
"""
import asyncio
import html
import json
import re
import time
from datetime import date, datetime, timedelta

from aiohttp import ClientTimeout

import vmware as VM

PAGE = "https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/{}"
# 2026's VMSAs before this source existed (VMSA-2026-0011 = 39626); read once on the first run
KNOWN = [36947, 36986, 37454, 37513, 38017, 38288, 39445, 39495, 39625, 39626]
AHEAD_STOP = 40       # numbers in a row that don't exist yet: the end for now
MAX_PER_RUN = 150     # pages per run (a run waits 1 s between pages)
GAP_BACK = 150        # unused numbers this far below the newest are tried again (drafts published later)
GAP_EVERY = 12 * 3600
GAP_PER_RUN = 15
RECHECK_DAYS = 60     # advisories this recent are read again once a day (revisions: VMSA-2026-0008.3)
RECHECK_EVERY = 86400
ITEM_DAYS = 365
PAUSE = 1.0

SCHEMA = """
CREATE TABLE IF NOT EXISTS vmsa (
  num INTEGER PRIMARY KEY, id TEXT, rev TEXT, title TEXT, link TEXT, published TEXT, updated TEXT,
  severity TEXT, cvss REAL, cves TEXT, products TEXT, sections TEXT, ranges TEXT,
  exploited INTEGER, looked REAL);
CREATE TABLE IF NOT EXISTS vmsa_probe (num INTEGER PRIMARY KEY, state TEXT, looked REAL);
"""
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
EXPLOITED_RE = re.compile(r"exploitation of [^.]{0,300}?(?:has )?occurred in the wild|exploited in the wild"
                          r"|(?:reports|evidence) of (?:active )?exploitation", re.I)
SEVERITIES = ["Low", "Moderate", "Important", "Critical"]
CVE_TAIL = re.compile(r"\s*\((?:\s*CVE-[\d-]+\s*(?:,|\band\b)?\s*)+\)\s*$")
# section headings: <h2>3a. ...</h2>, or on older pages <p><strong>1. Impacted Products</strong></p>
HEADING = re.compile(r"<h[1-4]\b[^>]*>(.*?)</h[1-4]>|<p\b[^>]*>\s*<strong>(\d[a-z]{0,2}\.\s.*?)</p>", re.S | re.I)


def migrate(db):
    db.executescript(SCHEMA)


# --- one advisory page ------------------------------------------------------------

def text(fragment):
    t = re.sub(r"<br\s*/?>|</p>|</li>|</h\d>", "\n", fragment or "", flags=re.I)
    t = html.unescape(re.sub(r"<[^>]+>", " ", t)).replace("\xa0", " ")
    return re.sub(r"[ \t\r\f\v]+", " ", re.sub(r"\s*\n\s*", "\n", t)).strip()


def one_line(fragment):
    return re.sub(r"\s+", " ", text(fragment)).strip()


def classify(status, body):
    """'vmsa', 'other' (another Broadcom division), 'none' (number not used yet), 'blocked' (browser check)."""
    if status == 403 and re.search(r"Just a moment|Enable JavaScript and cookies|_cf_chl", body or ""):
        return "blocked"
    if status != 200:
        return None
    if "Content not found" in body and "Advisory ID" not in body:
        return "none"
    return "vmsa" if re.search(r"Advisory ID:?\s*(?:</strong>)?(?:&#160;|\s)*</td>\s*<td[^>]*>\s*VMSA-", body) \
        or re.search(r"\bVMSA-\d{4}-\d{4}", body) and "Response Matrix" in body else "other"


def tables(fragment):
    """Every <table> as rows of cell texts."""
    out = []
    for t in re.findall(r"<table\b.*?</table>", fragment, re.S | re.I):
        rows = []
        for tr in re.findall(r"<tr\b.*?</tr>", t, re.S | re.I):
            rows.append([one_line(c) for c in re.findall(r"<t[hd]\b[^>]*>(.*?)</t[hd]>", tr, re.S | re.I)])
        out.append(rows)
    return out


def iso(s):
    s = (s or "").strip()
    m = re.search(r"\d{4}-\d{2}-\d{2}", s)
    if m:
        return m.group(0)
    try:
        return datetime.strptime(s, "%d %B %Y").date().isoformat()
    except ValueError:
        return None


def matrix_ranges(rows):
    """A response-matrix table -> vCenter/ESXi ranges with the CVEs each row covers."""
    if not rows or not any("fixed version" in c.lower() for c in rows[0]):
        return []
    head = [c.lower() for c in rows[0]]

    def col(name):
        return next((i for i, c in enumerate(head) if name in c), None)
    i_prod, i_comp, i_ver = col("product"), col("component"), col("version")
    i_cve, i_fix = col("cve"), col("fixed version")
    out = []
    for r in rows[1:]:
        if len(r) != len(head) or i_fix is None or i_ver is None:
            continue
        product = r[i_prod] if i_prod is not None else ""
        comp = r[i_comp] if i_comp is not None else ""
        if "telco" in product.lower():  # Telco Cloud versions aren't vCenter/ESXi versions
            continue
        k = VM.kind(comp if comp and comp.upper() != "N/A" else product)
        if not k:
            continue
        fixed = re.sub(r"^(?:\[\d+\]\s*)+", "", r[i_fix].strip())   # "[1] 9.1.0.0300": footnote marks
        has_fix = bool(re.search(r"\d+\.\d|\d{7,}", fixed)) \
            and not re.search(r"contact|pending|not impacted|KB\d", fixed, re.I)
        if re.search(r"not impacted", fixed, re.I):
            continue
        cves = CVE_RE.findall(r[i_cve]) if i_cve is not None else []
        for part in re.split(r",", r[i_ver]):
            line = VM.numbers(re.sub(r"\.x\b.*", "", part.strip()))[:2]
            if line:
                out.append({"kind": k, "product": f"{product} {comp}".strip() if comp.upper() != "N/A" else product,
                            "line": list(line), "upto": fixed if has_fix else None, "all": not has_fix,
                            "cves": cves})
    return out


def parse(page, num):
    """An advisory page -> the vmsa row as a dict (None when it isn't a VMSA)."""
    m = re.search(r"(VMSA-\d{4}-\d{4})(\.\d+)?\s*:\s*([^<\n]+)", page)
    if not m:
        return None
    vid = m.group(1)
    fields = {}
    for t in tables(page)[:3]:
        for r in t:
            if len(r) == 2 and r[0].endswith(":"):
                fields[r[0].rstrip(":").strip().lower()] = r[1]
    synopsis = fields.get("synopsis") or m.group(3)
    title = CVE_TAIL.sub("", synopsis).strip().replace(", and, ", ", and ")
    # the newest revision and its date, from the change log (the title can lag behind it)
    log_at = page.find("Change Log")
    changes = re.findall(r"(\d{4}-\d{2}-\d{2})\s*(?:<[^>]+>|\s|&#160;)*(" + re.escape(vid) + r"(?:\.\d+)?)",
                         page[log_at:] if log_at >= 0 else "")
    rev = max((c[1] for c in changes), key=lambda r: int(r.split(".")[1]) if "." in r else 0,
              default=vid + (m.group(2) or ""))
    portal = dict((k.strip().lower(), v.strip()) for k, v in re.findall(
        r'edit-solution-labels"[^>]*>([^<]+)</(?:span|label)>\s*<p class="edit-solution-text">([^<]*)</p>', page))
    published = iso(fields.get("issue date")) or iso(portal.get("initial publication date"))
    updated = max([d for d, _ in changes] + [iso(fields.get("updated on")) or "", iso(portal.get("last updated")) or ""])
    # Impacted products
    prods = []
    pm = re.search(r"Impacted Products\s*(?:</[^>]+>\s*)+<ul>(.*?)</ul>", page, re.S | re.I)
    if pm:
        prods = [one_line(li) for li in re.findall(r"<li\b[^>]*>(.*?)</li>", pm.group(1), re.S)]
    # sections 3a, 3b, ...: their own CVEs, score and notes
    sections = []
    # (empty <h2 id=...></h2> anchors sit inside sections: they don't end one)
    heads = [h for h in HEADING.finditer(page) if one_line(h.group(1) or h.group(2))]
    for i, h in enumerate(heads):
        head = one_line(h.group(1) or h.group(2))
        sm = re.match(r"(3[a-z]{0,2})\.\s*(.+)", head)
        if not sm:
            continue
        body = page[h.end(): heads[i + 1].start() if i + 1 < len(heads) else len(page)]
        plain = one_line(body)
        cm = re.search(r"maximum CVSSv3 base score of\s*([\d.]+)", plain)
        sv = re.search(r"in the\s+(Critical|Important|Moderate|Low)\s+severity", plain)
        av = re.search(r"Known Attack Vectors:\s*(.+?)\s*(?:Resolution:|Workarounds?:|$)", plain)
        notes = re.search(r"Notes?:\s*(.+?)\s*(?:Response Matrix|$)", plain)
        sections.append({
            "ref": sm.group(1), "title": CVE_TAIL.sub("", sm.group(2)).strip(),
            "cves": CVE_RE.findall(head) or CVE_RE.findall(plain[:400]),
            "cvss": float(cm.group(1).rstrip(".")) if cm else None,
            "severity": sv.group(1) if sv else None,
            "vector": av.group(1)[:400] if av else None,
            "exploited": bool(EXPLOITED_RE.search(notes.group(1) if notes else "") or EXPLOITED_RE.search(plain)),
        })
    ranges = [r for t in tables(page) for r in matrix_ranges(t)]
    cves = list(dict.fromkeys(CVE_RE.findall(fields.get("cve(s)") or "") + [c for s in sections for c in s["cves"]]
                              + CVE_RE.findall(synopsis)))
    cvss = max([s["cvss"] for s in sections if s["cvss"] is not None], default=None)
    if cvss is None:
        rm = re.search(r"([\d.]+)\s*$", fields.get("cvssv3 range") or "")
        cvss = float(rm.group(1)) if rm else None
    severity = (fields.get("advisory severity") or portal.get("severity") or "").strip().title() or None
    return {"num": num, "id": vid, "rev": rev, "title": title, "link": PAGE.format(num),
            "published": published, "updated": updated or published, "severity": severity, "cvss": cvss,
            "cves": cves, "products": prods, "sections": sections, "ranges": ranges,
            "exploited": any(s["exploited"] for s in sections)}


# --- finding and reading advisories -----------------------------------------------

def plan(db, now=None):
    """Which numbers to read this run: [(num, why)], ahead-of-newest last."""
    now = now or time.time()
    probe = {r["num"]: (r["state"], r["looked"]) for r in db.execute("SELECT num, state, looked FROM vmsa_probe")}
    out = [(n, "known") for n in KNOWN if n not in probe]
    since = (date.fromtimestamp(now) - timedelta(days=RECHECK_DAYS)).isoformat()
    out += [(r["num"], "recheck") for r in db.execute(
        "SELECT num FROM vmsa WHERE updated >= ? AND looked < ? ORDER BY num", (since, now - RECHECK_EVERY))]
    top = max([n for n, (s, _) in probe.items() if s in ("vmsa", "other", "blocked")] + KNOWN)
    gaps = [n for n, (s, looked) in sorted(probe.items(), reverse=True)
            if s == "none" and top - GAP_BACK <= n < top and looked < now - GAP_EVERY]
    out += [(n, "gap") for n in gaps[:GAP_PER_RUN]]
    return out, top


async def fetch(session, num):
    async with session.get(PAGE.format(num), timeout=ClientTimeout(total=40), allow_redirects=True) as r:
        return r.status, await r.text(errors="replace")


def save(db, row):
    db.execute("INSERT OR REPLACE INTO vmsa VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
               (row["num"], row["id"], row["rev"], row["title"], row["link"], row["published"], row["updated"],
                row["severity"], row["cvss"], json.dumps(row["cves"]), json.dumps(row["products"]),
                json.dumps(row["sections"]), json.dumps(row["ranges"]), int(row["exploited"]), time.time()))


async def refresh(db, session, pause=PAUSE, log=print):
    """Read new and recent VMSAs; returns how many VMSAs are stored."""
    todo, top = plan(db)
    asked = blocked = answered = 0
    ahead, misses = top + 1, 0

    async def one(num):
        nonlocal asked, blocked, answered
        asked += 1
        status, body = await fetch(session, num)
        state = classify(status, body)
        if state is None:
            raise RuntimeError(f"Broadcom advisories: HTTP {status} for notification {num}")
        if state == "blocked":
            blocked += 1
        else:
            answered += 1
        if state == "vmsa":
            row = parse(body, num)
            if row:
                save(db, row)
            else:
                state = "other"
        db.execute("INSERT OR REPLACE INTO vmsa_probe VALUES(?,?,?)", (num, state, time.time()))
        await asyncio.sleep(pause)
        return state

    for num, _why in todo:
        if asked >= MAX_PER_RUN:
            break
        await one(num)
    while asked < MAX_PER_RUN and misses < AHEAD_STOP:
        state = await one(ahead)
        misses = misses + 1 if state == "none" else 0
        ahead += 1
        if blocked >= 5 and not answered:
            break
    if blocked >= 5 and not answered:
        # every page asked for a browser check: don't record that as "someone else's advisory"
        db.execute("DELETE FROM vmsa_probe WHERE state='blocked' AND looked > ?", (time.time() - 3600,))
        raise RuntimeError("Broadcom's site is asking for a browser check; VMware advisories paused")
    return db.execute("SELECT COUNT(*) FROM vmsa").fetchone()[0]


# --- what the rest of Heads Up uses ------------------------------------------------

def info(r):
    sections = json.loads(r["sections"] or "[]")
    return {"id": r["id"], "rev": r["rev"], "num": r["num"], "title": r["title"], "link": r["link"],
            "published": r["published"], "updated": r["updated"], "severity": r["severity"], "cvss": r["cvss"],
            "products": json.loads(r["products"] or "[]"), "exploited": bool(r["exploited"]),
            "sections": sections, "fixes": fixes(json.loads(r["ranges"] or "[]"))}


def fixes(ranges):
    """Response-matrix rows for the card: one line per product line, the fix or what Broadcom says."""
    seen, out = set(), []
    for r in ranges:
        key = (r["kind"], tuple(r["line"]), r["upto"])
        if key in seen:
            continue
        seen.add(key)
        out.append({"product": "vCenter" if r["kind"] == "vcenter" else "ESX",
                    "line": ".".join(map(str, r["line"])), "fixed": r["upto"]})
    return out


def items(db, today=None):
    since = ((today or date.today()) - timedelta(days=ITEM_DAYS)).isoformat()
    out = []
    for r in db.execute("SELECT * FROM vmsa WHERE published >= ? ORDER BY published DESC", (since,)):
        x = info(r)
        top = sorted([s for s in x["sections"] if s["cvss"] is not None], key=lambda s: -s["cvss"])[:4]
        summary = "; ".join(f"{s['title']} ({s['cvss']:.1f})" for s in top) or x["title"]
        out.append({
            "id": f"vmsa:{r['id']}", "source": "vmsa", "title": r["title"], "link": r["link"],
            "published": r["published"], "updated": r["updated"] or r["published"],
            "category": "exploited" if r["exploited"] else (r["severity"] or "").lower(),
            "headline": f"{r['rev']} · {r['severity'] or 'unrated'}"
                        + (f" · CVSS {r['cvss']:.1f}" if r["cvss"] is not None else ""),
            "summary": summary, "cves": json.loads(r["cves"] or "[]"),
            "tags": x["products"], "fingerprint": f"{r['rev']}|{r['updated']}|{r['exploited']}|{r['cvss']}",
            "extra": x,
        })
    return out


def cve_info(db, cve_ids):
    """CVE -> what the newest VMSA naming it says about that CVE (its section's score and notes)."""
    want, out = set(cve_ids), {}
    for r in db.execute("SELECT * FROM vmsa ORDER BY published"):
        cves = json.loads(r["cves"] or "[]")
        if not want.intersection(cves):
            continue
        x = info(r)
        for c in cves:
            if c not in want:
                continue
            s = next((s for s in x["sections"] if c in s["cves"]), None)
            cvss = (s or {}).get("cvss")
            if cvss is None and len(cves) == 1:   # one CVE: the advisory's score is its score
                cvss = x["cvss"]
            out[c] = {"id": x["id"], "rev": x["rev"], "title": x["title"], "link": x["link"],
                      "published": x["published"], "severity": (s or {}).get("severity") or x["severity"],
                      "cvss": cvss, "section": (s or {}).get("title"),
                      "exploited": bool((s or {}).get("exploited")), "products": x["products"]}
    return out


def cve_ranges(db, cve_ids):
    """CVE -> vCenter/ESXi ranges from the newest VMSA naming it (wins over the CVE record)."""
    want, out = set(cve_ids), {}
    for r in db.execute("SELECT cves, ranges FROM vmsa ORDER BY published"):
        cves = want.intersection(json.loads(r["cves"] or "[]"))
        if not cves:
            continue
        ranges = json.loads(r["ranges"] or "[]")
        for c in cves:
            mine = [{k: v for k, v in x.items() if k != "cves"} for x in ranges if c in x["cves"]]
            if mine:
                out[c] = mine
    return out
