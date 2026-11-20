"""CISA's SSVC assessment for each CVE, from the official CVE record.

CISA's Vulnrichment project adds an SSVC block to CVE records (an "ADP"
container from CISA-ADP), with three decision points:

  Exploitation      none | poc | active   (active = CISA has evidence of attacks)
  Automatable       yes | no              (attackers can script it at scale)
  Technical Impact  partial | total       (total = full control of the system)

Records are read from cveawg.mitre.org, briefing and CISA CVEs first. CISA
revisits its assessment as evidence changes, so an assessment is read again
after a week; a record without one yet (CISA enriches new CVEs within days)
after a day. Writes are batched: the server's disk is slow.
"""
import asyncio
import json
import time

from aiohttp import ClientTimeout

from dbutil import batch

CVE_API = "https://cveawg.mitre.org/api/cve/"
SCHEMA = """
CREATE TABLE IF NOT EXISTS ssvc_cve (cve TEXT PRIMARY KEY, ssvc TEXT, looked REAL);
"""
RECHECK_HIT = 7 * 86400
RECHECK_MISS = 86400
PER_RUN = 60
KEYS = {"exploitation": "exploitation", "automatable": "automatable", "technical impact": "impact"}


def migrate(db):
    db.executescript(SCHEMA)


def parse(record):
    """A CVE record -> {exploitation, automatable, impact, at} from CISA's SSVC block, or None."""
    for adp in ((record or {}).get("containers") or {}).get("adp") or []:
        if (adp.get("providerMetadata") or {}).get("shortName") != "CISA-ADP":
            continue
        for m in adp.get("metrics") or []:
            other = m.get("other") or {}
            if other.get("type") != "ssvc":
                continue
            content = other.get("content") or {}
            out = {"exploitation": None, "automatable": None, "impact": None, "at": content.get("timestamp")}
            for opt in content.get("options") or []:
                for k, v in opt.items():
                    key = KEYS.get(k.strip().lower())
                    if key:
                        out[key] = str(v).strip().lower()
            if out["exploitation"] or out["automatable"] or out["impact"]:
                return out
    return None


def candidates(db, first, rest, limit=PER_RUN):
    """CVEs that need (re)reading: `first` (briefings, CISA) before `rest`, never-read before stale."""
    looked = {r["cve"]: (r["ssvc"], r["looked"]) for r in db.execute("SELECT cve, ssvc, looked FROM ssvc_cve")}
    t = time.time()

    def due(c):
        if c not in looked:
            return True
        ssvc, at = looked[c]
        return at < t - (RECHECK_HIT if ssvc else RECHECK_MISS)

    out = []
    for group in (first, rest):
        # never-read before stale (sort is stable, so the caller's order holds within each)
        out += sorted((c for c in group if c not in out and due(c)), key=lambda c: c in looked)
    return out[:limit]


async def lookup(db, session, first, rest, limit=PER_RUN):
    """Read CISA's SSVC block for up to `limit` CVEs; returns how many have one."""
    rows, todo, failed = [], candidates(db, first, rest, limit), 0
    for cve in todo:
        try:
            async with session.get(CVE_API + cve, timeout=ClientTimeout(total=30)) as r:
                if r.status == 404:
                    record = None
                elif r.status != 200:
                    failed += 1
                    continue
                else:
                    record = await r.json(content_type=None)
        except Exception:
            failed += 1
            continue
        found = parse(record)
        rows.append((cve, json.dumps(found) if found else None, time.time()))
        await asyncio.sleep(0.3)
    if rows:
        with batch(db):
            db.executemany("INSERT OR REPLACE INTO ssvc_cve VALUES(?,?,?)", rows)
    if todo and failed == len(todo):
        raise RuntimeError(f"the CVE record service didn't answer for any of {len(todo)} CVEs")
    return sum(1 for _, s, _ in rows if s)


def cve_info(db, cve_ids):
    """CVE -> its SSVC assessment."""
    out, ids = {}, list(cve_ids)
    for i in range(0, len(ids), 500):
        chunk = ids[i:i + 500]
        for r in db.execute(f"SELECT cve, ssvc FROM ssvc_cve WHERE ssvc IS NOT NULL AND cve IN ({','.join('?' * len(chunk))})",
                            chunk):
            out[r["cve"]] = json.loads(r["ssvc"])
    return out
