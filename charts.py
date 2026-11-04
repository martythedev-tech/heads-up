"""Numbers for the Charts tab, from data Heads Up already has, plus the
Cloudflare Radar fetcher (attack origins/targets, industries, attack types).
"""
import json
import time
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta, timezone

import vulns as V

# Plain names for the weakness types (CWE) that dominate CISA's catalog.
CWE_NAMES = {
    "CWE-20": "Improper input validation", "CWE-22": "Path traversal", "CWE-77": "Command injection",
    "CWE-78": "OS command injection", "CWE-79": "Cross-site scripting", "CWE-89": "SQL injection",
    "CWE-94": "Code injection", "CWE-119": "Memory buffer error", "CWE-120": "Buffer overflow",
    "CWE-121": "Stack buffer overflow", "CWE-122": "Heap buffer overflow", "CWE-125": "Out-of-bounds read",
    "CWE-190": "Integer overflow", "CWE-200": "Information exposure", "CWE-269": "Improper privilege management",
    "CWE-284": "Improper access control", "CWE-287": "Improper authentication", "CWE-288": "Auth bypass (alternate path)",
    "CWE-290": "Auth bypass by spoofing", "CWE-306": "Missing authentication", "CWE-352": "Cross-site request forgery",
    "CWE-362": "Race condition", "CWE-367": "Time-of-check time-of-use race", "CWE-400": "Resource exhaustion",
    "CWE-416": "Use after free", "CWE-434": "Unrestricted file upload", "CWE-476": "NULL pointer dereference",
    "CWE-502": "Unsafe deserialization", "CWE-611": "XML external entities", "CWE-668": "Resource exposed to wrong sphere",
    "CWE-693": "Protection mechanism failure", "CWE-732": "Wrong permissions", "CWE-787": "Out-of-bounds write",
    "CWE-798": "Hard-coded credentials", "CWE-843": "Type confusion", "CWE-862": "Missing authorization",
    "CWE-863": "Incorrect authorization", "CWE-917": "Expression language injection", "CWE-918": "Server-side request forgery",
    "CWE-1321": "Prototype pollution", "CWE-74": "Injection", "CWE-59": "Link following", "CWE-401": "Memory leak",
    "CWE-427": "Uncontrolled search path", "CWE-23": "Relative path traversal", "CWE-36": "Absolute path traversal",
}
STATES = ("investigating", "not_affected", "patched")


def _sev_bucket(cvss):
    if cvss is None:
        return "Not scored"
    return "Critical" if cvss >= 9 else "High" if cvss >= 7 else "Medium" if cvss >= 4 else "Low"


def build(db, vulns, items):
    today = datetime.now(timezone.utc).date()
    out = {}

    # --- CISA KEV over time, vendors, weakness types -------------------------------
    months = []
    d = date(today.year, today.month, 1)
    for _ in range(24):
        months.append(d.strftime("%Y-%m"))
        d = (d - timedelta(days=1)).replace(day=1)
    months.reverse()
    monthly = {m: {"month": m, "total": 0, "ransomware": 0} for m in months}
    year_ago = (today - timedelta(days=365)).isoformat()
    vendors, vendor_rw, cwes = Counter(), Counter(), Counter()
    total_year = rw_year = 0
    for r in db.execute("SELECT added, ransomware, vendor, cwes FROM kev"):
        added = r["added"] or ""
        rw = r["ransomware"] == "Known"
        m = monthly.get(added[:7])
        if m:
            m["total"] += 1
            m["ransomware"] += rw
        if added >= year_ago:
            total_year += 1
            rw_year += rw
            vendors[r["vendor"] or "Unknown"] += 1
            vendor_rw[r["vendor"] or "Unknown"] += rw
            for c in json.loads(r["cwes"] or "[]") or ["(not given)"]:
                cwes[c] += 1
    out["kevMonthly"] = list(monthly.values())
    out["kevYear"] = {"total": total_year, "ransomware": rw_year}
    out["kevVendors"] = [{"vendor": v, "count": n, "ransomware": vendor_rw[v]} for v, n in vendors.most_common(12)]
    out["kevCwes"] = [{"cwe": c, "name": CWE_NAMES.get(c, c if c != "(not given)" else "Not stated by CISA"), "count": n}
                      for c, n in cwes.most_common(10)]

    # --- Right now --------------------------------------------------------------------
    open_vulns = [v for v in vulns if v["group"] != "done"]
    by_group = defaultdict(Counter)
    for v in open_vulns:
        by_group[v["group"]][_sev_bucket(v["cvss"]) if not v["usnPrimary"] else
                             ("Critical" if v["ubuntuPriority"] == "critical" else "High")] += 1
    out["groups"] = {g: dict(by_group[g]) for g in ("act", "soon", "aware")}
    out["scatter"] = [{"id": v["id"], "title": v["title"], "cvss": v["cvss"], "epss": v["epss"],
                       "group": v["group"], "exploited": v["exploited"]}
                      for v in vulns if not v["usnPrimary"] and v["cvss"] is not None and v["epss"] is not None]

    # --- Your team's progress --------------------------------------------------------
    first_seen = {i["id"]: i["firstSeen"] for i in items}
    current = Counter()
    durations = []
    for v in vulns:
        t = v.get("triage")
        if t and t["state"] in STATES:
            current[t["state"]] += 1
            if t["state"] in ("patched", "not_affected") and first_seen.get(v["id"]):
                durations.append(max(0, t["at"] - first_seen[v["id"]]))
    durations.sort()
    out["progress"] = {
        "investigating": current["investigating"], "patched": current["patched"],
        "notAffected": current["not_affected"],
        "untriagedUrgent": sum(1 for v in open_vulns if v["group"] in ("act", "soon") and not v.get("triage")),
        "medianDaysToClose": round(durations[len(durations) // 2] / 86400, 1) if durations else None,
        "closedCount": len(durations),
    }
    # statuses set per day, last 30 days
    start = time.time() - 30 * 86400
    per_day = defaultdict(Counter)
    for r in db.execute("SELECT state, at FROM triage_log WHERE at >= ?", (start,)):
        per_day[datetime.fromtimestamp(r["at"], timezone.utc).date().isoformat()][r["state"]] += 1
    days = [(today - timedelta(days=i)).isoformat() for i in range(29, -1, -1)]
    out["activity"] = [{"day": d, **{s: per_day[d][s] for s in STATES}} for d in days]
    return out


# --- Cloudflare Radar ------------------------------------------------------------------

RADAR = "https://api.cloudflare.com/client/v4/radar"
RADAR_QUERIES = {
    # key: (path, params)
    "l7Origin": ("/attacks/layer7/top/locations/origin", {"dateRange": "7d", "limit": "100"}),
    "l7Target": ("/attacks/layer7/top/locations/target", {"dateRange": "7d", "limit": "100"}),
    "l3Origin": ("/attacks/layer3/top/locations/origin", {"dateRange": "7d", "limit": "100"}),
    "l3Target": ("/attacks/layer3/top/locations/target", {"dateRange": "7d", "limit": "100"}),
    "l7Pairs": ("/attacks/layer7/top/attacks", {"dateRange": "7d", "limit": "10"}),
    "l7Industry": ("/attacks/layer7/summary/INDUSTRY", {"dateRange": "7d"}),
    "l7Product": ("/attacks/layer7/summary/MITIGATION_PRODUCT", {"dateRange": "7d"}),
    "l7Rules": ("/attacks/layer7/summary/MANAGED_RULES", {"dateRange": "7d"}),
    "l7Series": ("/attacks/layer7/timeseries", {"dateRange": "28d", "aggInterval": "1d"}),
    "outages": ("/annotations/outages", {"dateRange": "30d", "limit": "100"}),
    "anomalies": ("/traffic_anomalies", {"dateRange": "7d", "limit": "60"}),
    # BGP: high-confidence hijacks, and route leaks (sorted by size on our side)
    "hijacks": ("/bgp/hijacks/events", {"dateRange": "7d", "per_page": "100", "minConfidence": "10",
                                         "sortBy": "TIME", "sortOrder": "DESC"}),
    "leaks": ("/bgp/leaks/events", {"dateRange": "7d", "per_page": "100"}),
}
RADAR_TEST = ("/attacks/layer7/summary/MITIGATION_PRODUCT", {"dateRange": "1d"})
RADAR_SCHEMA = """
CREATE TABLE IF NOT EXISTS radar (key TEXT PRIMARY KEY, data TEXT, at REAL);
"""


async def radar_get(session, token, path, params):
    from aiohttp import ClientTimeout
    async with session.get(RADAR + path, params={**params, "format": "json"},
                           headers={"Authorization": f"Bearer {token}"}, timeout=ClientTimeout(total=30)) as r:
        body = await r.json(content_type=None)
        if r.status != 200 or not body.get("success"):
            errs = "; ".join(e.get("message", "") for e in body.get("errors") or []) or f"HTTP {r.status}"
            raise RuntimeError(f"Radar {path}: {errs}")
        return body["result"]


def _simplify(key, result):
    """Keep only what the page draws."""
    if key in ("l7Origin", "l7Target", "l3Origin", "l3Target"):
        side = "origin" if key.endswith("Origin") else "target"
        rows = []
        for r in result.get("top_0") or []:
            iso = r.get(f"{side}CountryAlpha2") or r.get("clientCountryAlpha2") or r.get("countryAlpha2")
            name = r.get(f"{side}CountryName") or r.get("clientCountryName") or r.get("countryName")
            try:
                rows.append({"iso": iso, "name": name, "value": float(r.get("value"))})
            except (TypeError, ValueError):
                pass
        return rows
    if key == "l7Pairs":
        rows = []
        for r in result.get("top_0") or []:
            try:
                rows.append({"from": r.get("originCountryAlpha2"), "fromName": r.get("originCountryName"),
                             "to": r.get("targetCountryAlpha2"), "toName": r.get("targetCountryName"),
                             "value": float(r.get("value"))})
            except (TypeError, ValueError):
                pass
        return rows
    if key in ("l7Industry", "l7Product", "l7Rules"):
        s = result.get("summary_0") or {}
        rows = []
        for k, v in s.items():
            try:
                rows.append({"name": k, "value": float(v)})
            except (TypeError, ValueError):
                pass
        return sorted(rows, key=lambda r: -r["value"])
    if key == "outages":
        rows = []
        for a in result.get("annotations") or []:
            places = [{"iso": l.get("code"), "name": l.get("name")} for l in a.get("locationsDetails") or []]
            for e in a.get("entities") or []:
                if e.get("entityLocation") and not any(p["iso"] == e["entityLocation"] for p in places):
                    places.append({"iso": e.get("entityLocation"), "name": e.get("entityName")})
                elif e.get("entityName") and e.get("entityType") == "GEOLOCATION":
                    for p in places:
                        if p["iso"] == e.get("entityLocation"):
                            p["name"] = e["entityName"]
            asns = [{"asn": x.get("asn"), "name": x.get("name")} for x in a.get("asnsDetails") or []]
            for x in a.get("asnsDetails") or []:
                loc = x.get("locations") or x.get("location") or {}
                if isinstance(loc, dict) and loc.get("code") and not any(p["iso"] == loc["code"] for p in places):
                    places.append({"iso": loc["code"], "name": loc.get("name")})
            o = a.get("outage") or {}
            rows.append({"id": a.get("id"), "start": a.get("startDate"), "end": a.get("endDate"),
                         "description": a.get("description"), "cause": o.get("outageCause"),
                         "type": o.get("outageType"), "places": places, "asns": asns, "url": a.get("linkedUrl")})
        return rows
    if key == "anomalies":
        rows = []
        for a in result.get("trafficAnomalies") or []:
            asn = a.get("asnDetails") or {}
            loc = a.get("locationDetails") or asn.get("location") or {}
            rows.append({"start": a.get("startDate"), "end": a.get("endDate"), "status": a.get("status"),
                         "type": a.get("type"), "iso": loc.get("code"), "place": loc.get("name"),
                         "asn": asn.get("asn"), "asnName": asn.get("name")})
        return rows
    if key in ("hijacks", "leaks") or key.startswith("watch"):
        return simplify_bgp(key, result)
    if key == "l7Series":
        s = result.get("serie_0") or {}
        return [{"t": t, "value": float(v)} for t, v in zip(s.get("timestamps") or [], s.get("values") or [])]
    return result


def _asn_names(result):
    return {a.get("asn"): {"name": a.get("org_name"), "cc": a.get("country_code")} for a in result.get("asn_info") or []}


def simplify_bgp(key, result):
    names = _asn_names(result)
    net = lambda asn: {"asn": asn, "name": (names.get(asn) or {}).get("name"), "cc": (names.get(asn) or {}).get("cc")}
    out = []
    if "hijack" in key or key.startswith("watch"):
        for e in result.get("events") or []:
            if "hijacker_asn" not in e:
                continue
            out.append({"kind": "hijack", "id": f"h{e.get('id')}", "start": e.get("min_hijack_ts"), "end": e.get("max_hijack_ts"),
                        "ongoing": bool(e.get("on_going_count")), "confidence": e.get("confidence_score"),
                        "hijacker": net(e.get("hijacker_asn")), "victims": [net(a) for a in e.get("victim_asns") or []][:4],
                        "victimCountries": e.get("victim_countries") or [], "prefixes": (e.get("prefixes") or [])[:5],
                        "prefixCount": len(e.get("prefixes") or []), "peers": e.get("peer_ip_count")})
    if "leak" in key or key.startswith("watch"):
        for e in result.get("events") or []:
            if "leak_asn" not in e:
                continue
            out.append({"kind": "leak", "id": f"l{e.get('id')}", "start": e.get("min_ts"), "end": e.get("max_ts"),
                        "ongoing": not e.get("finished"), "leaker": net(e.get("leak_asn")),
                        "path": [net(a) for a in e.get("leak_seg") or []], "countries": sorted(set(e.get("countries") or [])),
                        "routes": e.get("leak_count"), "prefixCount": e.get("prefix_count"), "peers": e.get("peer_count")})
    if key == "leaks":
        out.sort(key=lambda x: -(x.get("routes") or 0))
        out = out[:40]
    return out


async def radar_refresh(db, session, token, watch=()):
    errors = []
    queries = dict(RADAR_QUERIES)
    # networks the admin asked to watch: any hijack (confidence 6+) or leak involving them
    for asn in watch:
        queries[f"watchH{asn}"] = ("/bgp/hijacks/events", {"dateRange": "7d", "per_page": "50", "involvedAsn": str(asn), "minConfidence": "6"})
        queries[f"watchL{asn}"] = ("/bgp/leaks/events", {"dateRange": "7d", "per_page": "50", "involvedAsn": str(asn)})
    db.execute("DELETE FROM radar WHERE key LIKE 'watch%'")
    for key, (path, params) in queries.items():
        try:
            result = await radar_get(session, token, path, params)
            db.execute("INSERT OR REPLACE INTO radar VALUES(?,?,?)",
                       (key, json.dumps(_simplify(key, result)), time.time()))
        except Exception as e:
            errors.append(f"{key}: {e}")
    return errors


def watched_events(radar):
    """All events involving watched networks, newest first, de-duplicated."""
    seen, out = set(), []
    for key, rows in radar.items():
        if key.startswith("watch"):
            for e in rows:
                if e["id"] not in seen:
                    seen.add(e["id"])
                    out.append({**e, "watchedAsn": int(key[6:])})
    return sorted(out, key=lambda e: e.get("start") or "", reverse=True)


def radar_data(db):
    rows = {r["key"]: r for r in db.execute("SELECT * FROM radar")}
    return {k: json.loads(r["data"]) for k, r in rows.items()}, max((r["at"] for r in rows.values()), default=None)
