"""One entry per vulnerability, grouped by urgency.

The dashboard and the webhooks both use this, so what people see on the page
and what gets announced in chat always agree.

Groups:
  act    exploited (CISA) and either Cloudflare says it needs attention or
         CISA added it in the last 14 days
  soon   not exploited, but Cloudflare says it needs attention, CVSS >= 9,
         Ubuntu rates it critical, or EPSS >= 0.5
  aware  everything else (incl. exploited more than 14 days ago)
  done   marked Patched or Not affected
"""
from datetime import datetime, timedelta, timezone

import exploits as X

GROUP_TITLES = {"act": "Act now", "soon": "Patch soon", "aware": "For awareness", "done": "Done"}
STATE_LABEL = {"untriaged": "Not checked yet", "investigating": "Investigating",
               "not_affected": "Not affected", "patched": "Patched"}
REL_NAME = {"resolute": "26.04", "noble": "24.04", "jammy": "22.04", "focal": "20.04",
            "stonking": "26.10", "questing": "25.10"}


def rel(r):
    return REL_NAME.get(r, r)


def kev_short(it):
    """'Ivanti Connect Secure Missing Authentication ... Vulnerability' -> 'Missing Authentication ...'"""
    n = str(it.get("headline") or "")
    vendor = (it.get("tags") or [""])[0] or ""
    title = it.get("title") or ""
    product = title[len(vendor) + 1:] if title.lower().startswith(vendor.lower() + " ") else title
    for _ in range(3):
        for w in (title, vendor, product):
            if w and n.lower().startswith(w.lower() + " "):
                n = n[len(w) + 1:]
    for suffix in (" Vulnerability", " Vulnerabilities"):
        if n.endswith(suffix):
            n = n[: -len(suffix)]
    return n


def short_date(iso):
    if not iso:
        return ""
    try:
        d = datetime.fromisoformat(iso[:10])
    except ValueError:
        return iso
    return f"{d.strftime('%b')} {d.day}"


def severity_text(cvss):
    if cvss is None:
        return None
    label = "Critical" if cvss >= 9 else "High" if cvss >= 7 else "Medium" if cvss >= 4 else "Low"
    return f"{label} · {cvss:.1f}"


def _max(xs):
    xs = [x for x in xs if x is not None]
    return max(xs) if xs else None


def build(items, releases):
    """items: the dicts api_state sends (cves enriched). Returns a list of vulnerabilities."""
    out, by_cve = [], {}

    def base(p):
        return {"id": p["id"], "primary": p, "zw": None, "kevs": [], "usns": [], "ms": [], "usnPrimary": False}

    def add(v):
        out.append(v)
        for c in v["primary"]["cves"]:
            by_cve.setdefault(c["id"], v)

    for it in items:
        if it["source"] == "zerowire":
            v = base(it)
            v["zw"] = it
            add(v)
    for it in items:
        if it["source"] == "kev":
            cve = it["cves"][0]["id"] if it["cves"] else None
            if cve in by_cve:
                by_cve[cve]["kevs"].append(it)
            else:
                v = base(it)
                v["kevs"] = [it]
                add(v)
    for it in items:
        if it["source"] == "msrc":
            cve = it["cves"][0]["id"] if it["cves"] else None
            if cve in by_cve:
                by_cve[cve]["ms"].append(it)
            else:
                v = base(it)
                v["ms"] = [it]
                add(v)
    for it in items:
        if it["source"] != "ubuntu":
            continue
        linked = {}
        for c in it["cves"]:
            v = by_cve.get(c["id"])
            if v:
                linked[v["id"]] = v
        for v in linked.values():
            v["usns"].append(it)
        if not linked and it.get("category") in ("critical", "high"):
            v = base(it)
            v["usns"] = [it]
            v["usnPrimary"] = True
            out.append(v)
    today = datetime.now(timezone.utc).date()
    return [describe(v, releases, today) for v in out]


def describe(v, releases, today):
    p = v["primary"]
    cves = p["cves"]
    kev_dates = sorted(c["kev"]["added"] for c in cves if c.get("kev") and c["kev"].get("added"))
    cvss = _max(c.get("cvss") for c in cves)
    epss = _max(c.get("epss") for c in cves)
    ms_info = [c["msrc"] for c in cves if c.get("msrc")]
    ms_exploited = sorted(m["releaseLabel"] for m in ms_info if m["exploited"])
    ms_disclosed = any(m["disclosed"] for m in ms_info)
    ms_dates = sorted(i["published"] for i in v["ms"] if i.get("extra", {}).get("exploited") and i.get("published"))
    exploited = bool(kev_dates) or bool(ms_exploited)
    kev_last = kev_dates[-1] if kev_dates else (ms_dates[-1] if ms_dates else None)
    exploited_by = "CISA" if kev_dates else "Microsoft" if ms_exploited else None
    # public exploit code, strongest first
    n_msf = sum(len(c.get("msf") or []) for c in cves)
    n_edb = sum(len(c.get("edb") or []) for c in cves)
    n_poc = sum(len(c.get("poc") or []) for c in cves)
    exploit = "metasploit" if n_msf else "exploitdb" if n_edb else "poc" if n_poc else None
    # exploit-chance trend of the CVE most likely to be exploited
    top = max((c for c in cves if c.get("epss") is not None), key=lambda c: c["epss"], default=None)
    epss_trend, epss_was = X.trend(top.get("epssSeries")) if top else (None, None)

    fixed, pending = set(), set()
    if not v["usnPrimary"]:
        for c in cves:
            for pkg in c.get("ubuntu") or []:
                for r, st in pkg["releases"].items():
                    if st == "released":
                        fixed.add(r)
                    elif st in ("needed", "pending", "needs-triage"):
                        pending.add(r)
    for u in v["usns"]:
        fixed.update((u.get("extra") or {}).get("releases") or [])
    ubuntu = {"fixed": [rel(r) for r in releases if r in fixed],
              "pending": [rel(r) for r in releases if r in pending]}

    zw = v["zw"]
    if zw:
        title, desc = zw["title"], zw["summary"]
    elif v["usnPrimary"]:
        title, desc = p["title"], p["summary"]
    elif p["source"] == "msrc":
        title = f"{(p.get('tags') or ['Microsoft'])[0]}: {p['title']}"
        desc = p["summary"]
    else:
        title = f"{p['title']}: {kev_short(p)}"
        desc = str(p.get("summary") or "")
        words = desc.split(" ", 2)
        if len(words) > 2 and words[0] == words[1]:
            desc = " ".join(words[1:])

    triage = p.get("triage")
    done = (triage or {}).get("state") in ("patched", "not_affected")
    recent_kev = exploited and kev_last >= (today - timedelta(days=14)).isoformat()
    cf_urgent = bool(zw) and zw.get("category") == "Needs attention"
    prio = p.get("category") if v["usnPrimary"] else None
    if done:
        group = "done"
    elif exploited and (cf_urgent or recent_kev):
        group = "act"
    elif exploited:
        group = "aware"
    elif (cf_urgent or (cvss or 0) >= 9 or prio == "critical" or (epss or 0) >= 0.5
          or (exploit in ("metasploit", "exploitdb") and (cvss or 0) >= 7) or ms_disclosed):
        group = "soon"
    else:
        group = "aware"

    # "why" as segments: [text, bold]
    why = []
    if done:
        why += [["Marked ", False], [STATE_LABEL[triage["state"]], True], [f" by {triage['by']}.", False]]
    elif exploited:
        why += [["Attackers are using this", True], [f", confirmed by {exploited_by} on {short_date(kev_last)}.", False]]
        if zw:
            why += [[" Cloudflare says: ", False], [zw.get("headline") or "", True], [".", False]]
        if not recent_kev and not cf_urgent:
            product = v["kevs"][0]["title"] if v["kevs"] else "it"
            why += [[f" Reported over 2 weeks ago; check whether you run {product}.", False]]
    elif ms_disclosed:
        why += [["Publicly disclosed", True], [" before Microsoft's fix (a zero-day); not seen exploited yet.", False]]
    elif zw:
        why += [["Cloudflare says: ", False], [zw.get("headline") or "", True], [". Not confirmed as exploited yet.", False]]
    elif v["usnPrimary"]:
        why += [["Ubuntu rates this ", False], [prio, True],
                [f"; updates are out for {', '.join(ubuntu['fixed']) or 'supported releases'}.", False]]
    elif cvss is not None and cvss >= 9:
        why += [["Critical severity", True], [f" ({cvss:.1f} out of 10).", False]]
    if not done and exploit in ("metasploit", "exploitdb"):
        why += [[" Exploit code is public", True],
                [" (Metasploit module)." if exploit == "metasploit" else " (Exploit-DB).", False]]
    elif not done and exploit == "poc" and not exploited:
        why += [[" Proof-of-concept code is on GitHub.", False]]
    if not done and not exploited and epss_trend == "rising":
        why += [[" Exploit chance is rising", True], [f" (from {epss_was * 100:.1f}% a month ago).", False]]
    if not done and ms_info:
        why += [[f" Microsoft fix out ({ms_info[0]['releaseLabel']} updates).", False]]
    if not done and not v["usnPrimary"]:
        if ubuntu["fixed"]:
            why += [[f" Ubuntu fix out for {', '.join(ubuntu['fixed'])}.", False]]
        elif ubuntu["pending"]:
            why += [[" Ubuntu fix still pending.", False]]

    reported = [s for s, on in (("Cloudflare", bool(zw)), ("CISA", bool(kev_dates)), ("Microsoft", bool(ms_info)),
                                ("Ubuntu", bool(ubuntu["fixed"] or ubuntu["pending"]))) if on]
    return {
        "id": v["id"], "group": group, "title": title, "desc": desc, "why": why,
        "cvss": cvss, "epss": epss, "exploited": exploited, "kevLast": kev_last,
        "ubuntu": ubuntu, "usnPrimary": v["usnPrimary"], "ubuntuPriority": prio,
        "cveCount": len(cves), "reportedBy": reported,
        "exploit": exploit, "exploitCounts": {"msf": n_msf, "edb": n_edb, "poc": n_poc},
        "epssTrend": epss_trend, "epssWas": epss_was,
        "zwId": zw["id"] if zw else None, "zwChanged": zw["changedAt"] if zw else None,
        "zwHeadline": zw.get("headline") if zw else None,
        "zwLatest": ((zw.get("extra") or {}).get("chronology") or [None])[0] if zw else None,
        "kevIds": [k["id"] for k in v["kevs"]], "usnIds": [u["id"] for u in v["usns"]],
        "msIds": [m["id"] for m in v["ms"]], "exploitedBy": exploited_by,
        "microsoft": ms_info[0] if ms_info else None,
        "latest": _max([i.get("updated") or i.get("published") for i in
                        [zw, *v["kevs"], *v["usns"], *v["ms"]] if i]) or "",
        "triage": triage,
    }


def why_text(v):
    return "".join(t for t, _ in v["why"]).strip()
