"""One entry per vulnerability, grouped by urgency.

The dashboard and the webhooks both use this, so what people see on the page
and what gets announced in chat always agree.

Groups:
  act    exploited (CISA) and either Cloudflare says it needs attention or
         CISA added it in the last 14 days
  soon   not exploited, but Cloudflare says it needs attention, CVSS >= 9,
         Ubuntu rates it critical, EPSS >= 0.5, or TrueNAS rated its impact
         High/Critical in the last 45 days, or Fortinet rated an advisory for
         your Fortinet products 9+ in the last 45 days
         (Fortinet saying "exploited in the wild" counts as exploited; for a
         product you don't run it stays in For awareness)
  aware  everything else (incl. exploited more than 14 days ago)
  done   marked Patched or Not affected

"What we run" (inventory.py) changes this for products you use:
  act    exploited, whatever its age or source (no "check whether you run it")
  soon   not exploited but serious: CVSS >= 7, Ubuntu high/critical, TrueNAS
         High/Critical, or any Cloudflare briefing
"""
import re
from datetime import datetime, timedelta, timezone

import exploits as X
import truenas as TN
import fortinet as FN
import inventory as INV

GROUP_TITLES = {"act": "Act now", "soon": "Patch soon", "aware": "For awareness", "done": "Done"}
STATE_LABEL = {"untriaged": "Not checked yet", "investigating": "Investigating",
               "not_affected": "Not affected", "patched": "Patched"}
REL_NAME = {"resolute": "26.04", "noble": "24.04", "jammy": "22.04", "focal": "20.04",
            "stonking": "26.10", "questing": "25.10"}


def rel(r):
    return REL_NAME.get(r, r)


def cf_says(zw, after):
    """Cloudflare's advice as "why" segments, without a blank if it has none."""
    headline = zw.get("headline")
    if not headline:
        return [["Cloudflare flagged this" + after, False]]
    return [["Cloudflare says: ", False], [headline, True], [after, False]]


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


def build(items, releases, inventory=None):
    """items: the dicts api_state sends (cves enriched). Returns a list of vulnerabilities."""
    matcher = INV.Matcher(inventory or [])
    out, by_cve = [], {}

    def base(p):
        return {"id": p["id"], "primary": p, "zw": None, "kevs": [], "usns": [], "ms": [], "vcs": [], "tns": [], "fns": [], "usnPrimary": False}

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
        if it["source"] == "vulncheck":
            cve = it["cves"][0]["id"] if it["cves"] else None
            if cve in by_cve:
                by_cve[cve]["vcs"].append(it)
            else:
                v = base(it)
                v["vcs"] = [it]
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
        if it["source"] == "fortinet":
            v = next((by_cve[c["id"]] for c in it["cves"] if c["id"] in by_cve), None)
            if v:
                v["fns"].append(it)
            else:
                v = base(it)
                v["fns"] = [it]
                add(v)
    for it in items:
        if it["source"] == "truenas":
            # one page can cover several CVEs (Samba, Lodash); join the first one already listed
            v = next((by_cve[c["id"]] for c in it["cves"] if c["id"] in by_cve), None)
            if v:
                v["tns"].append(it)
            else:
                v = base(it)
                v["tns"] = [it]
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
    for v in out:
        parts = [v["primary"], v["zw"], *v["kevs"], *v["usns"], *v["ms"], *v["vcs"], *v["tns"], *v["fns"]]
        via = {}   # product name -> the sources it matched through
        if matcher:
            for i in {id(i): i for i in parts if i}.values():
                for name in matcher.match(INV.product_text(i)):
                    via.setdefault(name, set()).add(i["source"])
        v["ours"] = sorted(via)
        v["oursTrueNASOnly"] = bool(via) and all(s == {"truenas"} for s in via.values())
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
    vc_dates = sorted(c["vulncheck"]["added"] for c in cves if c.get("vulncheck") and c["vulncheck"].get("added"))
    # what TrueNAS said: pages attached to this entry, plus any page naming one of its CVEs
    tn_pages = {i["link"]: i["extra"] for i in v["tns"]}
    for c in cves:
        if c.get("truenas"):
            tn_pages.setdefault(c["truenas"]["link"], c["truenas"])
    tn = max(tn_pages.values(), key=lambda t: (TN.LEVELS.index(t["level"]) if t.get("level") in TN.LEVELS else -1,
                                               t.get("published") or ""), default=None)
    tn_urgent = bool(tn) and tn.get("level") in ("high", "critical") and TN.is_recent(tn.get("published"), today=today)
    # what Fortinet said: advisories attached here, plus any advisory/statement naming one of its CVEs
    fn_pages = {i["extra"]["id"]: i["extra"] for i in v["fns"]}
    for c in cves:
        if c.get("fortinet"):
            fn_pages.setdefault(c["fortinet"]["id"], c["fortinet"])
    fn = max(fn_pages.values(), key=lambda f: (bool(f.get("yours")), f.get("exploited"), f.get("cvss") or 0), default=None)
    fn_mine = bool(fn) and bool(fn.get("yours"))
    fn_dates = sorted(f["published"] for f in fn_pages.values() if f.get("exploited") and f.get("published"))
    fn_urgent = fn_mine and (fn.get("cvss") or 0) >= 9 and TN.is_recent(fn.get("published"), days=FN.SOON_DAYS, today=today)
    exploited = bool(kev_dates) or bool(ms_exploited) or bool(vc_dates) or bool(fn_dates)
    kev_last = kev_dates[-1] if kev_dates else (vc_dates[-1] if vc_dates else (ms_dates[-1] if ms_dates else
                                                                              (fn_dates[-1] if fn_dates else None)))
    exploited_by = ("CISA" if kev_dates else "VulnCheck" if vc_dates else "Microsoft" if ms_exploited
                    else "Fortinet" if fn_dates else None)
    # exploited only according to Fortinet, in a Fortinet product you don't run
    fn_not_mine = exploited_by == "Fortinet" and not fn_mine
    # how many days VulnCheck listed it before CISA did
    vc_lead = None
    if kev_dates and vc_dates and vc_dates[0] < kev_dates[0]:
        vc_lead = (datetime.fromisoformat(kev_dates[0][:10]) - datetime.fromisoformat(vc_dates[0][:10])).days
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
    elif p["source"] == "vulncheck":
        title = f"{p['title']}: {kev_short(p)}"
        desc = str(p.get("summary") or "")
    elif p["source"] == "msrc":
        product = (p.get("tags") or ["Microsoft"])[0]
        title = p["title"] if product.lower() in p["title"].lower() else f"{product}: {p['title']}"
        desc = p["summary"]
    elif p["source"] == "truenas":
        title = p["title"] if "truenas" in p["title"].lower() else f"TrueNAS: {p['title']}"
        desc = p["summary"]
    elif p["source"] == "fortinet":
        product = ((p.get("extra") or {}).get("yours") or p.get("tags") or ["Fortinet"])[0]
        title = p["title"] if product.lower() in p["title"].lower() else f"{product}: {p['title']}"
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
    # VulnCheck-only items (CISA and Microsoft don't confirm them) need a strong
    # signal for Act now; otherwise they wait in For awareness.
    vc_only = bool(vc_dates) and not kev_dates and not ms_exploited
    years = [int(c["id"].split("-")[1]) for c in cves if c["id"].count("-") >= 2 and c["id"].split("-")[1].isdigit()]
    old_cve = bool(years) and max(years) < today.year - 1
    vc_strong = (any((c.get("vulncheck") or {}).get("canary") for c in cves)
                 or exploit in ("metasploit", "exploitdb") or (cvss or 0) >= 9 or bool(zw) or bool(ms_info))
    ours = v.get("ours") or []
    # Known only through a TrueNAS impact statement that rates it Low/Medium on
    # TrueNAS: the vendor's rating wins, so at most Patch soon.
    tn_softened = bool(ours) and v.get("oursTrueNASOnly") and bool(tn) and tn.get("level") in ("low", "medium")
    ours_serious = ((cvss or 0) >= 7 or prio in ("high", "critical") or bool(zw)
                    or (bool(tn) and tn.get("level") in ("high", "critical")))
    if done:
        group = "done"
    elif ours and exploited:
        group = "soon" if tn_softened else "act"
    elif ours and ours_serious and not tn_softened:
        group = "soon"
    elif vc_only and not (vc_strong and recent_kev and not old_cve):
        group = "aware"
    elif fn_not_mine and not ours:
        group = "aware"
    elif exploited and (cf_urgent or recent_kev):
        group = "act"
    elif exploited:
        group = "aware"
    elif (cf_urgent or (cvss or 0) >= 9 or prio == "critical" or (epss or 0) >= 0.5
          or (exploit in ("metasploit", "exploitdb") and (cvss or 0) >= 7) or ms_disclosed or tn_urgent or fn_urgent
          or (exploit == "poc" and bool(v["ms"]))):
        group = "soon"
    else:
        group = "aware"

    # "why" as segments: [text, bold]
    why = []
    if ours and not done:
        why += [["You run ", False], [", ".join(ours), True], [". ", False]]
    if done:
        why += [["Marked ", False], [STATE_LABEL[triage["state"]], True], [f" by {triage['by']}.", False]]
    elif exploited:
        why += [["Attackers are using this", True], [f", confirmed by {exploited_by} on {short_date(kev_last)}.", False]]
        if fn_not_mine and not ours:
            why += [[f" Not one of your Fortinet products ({', '.join(fn.get('products') or [])}).", False]]
        if exploited_by == "VulnCheck":
            why += [[" Not on CISA's list yet.", False]]
            if group == "aware" and not ours:
                product = v["vcs"][0]["title"] if v["vcs"] else "it"
                why += [[f" Check whether you run {product}." + (" (An older CVE, only recently reported as exploited.)" if old_cve else ""), False]]
        if zw:
            why += [[" ", False], *cf_says(zw, ".")]
        if not recent_kev and not cf_urgent and not fn_not_mine and not ours:
            product = v["kevs"][0]["title"] if v["kevs"] else "it"
            why += [[f" Reported over 2 weeks ago; check whether you run {product}.", False]]
    elif ms_disclosed:
        why += [["Publicly disclosed", True], [" before Microsoft's fix (a zero-day); not seen exploited yet.", False]]
    elif zw:
        why += cf_says(zw, ". Not confirmed as exploited yet.")
    elif p["source"] == "fortinet" and fn:
        why += [["Fortinet advisory for your ", False], [", ".join(fn["yours"] or fn["products"]), True],
                [f" (CVSS {fn['cvss']:.1f})." if fn.get("cvss") is not None else ".", False]]
    elif p["source"] == "truenas" and tn:
        if tn.get("level") == "none":
            why += [["TrueNAS itself is not affected", True],
                    [f"; {tn['impact']}" if tn.get("impact") else ".", False]]
        elif tn.get("rating"):
            why += [["TrueNAS rates the impact ", False], [tn["rating"], True], [".", False]]
        else:
            why += [["TrueNAS published a security notice.", False]]
        if tn.get("level") in ("high", "critical") and not tn_urgent:
            why += [[f" Published {short_date(tn.get('published'))}; check your TrueNAS has the update.", False]]
        m = re.search(r"\b(critical|high|medium|low)\b", tn.get("upstream") or "", re.I)
        up = m.group(1).lower() if m else None
        if up and tn.get("level") not in (None, "none") and TN.LEVELS.index(up) > TN.LEVELS.index(tn["level"]):
            why += [[f" Rated {up} elsewhere, lower on TrueNAS.", False]]
    elif v["usnPrimary"]:
        why += [["Ubuntu rates this ", False], [prio, True],
                [f"; updates are out for {', '.join(ubuntu['fixed']) or 'supported releases'}.", False]]
    elif cvss is not None and cvss >= 9:
        why += [["Critical severity", True], [f" ({cvss:.1f} out of 10).", False]]
    if not done and exploit in ("metasploit", "exploitdb"):
        why += [[" Exploit code is public", True],
                [" (Metasploit module)." if exploit == "metasploit" else " (Exploit-DB).", False]]
    elif not done and exploit == "poc" and not exploited and v["ms"]:
        why += [[" Unverified public exploit code", True], [" is on GitHub. Don't run it: some of these are fakes or malware.", False]]
    elif not done and exploit == "poc" and not exploited:
        why += [[" Proof-of-concept code is on GitHub.", False]]
    if not done and not exploited and epss_trend == "rising":
        why += [[" Exploit chance is rising", True], [f" (from {epss_was * 100:.1f}% a month ago).", False]]
    if not done and tn_softened:
        why += [[f" TrueNAS rates the impact {tn.get('rating') or tn.get('level')} on TrueNAS, so Patch soon rather than Act now.", False]]
    if not done and fn and fn_mine:
        if p["source"] != "fortinet":
            why += [[" Affects your ", False], [", ".join(fn["yours"]), True], [f" (Fortinet {fn['id']}).", False]]
        if fn.get("fixes"):
            why += [[" Fortinet fix: ", False], [fn["fixes"][0], True], [".", False]]
        if "virtual patch" in (fn.get("workaround") or "").lower():
            why += [[" An IPS virtual patch is available.", False]]
    elif not done and fn and fn.get("kind") == "statement" and p["source"] != "fortinet":
        why += [[" Fortinet published a statement on this.", False]]
    if not done and tn and p["source"] != "truenas" and not tn_softened:
        why += [[" TrueNAS itself is not affected." if tn.get("level") == "none"
                 else f" TrueNAS rates the impact {tn.get('rating') or 'unrated'}.", False]]
    if not done and tn and tn.get("fixedIn"):
        why += [[" TrueNAS fix: ", False], [tn["fixedIn"], True], [".", False]]
    if not done and ms_info:
        why += [[f" Microsoft fix out ({ms_info[0]['releaseLabel']} updates).", False]]
    if not done and not v["usnPrimary"]:
        if ubuntu["fixed"]:
            why += [[f" Ubuntu fix out for {', '.join(ubuntu['fixed'])}.", False]]
        elif ubuntu["pending"]:
            why += [[" Ubuntu fix still pending.", False]]

    reported = [s for s, on in (("Cloudflare", bool(zw)), ("CISA", bool(kev_dates)), ("VulnCheck", bool(vc_dates)),
                                ("Microsoft", bool(ms_info)), ("TrueNAS", bool(tn)), ("Fortinet", bool(fn)),
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
        "vcIds": [x["id"] for x in v["vcs"]], "vcLeadDays": vc_lead,
        "tnIds": [x["id"] for x in v["tns"]], "truenas": tn,
        "fnIds": [x["id"] for x in v["fns"]], "fortinet": fn, "ours": ours,
        "microsoft": ms_info[0] if ms_info else None,
        "latest": _max([i.get("updated") or i.get("published") for i in
                        [zw, *v["kevs"], *v["usns"], *v["ms"], *v["vcs"], *v["tns"], *v["fns"]] if i]) or "",
        "triage": triage,
    }


def why_text(v):
    return "".join(t for t, _ in v["why"]).strip()
