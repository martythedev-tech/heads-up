"""Versions you run (What we run) against the fixed versions vendors publish.

Only sources that state fixes in a form that can be compared take part:
  Fortinet  one line per release line, e.g. "FortiOS 7.4: Upgrade to 7.4.9 or above",
            "... Upgrade to upcoming 7.6.9 or above" or "... Migrate to a fixed release"
  TrueNAS   the "Fixed in" field, e.g. "TrueNAS SCALE 25.10.8 and later (25.10 train)"

A version is compared within its release line (the first two numbers: 7.4.8 is
on the 7.4 line). Anything that can't be decided stays open: a line with no
fix listed, wording that doesn't parse, or a product with no version entered.
"""
import re

VER = re.compile(r"(?<![\d.])\d+(?:\.\d+)+")
FN_LINE = re.compile(r"^(?P<product>.+?)\s+(?P<train>\d+\.\d+)(?:\.x)?\s*:\s*(?P<text>.+)$", re.I)
FN_UPGRADE = re.compile(r"Upgrade to (?P<upcoming>upcoming )?(?:version )?(?P<ver>\d+(?:\.\d+)+)", re.I)
FN_MIGRATE = re.compile(r"Migrate to a fixed release", re.I)


def parse(text):
    """'7.4.8, 7.6.3' -> ['7.4.8', '7.6.3'] (versions need at least two numbers)."""
    return list(dict.fromkeys(VER.findall(str(text or ""))))


def key(ver):
    return tuple(int(x) for x in ver.split("."))


def line_of(ver):
    return key(ver)[:2]


def fortinet_fixes(lines):
    """Fortinet fix lines -> [{product, line, fixed, upcoming, migrate}] (lines that don't parse are skipped)."""
    out = []
    for raw in lines or []:
        m = FN_LINE.match(raw.strip())
        if not m:
            continue
        up = FN_UPGRADE.search(m["text"])
        if up:
            out.append({"product": m["product"].strip(), "line": key(m["train"]), "fixed": up["ver"],
                        "upcoming": bool(up["upcoming"]), "migrate": False, "vendor": "Fortinet"})
        elif FN_MIGRATE.search(m["text"]):
            out.append({"product": m["product"].strip(), "line": key(m["train"]), "fixed": None,
                        "upcoming": False, "migrate": True, "vendor": "Fortinet"})
    return out


def truenas_fixes(fixed_in):
    """'TrueNAS SCALE 25.10.8 and later (25.10 train)' -> one fix per full version named."""
    return [{"product": "TrueNAS", "line": line_of(v), "fixed": v, "upcoming": False, "migrate": False, "vendor": "TrueNAS"}
            for v in parse(fixed_in) if len(key(v)) >= 3]


def check(entries, fixes):
    """entries: the What we run entries this item matched, each {name, terms, version}.
    fixes: everything fortinet_fixes / truenas_fixes found for this item, all vendors together.

    Returns None when no entry with versions has fix data here, else
    {"fixed": bool (every matched entry is on a fixed version), "notes": [...]}, where
    each note is {product, version, state, fix}; state is fixed / upgrade / upcoming /
    migrate / unlisted, or noversion for a matched entry with no version entered.
    """
    notes, checked = [], False
    for e in entries:
        terms = {t.lower() for t in e.get("terms") or []} | {e["name"].lower()}
        mine = [f for f in fixes if f["product"].lower() in terms]
        versions = parse(e.get("version"))
        if not mine:
            notes.append({"product": e["name"], "version": None, "state": "nodata", "fix": None})
            continue
        if not versions:
            notes.append({"product": e["name"], "version": None, "state": "noversion", "fix": None})
            continue
        checked = True
        for ver in versions:
            f = next((f for f in mine if f["line"] == line_of(ver)), None)
            product = f["product"] if f else mine[0]["product"]
            vendor = (f or mine[0])["vendor"]
            if f is None:
                state, fix = "unlisted", None
            elif f["migrate"]:
                state, fix = "migrate", None
            elif key(ver) >= key(f["fixed"]):
                state, fix = "fixed", f["fixed"]
            else:
                state, fix = ("upcoming" if f["upcoming"] else "upgrade"), f["fixed"]
            notes.append({"product": product, "version": ver, "state": state, "fix": fix, "vendor": vendor})
    if not checked:
        return None
    return {"fixed": all(n["state"] == "fixed" for n in notes), "notes": notes}


def why(result):
    """'why' segments ([text, bold]) for an item that is still open."""
    out = []
    for n in result["notes"]:
        if n["state"] in ("nodata", "noversion"):
            continue
        run = f" You run {n['product']} {n['version']}"
        if n["state"] == "fixed":
            out += [[run + ": ", False], ["already fixed", True], [f" (fix {n['fix']}).", False]]
        elif n["state"] == "upgrade":
            out += [[run + ": ", False], [f"upgrade to {n['fix']}", True], [".", False]]
        elif n["state"] == "upcoming":
            out += [[run + ": ", False], [f"upgrade to {n['fix']}", True], [" when it's released.", False]]
        elif n["state"] == "migrate":
            line = ".".join(map(str, line_of(n["version"])))
            out += [[run + ": ", False], [f"no fix on the {line} line", True], [", move to a fixed release.", False]]
        else:
            line = ".".join(map(str, line_of(n["version"])))
            out += [[run + f": {n['vendor']} lists no fix for the {line} line", False],
                    [" (usually means it isn't affected; check the advisory).", False]]
    return out


def why_done(result):
    """'why' segments for an item closed because every version you run is fixed."""
    runs = ", ".join(f"{n['product']} {n['version']} (fix {n['fix']})" for n in result["notes"] if n["state"] == "fixed")
    return [["Fixed in the version you run", True], [f": {runs}.", False]]
