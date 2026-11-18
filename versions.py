"""Versions you run (What we run) against the fixed versions vendors publish.

Only sources that state fixes in a form that can be compared take part:
  Fortinet  one line per release line, e.g. "FortiOS 7.4: Upgrade to 7.4.9 or above",
            "... Upgrade to upcoming 7.6.9 or above" or "... Migrate to a fixed release"
  TrueNAS   the "Fixed in" field, e.g. "TrueNAS SCALE 25.10.8 and later (25.10 train)"

When the fix lines leave a product out (Fortinet's files sometimes do), the
affected version ranges in the same file decide: inside a range is affected,
above every range on that line is fixed, a line with no affected range isn't
affected.

A version is compared within its release line (the first two numbers: 7.4.8 is
on the 7.4 line). "7.4.x" or a bare "7.4" means "somewhere on the 7.4 line"
(several boxes or clients on different patch levels): it is never counted as
fixed, it says which version to check for instead. Anything that can't be decided stays open: a line with no
fix listed, wording that doesn't parse, or a product with no version entered.
"""
import re

VER = re.compile(r"(?<![\d.])\d+(?:\.\d+)+(?:\.[xX*])?")
FN_LINE = re.compile(r"^(?P<product>.+?)\s+(?P<train>\d+\.\d+)(?:\.x)?\s*:\s*(?P<text>.+)$", re.I)
FN_UPGRADE = re.compile(r"Upgrade to (?P<upcoming>upcoming )?(?:version )?(?P<ver>\d+(?:\.\d+)+)", re.I)
FN_MIGRATE = re.compile(r"Migrate to a fixed release", re.I)


def parse(text):
    """'7.4.8, 7.6.x' -> ['7.4.8', '7.6.x'] (versions need at least two numbers)."""
    return list(dict.fromkeys(v[:-1] + "x" if v[-1] in "X*" else v for v in VER.findall(str(text or ""))))


def key(ver):
    return tuple(int(x) for x in ver.split(".") if x.isdigit())


def whole_line(ver):
    """'7.4.x' or '7.4': a release line, not an exact version."""
    return ver.endswith(".x") or len(key(ver)) < 3


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


def fortinet_ranges(ranges):
    """Stored ranges (fortinet.parse_ranges) -> the same with keys ready for comparing."""
    out = []
    for r in ranges or []:
        try:
            out.append({**r, "line": tuple(r["line"]), "lo": key(r["min"]) if r.get("min") else None,
                        "hi": key(r["max"]) if r.get("max") else None})
        except (KeyError, ValueError, TypeError):
            continue
    return out


def from_ranges(product, ver, ranges):
    """Decide one version from Fortinet's affected ranges when no fix line names the product.
    -> (state, fix, upto) or None when there are no ranges for the product."""
    mine = [r for r in ranges if r["product"].lower() == product.lower()]
    if not mine:
        return None
    on_line = [r for r in mine if r["affected"] and r["line"] == line_of(ver)]
    if not on_line:
        return "notaffected", None, None
    if any(r["all"] for r in on_line):
        return "affectedline", None, None
    upto = max(on_line, key=lambda r: r["hi"])["max"]
    if whole_line(ver):
        return "rangeline", None, upto
    k = key(ver)
    if any(r["lo"] <= k <= r["hi"] for r in on_line):
        return "affected", None, upto
    if k > key(upto):
        return "fixed", None, upto
    return "notaffected", None, None


def check(entries, fixes, ranges=()):
    """entries: the What we run entries this item matched, each {name, terms, version}.
    fixes: everything fortinet_fixes / truenas_fixes found for this item, all vendors together.
    ranges: Fortinet's affected version ranges (fortinet_ranges), used for a product
    the fix lines leave out.

    Returns None when no entry with versions has data here, else
    {"fixed": bool (every matched entry is on a fixed or unaffected version), "notes": [...]},
    where each note is {product, version, state, fix, upto}; state is
      fixed / notaffected                     counts as done
      upgrade / upcoming / migrate / line     from a fix line (line = a whole line like 7.4.x)
      affected / affectedline / rangeline     from the ranges (no fix version known)
      unlisted                                a fix line exists for another line only
      nodata / noversion                      nothing to compare, or no version entered
    """
    notes, checked = [], False
    for e in entries:
        terms = {t.lower() for t in e.get("terms") or []} | {e["name"].lower()}
        mine = [f for f in fixes if f["product"].lower() in terms]
        mine_r = [r for r in ranges if r["product"].lower() in terms]
        versions = parse(e.get("version"))
        if not mine and not mine_r:
            notes.append({"product": e["name"], "version": None, "state": "nodata", "fix": None})
            continue
        if not versions:
            notes.append({"product": e["name"], "version": None, "state": "noversion", "fix": None})
            continue
        checked = True
        for ver in versions:
            f = next((f for f in mine if f["line"] == line_of(ver)), None)
            upto = None
            if f is None:
                # the fix lines don't cover this product or line: Fortinet's ranges can
                product = next((r["product"] for r in mine_r if r["affected"]), None) or \
                    (mine_r[0]["product"] if mine_r else mine[0]["product"])
                vendor = "Fortinet" if mine_r else mine[0]["vendor"]
                decided = from_ranges(product, ver, mine_r) if mine_r else None
                state, fix, upto = decided or ("unlisted", None, None)
            else:
                product, vendor = f["product"], f["vendor"]
                if f["migrate"]:
                    state, fix = "migrate", None
                elif whole_line(ver):
                    state, fix = ("upcoming" if f["upcoming"] else "line"), f["fixed"]
                elif key(ver) >= key(f["fixed"]):
                    state, fix = "fixed", f["fixed"]
                else:
                    state, fix = ("upcoming" if f["upcoming"] else "upgrade"), f["fixed"]
            notes.append({"product": product, "version": ver, "state": state, "fix": fix, "upto": upto,
                          "vendor": vendor})
    if not checked:
        return None
    return {"fixed": all(n["state"] in ("fixed", "notaffected") for n in notes), "notes": notes}


def _line(ver):
    return ".".join(map(str, line_of(ver)))


def why(result):
    """'why' segments ([text, bold]) for an item that is still open."""
    out = []
    for n in result["notes"]:
        if n["state"] in ("nodata", "noversion"):
            continue
        run = f" You run {n['product']} {n['version']}"
        st = n["state"]
        if st == "fixed":
            basis = f"fix {n['fix']}" if n.get("fix") else f"affected up to {n['upto']}"
            out += [[run + ": ", False], ["already fixed", True], [f" ({basis}).", False]]
        elif st == "notaffected":
            out += [[run + ": ", False], ["not affected", True], [f" (Fortinet doesn't list it as affected).", False]]
        elif st == "upgrade":
            out += [[run + ": ", False], [f"upgrade to {n['fix']}", True], [".", False]]
        elif st == "line":
            out += [[run + ": ", False], [f"make sure each one is on {n['fix']} or later", True], [".", False]]
        elif st == "rangeline":
            out += [[run + ": ", False], [f"make sure each one is newer than {n['upto']}", True], [".", False]]
        elif st == "upcoming":
            out += [[run + ": ", False], [f"upgrade to {n['fix']}", True], [" when it's released.", False]]
        elif st == "migrate":
            out += [[run + ": ", False], [f"no fix on the {_line(n['version'])} line", True], [", move to a fixed release.", False]]
        elif st == "affectedline":
            out += [[run + ": ", False], [f"the whole {_line(n['version'])} line is affected", True],
                    [", move to a fixed release.", False]]
        elif st == "affected":
            out += [[run + ": ", False], ["affected", True],
                    [f" (up to {n['upto']}); Fortinet gives no fix version here, check the advisory.", False]]
        else:
            out += [[run + f": {n['vendor']} lists no fix for the {_line(n['version'])} line", False],
                    [" (usually means it isn't affected; check the advisory).", False]]
    return out


def why_done(result):
    """'why' segments for an item closed because every version you run is fixed or not affected."""
    def basis(n):
        if n["state"] == "notaffected":
            return "not listed as affected"
        return f"fix {n['fix']}" if n.get("fix") else f"affected up to {n['upto']}"
    runs = ", ".join(f"{n['product']} {n['version']} ({basis(n)})" for n in result["notes"]
                     if n["state"] in ("fixed", "notaffected"))
    return [["Fixed in the version you run", True], [f": {runs}.", False]]
