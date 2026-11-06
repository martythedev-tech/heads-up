"""Is each source still working? Decides when to tell people that one isn't.

A single failed fetch is normal (a DNS blip, a slow server), so a source only
counts as down once it has kept failing past its next retry, or has gone quiet
for much longer than its schedule. Each incident alerts once, and once more
when it recovers.
"""
import json

HOUR = 3600
# name: (what people call it, how often it runs in seconds, can it go quiet?)
# NVD and GitHub only run when there is something to look up, so silence is fine there.
WATCHED = {
    "zerowire": ("Cloudflare", HOUR // 2, True),
    "kev": ("CISA", 3 * HOUR, True),
    "ubuntu": ("Ubuntu", HOUR, True),
    "msrc": ("Microsoft", 6 * HOUR, True),
    "vulncheck": ("VulnCheck KEV", 6 * HOUR, True),
    "truenas": ("TrueNAS", 6 * HOUR, True),
    "fortinet": ("Fortinet", 6 * HOUR, True),
    "exploits": ("Exploit-DB and Metasploit", 24 * HOUR, True),
    "epss": ("exploit chance (FIRST)", HOUR, True),
    "radar": ("Cloudflare Radar", HOUR, True),
    "nvd": ("severity scores (NVD)", 2 * HOUR, False),
    "poc": ("GitHub exploit check", HOUR, False),
    "backup": ("the nightly backup", 24 * HOUR, True),
}


def _load(db):
    row = db.execute("SELECT value FROM meta WHERE key='source_health'").fetchone()
    return json.loads(row[0]) if row else {"failing": {}, "down": {}}


def update(db, t):
    """Record each source's state. Returns (newly down, recovered) as {name: reason}."""
    state = _load(db)
    failing, down = state["failing"], state["down"]
    sources = {r["name"]: r for r in db.execute("SELECT * FROM sources")}
    newly, recovered = {}, {}
    for name, (label, every, can_go_quiet) in WATCHED.items():
        row = sources.get(name)
        reason = None
        if row is None:  # never ran, or turned off (an optional source with no token)
            failing.pop(name, None)
        else:
            ok_at, err_at = row["ok_at"] or 0, row["err_at"] or 0
            if row["error"] and err_at >= ok_at:
                since = failing.setdefault(name, t)
                if t - since >= max(HOUR, 1.5 * every):
                    reason = f"{label}: failing ({str(row['error'])[:160]})"
            else:
                failing.pop(name, None)
            if not reason and can_go_quiet and ok_at and t - ok_at > 2 * every + 900:
                reason = f"{label}: no update for {round((t - ok_at) / HOUR)} hours"
        if reason and name not in down:
            newly[name] = down[name] = reason
        elif not reason and name in down:
            recovered[name] = down.pop(name)
    db.execute("INSERT OR REPLACE INTO meta VALUES('source_health', ?)", (json.dumps(state),))
    return newly, recovered


def message(newly, recovered):
    """-> (title, body) for an alert, or None if there is nothing to say."""
    label = lambda n: WATCHED[n][0]
    if newly:
        names = ", ".join(label(n) for n in newly)
        body = " ".join(f"{r}." for r in newly.values()) + " The page keeps showing the last good data."
        if recovered:
            body += " Working again: " + ", ".join(label(n) for n in recovered) + "."
        return f"Heads Up: {names} stopped working", body
    if recovered:
        names = ", ".join(label(n) for n in recovered)
        return f"Heads Up: {names} working again", "The page is up to date for this source again."
    return None
