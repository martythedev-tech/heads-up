"use strict";

const $ = (s, el = document) => el.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const STATE_LABEL = { untriaged: "Not checked yet", investigating: "Investigating", not_affected: "Not affected", patched: "Patched" };
const REL_NAME = { resolute: "26.04", noble: "24.04", jammy: "22.04", focal: "20.04", stonking: "26.10", questing: "25.10" };
const rel = (r) => REL_NAME[r] || r;

const SOURCES = {
  cf: { name: "Cloudflare", what: "Expert write-ups of the most important internet-facing vulnerabilities, with what to do.", feeds: ["zerowire"], url: "https://radar.cloudflare.com/security/zero-wire", stale: 2 * 3600 },
  cisa: { name: "CISA", what: "US government list of vulnerabilities attackers are confirmed to be using.", feeds: ["kev"], url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", stale: 8 * 3600 },
  ubu: { name: "Ubuntu", what: "Security updates for Ubuntu and whether each release has a fix yet.", feeds: ["ubuntu", "osv"], url: "https://ubuntu.com/security/notices", stale: 3 * 3600 },
  ms: { name: "Microsoft", what: "Patch Tuesday: Microsoft's monthly security fixes, including zero-days.", feeds: ["msrc"], url: "https://msrc.microsoft.com/update-guide", stale: 8 * 3600 },
  ex: { name: "Exploit code", what: "Public attack code: Metasploit modules, Exploit-DB and proof-of-concepts on GitHub.", feeds: ["exploits", "poc"], url: "https://www.exploit-db.com", stale: 26 * 3600 },
};
const GROUPS = {
  act: { title: "Act now", explain: "Attackers are using these. Check whether you run them, then patch.", cls: "g-act" },
  soon: { title: "Patch soon", explain: "Critical, but not confirmed as being exploited yet.", cls: "g-soon" },
  aware: { title: "For awareness", explain: "Exploited over 2 weeks ago, reference briefings, and high-priority Ubuntu updates.", cls: "g-aware" },
  done: { title: "Done", explain: "Marked Patched or Not affected.", cls: "g-done" },
};

let data = null;
let vulns = [];
let query = "";
let openId = null;
const shown = { act: 25, soon: 25, aware: 12, done: 25 };
let showDone = false;

const prevVisit = (() => { try { return Number(localStorage.getItem("hu.lastVisit")) || 0; } catch { return 0; } })();
setTimeout(() => { try { localStorage.setItem("hu.lastVisit", String(Date.now() / 1000)); } catch {} }, 15000);

// --- small helpers ---------------------------------------------------------------

function ago(ts) {
  if (!ts) return "never";
  const s = Math.max(0, data.now - ts);
  if (s < 90) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400 * 2) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} days ago`;
}
function day(iso) {
  if (!iso) return "";
  const d = new Date(iso.length === 10 ? iso + "T00:00:00" : iso);
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric", year: d.getFullYear() === new Date().getFullYear() ? undefined : "numeric" });
}
const daysAgoIso = (n) => new Date(Date.now() - n * 86400000).toISOString().slice(0, 10);
const isNew = (it) => prevVisit && it.changedAt > prevVisit;
const max = (xs) => xs.reduce((a, b) => (b != null && (a == null || b > a) ? b : a), null);

function severity(cvss) {
  if (cvss == null) return null;
  if (cvss >= 9) return { label: "Critical", cls: "crit" };
  if (cvss >= 7) return { label: "High", cls: "high" };
  if (cvss >= 4) return { label: "Medium", cls: "med" };
  return { label: "Low", cls: "low" };
}
function exploitChance(epss) {
  if (epss == null) return null;
  const pct = epss * 100;
  const label = epss >= 0.5 ? "Very high" : epss >= 0.1 ? "High" : epss >= 0.01 ? "Moderate" : "Low";
  const cls = epss >= 0.5 ? "crit" : epss >= 0.1 ? "high" : epss >= 0.01 ? "med" : "low";
  return { label, cls, pct: pct >= 10 ? pct.toFixed(0) : pct.toFixed(1) };
}
function kevShort(it) {
  // "Ivanti Connect Secure Missing Authentication ... Vulnerability" -> "Missing Authentication ..."
  let n = String(it.headline || "");
  const vendor = it.tags[0] || "";
  const product = it.title.toLowerCase().startsWith(vendor.toLowerCase() + " ") ? it.title.slice(vendor.length + 1) : it.title;
  for (let i = 0; i < 3; i++) {
    for (const w of [it.title, vendor, product]) if (w && n.toLowerCase().startsWith(w.toLowerCase() + " ")) n = n.slice(w.length + 1);
  }
  return n.replace(/ Vulnerabilit(y|ies)$/, "");
}

// --- one entry per vulnerability ----------------------------------------------------

function buildVulns() {
  // Grouping happens on the server (vulns.py) so the page and the webhooks agree.
  const byId = new Map(data.items.map((i) => [i.id, i]));
  return data.vulns.map((src) => {
    const v = { ...src };
    v.primary = byId.get(src.id) || { cves: [], tags: [] };
    v.zw = src.zwId ? byId.get(src.zwId) : null;
    v.kevs = src.kevIds.map((id) => byId.get(id)).filter(Boolean);
    v.usns = src.usnIds.map((id) => byId.get(id)).filter(Boolean);
    v.ms = (src.msIds || []).map((id) => byId.get(id)).filter(Boolean);
    v.cveList = v.primary.cves || [];
    v.items = [v.zw, ...v.kevs, ...v.usns, ...v.ms].filter(Boolean);
    v.isNew = v.items.some(isNew);
    v.done = v.group === "done";
    v.why = src.why.map(([t, bold]) => (bold ? `<b>${esc(t)}</b>` : esc(t))).join("");
    return v;
  });
}

function matches(v) {
  if (!query) return true;
  const hay = [v.title, v.desc, v.id, ...v.items.flatMap((i) => [i.title, i.headline, i.tags.join(" "), i.extra?.packages?.join(" ")]),
    ...v.cveList.slice(0, 50).map((c) => c.id)].join(" ").toLowerCase();
  return query.split(/\s+/).every((w) => hay.includes(w));
}

// --- pieces ---------------------------------------------------------------------

function badges(v) {
  const b = [];
  if (v.zw) b.push(`<span class="badge cf">Cloudflare <span class="detail">briefing</span></span>`);
  if (v.cveList.some((c) => c.kev)) b.push(`<span class="badge cisa">CISA <span class="detail">exploited</span></span>`);
  if (v.microsoft) b.push(`<span class="badge ms">Microsoft <span class="detail">${v.microsoft.exploited ? "zero-day, fixed" : v.microsoft.disclosed ? "disclosed, fixed" : "fix out"}</span></span>`);
  if (v.exploit) b.push(`<span class="badge ex">${{ metasploit: "Metasploit", exploitdb: "Exploit-DB", poc: "GitHub" }[v.exploit]} <span class="detail">${v.exploit === "poc" ? "proof of concept" : "exploit"}</span></span>`);
  if (v.ubuntu.fixed.length) b.push(`<span class="badge ubu">Ubuntu <span class="detail">fix out</span></span>`);
  else if (v.ubuntu.pending.length) b.push(`<span class="badge ubu">Ubuntu <span class="detail">fix pending</span></span>`);
  return b.join("");
}

function facts(v) {
  const sev = severity(v.cvss);
  const ex = exploitChance(v.epss);
  const rows = [];
  if (v.usnPrimary) {
    const pr = v.ubuntuPriority;
    rows.push(["Ubuntu priority", `<span class="v ${pr === "critical" ? "crit" : "high"}">${esc(pr[0].toUpperCase() + pr.slice(1))}</span>`]);
    rows.push(["Fixes", `<span class="v none">${v.cveList.length} CVE${v.cveList.length === 1 ? "" : "s"}</span>`]);
  } else {
    rows.push(["Severity", sev ? `<span class="v ${sev.cls}">${sev.label} · ${v.cvss.toFixed(1)}</span>` : `<span class="v none">Not scored yet</span>`]);
    rows.push(["Exploited", v.exploited ? `<span class="v crit">Yes</span>` : `<span class="v none">Not confirmed</span>`]);
  }
  const arrow = v.epssTrend === "rising" ? " ↑" : v.epssTrend === "falling" ? " ↓" : "";
  const was = v.epssWas != null ? `, ${(v.epssWas * 100).toFixed(1)}% a month ago` : "";
  if (v.exploited) rows.push(["Exploit chance", `<span class="v crit" title="CISA has confirmed attacks">Already happening</span>`]);
  else rows.push(["Exploit chance", ex ? `<span class="v ${ex.cls}" title="${ex.pct}% chance of exploitation in the next 30 days${was} (FIRST EPSS)">${ex.label}${arrow}</span>` : `<span class="v none">Unknown</span>`]);
  if (!v.usnPrimary) {
    const pe = { metasploit: ["crit", "Metasploit"], exploitdb: ["high", "Exploit-DB"], poc: ["med", "GitHub PoC"] }[v.exploit];
    rows.push(["Public exploit", pe ? `<span class="v ${pe[0]}">${pe[1]}</span>` : `<span class="v none">None known</span>`]);
  }
  return `<div class="facts">${rows.map(([k, val]) => `<div class="fact"><span class="k">${k}</span>${val}</div>`).join("")}</div>`;
}

function triageCell(v) {
  const s = v.triage?.state || "untriaged";
  return `<span class="triage tri-${s}"><span class="tri-dot"></span>${STATE_LABEL[s]}</span>${v.triage && s !== "untriaged" ? `<span class="by">${esc(v.triage.by)}, ${ago(v.triage.at)}</span>` : ""}`;
}

// --- render ---------------------------------------------------------------------

function renderSources() {
  const src = data.sources || {};
  $("#sources").innerHTML = Object.entries(SOURCES).map(([key, s]) => {
    const st = s.feeds.map((f) => src[f] || {});
    const ok = max(st.map((x) => x.ok_at));
    const failing = st.some((x) => x.error && (!x.ok_at || x.err_at > x.ok_at));
    const cls = failing ? "bad" : ok && data.now - ok < s.stale ? "ok" : ok ? "warn" : "";
    const text = failing ? "Last check failed, showing older data" : ok ? `Checked ${ago(ok)}` : "Not checked yet";
    return `<div class="src-card"><a class="badge ${key}" href="${s.url}" target="_blank" rel="noopener">${s.name}</a>
      <div class="what">${s.what}</div>
      <div class="fresh"><span class="dot ${cls}"></span>${text}</div></div>`;
  }).join("");
}

function renderSummary(byGroup) {
  $("#summary").innerHTML = Object.entries(GROUPS).map(([k, g]) => {
    const n = byGroup[k].length;
    return `<button class="sum ${g.cls} ${n ? "" : "zero"}" data-jump="${k}"><div class="n">${n}</div><div class="t">${g.title}</div><div class="d">${g.explain}</div></button>`;
  }).join("");
}

function renderGroups(byGroup) {
  $("#groups").innerHTML = Object.entries(GROUPS).map(([k, g]) => {
    const list = byGroup[k];
    const collapsed = k === "done" && !showDone;
    const rows = collapsed ? "" : list.slice(0, shown[k]).map((v) => `
      <button class="vrow" data-id="${esc(v.id)}">
        <div>
          <div class="v-title">${v.isNew ? `<span class="new">${v.items.some((i) => isNew(i) && i.firstSeen <= prevVisit) ? "UPDATED" : "NEW"}</span>` : ""}${esc(v.title)}</div>
          <div class="v-desc">${esc(v.desc)}</div>
          <div class="v-why">${v.why}</div>
        </div>
        ${facts(v)}
        <div class="sources-col">${badges(v)}</div>
        <div class="status-col">${triageCell(v)}</div>
      </button>`).join("");
    const more = !collapsed && list.length > shown[k] ? `<button class="more" data-more="${k}">Show ${list.length - shown[k]} more</button>` : "";
    const toggle = k === "done" && list.length ? `<button class="ghost toggle" data-toggle-done>${showDone ? "Hide" : "Show"}</button>` : "";
    const body = collapsed ? "" : list.length
      ? `<div class="table"><div class="cols"><span>Vulnerability</span><span>Risk</span><span>Reported by</span><span>Our status</span></div>${rows}${more}</div>`
      : `<div class="table"><div class="empty">${query ? "Nothing matches your search." : "Nothing here right now."}</div></div>`;
    return `<section class="group ${g.cls}" id="group-${k}">
      <div class="g-head"><h2>${g.title}</h2><span class="count">${list.length}</span><span class="explain">${g.explain}</span>${toggle}</div>
      ${body}</section>`;
  }).join("");
}

function render() {
  if (!data) return;
  vulns = buildVulns();
  const byGroup = { act: [], soon: [], aware: [], done: [] };
  const rank = (v) => (v.zw?.category === "Needs attention" ? 1 : 0);
  for (const v of vulns.filter(matches)) byGroup[v.group].push(v);
  for (const list of Object.values(byGroup)) {
    list.sort((a, b) => (rank(b) - rank(a)) || String(b.kevLast || b.latest).localeCompare(String(a.kevLast || a.latest)));
  }
  renderSources();
  renderSummary(byGroup);
  renderGroups(byGroup);
  $("#account").textContent = data.user ? data.user.name : "Sign in";
  $("#account").title = data.user ? "Your account" : "Sign in to track status";
  $("#account").hidden = !data.canSignIn && !data.user;
  $("#refresh").hidden = !data.user;
  $("#hooks-btn").hidden = data.user?.role !== "admin" || !data.webhooksAvailable;
  if ((hooksOpen || accountOpen) && !data.user) closeDrawer();
  $("#version").textContent = `Heads Up ${data.version}`;
  if (openId) renderDrawer(openId, true);
}

// --- drawer -----------------------------------------------------------------------

function section(body, name) {
  const m = (body || "").match(new RegExp(`<h2>${name}</h2>([\\s\\S]*?)(?=<h[23]>|$)`));
  return m ? m[1] : "";
}

function cfBox(v) {
  const it = v.zw;
  if (!it) return "";
  const todo = section(it.body, "What to do now");
  const who = section(it.body, "Who should investigate");
  return `<div class="box src-cf"><h4><span class="badge cf">Cloudflare</span> says: ${esc(it.headline)}
      <span class="muted small">checked ${esc(day(it.updated))}</span>
      <a class="small" href="${esc(it.link)}" target="_blank" rel="noopener">Read on Cloudflare ↗</a></h4>
    <div class="prose">
      ${todo ? `<div class="label">What to do now</div>${todo}` : `<p>${esc(it.summary)}</p>`}
      ${who ? `<div class="label">Who should check</div>${who}` : ""}
      <details class="full"><summary>Full briefing (what happened, timeline, sources)</summary>${it.body}</details>
    </div></div>`;
}

function cisaBox(v) {
  const kevCves = v.cveList.filter((c) => c.kev);
  if (!kevCves.length) return "";
  const items = new Map(v.kevs.map((k) => [k.cves[0]?.id, k]));
  return `<div class="box src-cisa"><h4><span class="badge cisa">CISA</span> confirmed exploited</h4>
    ${kevCves.map((c) => {
      const it = items.get(c.id);
      return `<div class="kv">
        <span class="k">Vulnerability</span><span><a class="mono" href="https://nvd.nist.gov/vuln/detail/${esc(c.id)}" target="_blank" rel="noopener">${esc(c.id)}</a>${it ? ` · ${esc(kevShort(it))}` : ""}</span>
        <span class="k">Added to the list</span><span>${esc(day(c.kev.added))}</span>
        <span class="k">Used in ransomware</span><span>${c.kev.ransomware === "Known" ? `<b class="v crit">Yes</b>` : "Not known"}</span>
        <span class="k">Deadline (US agencies)</span><span>${esc(day(c.kev.due))}</span>
      </div>`;
    }).join(`<hr class="sep">`)}</div>`;
}

function ubuBox(v) {
  const perCve = v.usnPrimary ? [] : v.cveList.filter((c) => c.ubuntu?.length);
  const notIn = !v.usnPrimary && v.cveList.length && v.cveList.every((c) => c.ubuntuPriority === "not-in-ubuntu" || (c.ubuntu && !c.ubuntu.length));
  if (!perCve.length && !v.usns.length) {
    return notIn ? `<div class="box src-ubu"><h4><span class="badge ubu">Ubuntu</span> not affected</h4><p class="muted">Ubuntu doesn't ship the affected software, so Ubuntu updates won't fix this.</p></div>` : "";
  }
  const status = perCve.map((c) => `<div class="kv"><span class="k mono">${esc(c.id)}</span><div>${c.ubuntu.map((p) =>
    `<div class="ubu-st"><b>${esc(p.package)}</b>${Object.entries(p.releases).map(([r, st]) =>
      `<span class="st-${esc(st)}">${esc(rel(r))}: ${esc(st === "released" ? "fixed" : st === "DNE" ? "not shipped" : st)}</span>`).join("")}</div>`).join("")}</div></div>`).join("");
  const notices = v.usns.map((u) => `<li><a href="${esc(u.link)}" target="_blank" rel="noopener">${esc(u.headline)}</a> · ${esc(u.title)} · ${esc(day(u.published))} · ${esc((u.extra?.releases || []).map(rel).join(", "))}</li>`).join("");
  const primary = v.usnPrimary ? `<div class="label">Summary</div><p>${esc(v.primary.summary)}</p>
    ${v.primary.extra?.packages?.length ? `<div class="label">Packages</div><p class="mono small">${esc(v.primary.extra.packages.join("  "))}</p>` : ""}
    ${v.primary.extra?.instructions ? `<div class="label">How to update</div><p>${esc(v.primary.extra.instructions)}</p>` : ""}` : "";
  return `<div class="box src-ubu"><h4><span class="badge ubu">Ubuntu</span> fixes</h4>
    ${primary}
    ${status ? `<div class="label">Fix status per release</div>${status}` : ""}
    ${notices ? `<div class="label">Security notices</div><ul class="small">${notices}</ul>` : ""}</div>`;
}

function sparkline(series, w = 84, h = 22) {
  if (!series || series.length < 2) return "";
  const vals = series.map((p) => p.e);
  const max = Math.max(...vals, 0.0001), min = Math.min(...vals);
  const span = max - min || max;
  const pts = vals.map((e, i) => `${((i / (vals.length - 1)) * (w - 4) + 2).toFixed(1)},${(h - 3 - ((e - min) / span) * (h - 6)).toFixed(1)}`).join(" ");
  const last = pts.split(" ").pop().split(",");
  return `<svg class="spark" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" aria-label="exploit chance over 30 days"><polyline points="${pts}"/><circle cx="${last[0]}" cy="${last[1]}" r="2.5"/></svg>`;
}

function msBox(v) {
  const rows = v.cveList.filter((c) => c.msrc);
  if (!rows.length) return "";
  return `<div class="box src-ms"><h4><span class="badge ms">Microsoft</span> fixed in ${esc(rows[0].msrc.releaseLabel)} security updates</h4>
    ${rows.slice(0, 12).map((c) => `<div class="kv">
      <span class="k">Vulnerability</span><span><a class="mono" href="https://msrc.microsoft.com/update-guide/vulnerability/${esc(c.id)}" target="_blank" rel="noopener">${esc(c.id)}</a> · ${esc(c.msrc.product || "")}</span>
      <span class="k">Microsoft's rating</span><span>${esc(c.msrc.severity || "")}</span>
      <span class="k">Status at release</span><span>${c.msrc.exploited ? `<b class="v crit">Already exploited</b>` : c.msrc.disclosed ? `<b class="v high">Publicly disclosed</b>` : "Not exploited, not disclosed"}</span>
      <span class="k">Microsoft expects</span><span>${esc(c.msrc.likelihood || "–")}</span></div>`).join(`<hr class="sep">`)}
    <p class="small muted">Install the ${esc(rows[0].msrc.releaseLabel)} updates (Windows Update, WSUS or Intune) on affected systems.</p></div>`;
}

function exploitBox(v) {
  if (v.usnPrimary) return "";
  const msf = v.cveList.flatMap((c) => (c.msf || []).map((m) => ({ ...m, cve: c.id })));
  const edb = v.cveList.flatMap((c) => (c.edb || []).map((m) => ({ ...m, cve: c.id })));
  const poc = v.cveList.flatMap((c) => (c.poc || []).map((m) => ({ ...m, cve: c.id })));
  const checked = v.cveList.some((c) => c.poc != null);
  if (!msf.length && !edb.length && !poc.length) {
    return `<div class="box src-ex"><h4><span class="badge ex">Exploit code</span> none known</h4>
      <p class="muted small">${checked ? "No Metasploit module, Exploit-DB entry or GitHub proof-of-concept found." : "No Metasploit module or Exploit-DB entry found. GitHub is checked within the hour."}</p></div>`;
  }
  return `<div class="box src-ex"><h4><span class="badge ex">Exploit code</span> is public</h4>
    ${msf.length ? `<div class="label">Metasploit: ready-made attack module</div><ul class="small">${msf.map((m) =>
      `<li><a href="https://www.rapid7.com/db/modules/${esc(m.name)}/" target="_blank" rel="noopener"><span class="mono">${esc(m.name)}</span></a> · ${esc(m.title)}${m.rank ? ` · rank ${esc(m.rank)}` : ""} <span class="muted">(${esc(m.cve)})</span></li>`).join("")}</ul>` : ""}
    ${edb.length ? `<div class="label">Exploit-DB: published exploit code</div><ul class="small">${edb.map((m) =>
      `<li><a href="https://www.exploit-db.com/exploits/${esc(m.id)}" target="_blank" rel="noopener">EDB-${esc(m.id)}</a> · ${esc(m.title)} · ${esc(m.date)}${m.verified ? " · verified" : ""} <span class="muted">(${esc(m.cve)})</span></li>`).join("")}</ul>` : ""}
    ${poc.length ? `<div class="label">Proof-of-concept code on GitHub</div>
      <p class="small warn-text">Unvetted code from strangers: some are only scanners, some are fake or malware. Read it before running anything.</p>
      <ul class="small">${poc.slice(0, 6).map((m) =>
      `<li><a href="${esc(m.url)}" target="_blank" rel="noopener">${esc(m.name)}</a> · ★ ${m.stars} · ${esc(m.created)}${m.description ? ` · <span class="muted">${esc(m.description)}</span>` : ""}</li>`).join("")}</ul>` : ""}
  </div>`;
}

function scoresBox(v) {
  let list = v.cveList;
  if (!list.length) return "";
  if (list.length > 12) list = [...list].sort((a, b) => (b.epss ?? 0) - (a.epss ?? 0)).slice(0, 12);
  const rows = list.map((c) => {
    const sev = severity(c.cvss);
    const ex = exploitChance(c.epss);
    return `<tr><td><a class="mono" href="https://nvd.nist.gov/vuln/detail/${esc(c.id)}" target="_blank" rel="noopener">${esc(c.id)}</a></td>
      <td>${sev ? `<span class="v ${sev.cls}">${sev.label} · ${c.cvss.toFixed(1)}</span>` : `<span class="muted">not scored yet</span>`}</td>
      <td>${ex ? `<span class="v ${ex.cls}">${ex.label}</span> <span class="muted">(${ex.pct}%)</span>${c.epssSeries && c.epssSeries.length > 1 ? `<div class="spark-row">${sparkline(c.epssSeries)}<span class="muted small">${(c.epssSeries[0].e * 100).toFixed(1)}% on ${esc(day(c.epssSeries[0].d))}</span></div>` : ""}` : `<span class="muted">unknown</span>`}</td>
      <td>${c.kev ? `<span class="v crit">Yes</span> <span class="muted">since ${esc(day(c.kev.added))}</span>` : `<span class="muted">not confirmed</span>`}</td></tr>`;
  }).join("");
  return `<div class="box"><h4>Scores per CVE${v.cveList.length > list.length ? ` <span class="muted small">(${list.length} most likely to be exploited, of ${v.cveList.length})</span>` : ""}</h4>
    <table class="cves"><thead><tr><th>CVE</th><th>Severity<small>0–10, from NVD</small></th><th>Exploit chance<small>next 30 days, trend over the last month, from FIRST</small></th><th>Exploited<small>from CISA</small></th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

function triageBox(v) {
  const cur = v.triage?.state || "untriaged";
  const disabled = data.user ? "" : "disabled";
  const seg = Object.entries(STATE_LABEL).map(([k, label]) => `<button data-state="${k}" class="${k === cur ? "on" : ""}" ${disabled}>${label}</button>`).join("");
  const last = v.triage ? `Last set by ${esc(v.triage.by)} ${ago(v.triage.at)}` : "No status yet";
  return `<div class="box tri-box"><h4>Our status</h4>
    <div class="seg" id="tri-seg">${seg}</div>
    <textarea id="tri-note" placeholder="${data.user ? "Note: affected hosts, ticket number, workaround…" : "Sign in to set a status"}" ${disabled}>${esc(v.triage?.note || "")}</textarea>
    <div class="actions"><span class="muted small">${last}</span>
      ${data.user ? `<button class="primary" id="tri-save">Save</button>` : `<button class="ghost" id="tri-signin">Sign in</button>`}</div>
    <ul class="hist" id="tri-hist"></ul></div>`;
}

function renderDrawer(id, keepScroll) {
  const v = vulns.find((x) => x.id === id);
  if (!v) return closeDrawer();
  const drawer = $("#drawer");
  const scroll = drawer.scrollTop;
  drawer.innerHTML = `<div class="d-head">
      <button class="ghost d-close" id="d-close" title="Close (Esc)">✕</button>
      <div class="d-group ${GROUPS[v.group].cls}">${GROUPS[v.group].title}</div>
      <h3>${esc(v.title)}</h3>
      <p class="d-why">${v.why}</p>
    </div>
    <div class="d-body">${triageBox(v)}${cfBox(v)}${cisaBox(v)}${msBox(v)}${exploitBox(v)}${ubuBox(v)}${scoresBox(v)}</div>`;
  drawer.hidden = false;
  $("#scrim").hidden = false;
  if (keepScroll) drawer.scrollTop = scroll;
  loadHistory(v.id);
  $("#d-close").onclick = closeDrawer;
  for (const b of drawer.querySelectorAll("#tri-seg button")) b.onclick = () => {
    for (const o of drawer.querySelectorAll("#tri-seg button")) o.classList.toggle("on", o === b);
  };
  const save = $("#tri-save");
  if (save) save.onclick = () => saveTriage(v.id);
  const si = $("#tri-signin");
  if (si) si.onclick = openLogin;
}

async function loadHistory(id) {
  try {
    const rows = await (await fetch(`/api/history/${encodeURIComponent(id)}`)).json();
    const el = $("#tri-hist");
    if (el && openId === id) el.innerHTML = rows.slice(0, 8).map((r) =>
      `<li>${new Date(r.at * 1000).toLocaleString()}: <b>${esc(r.by)}</b> set ${esc(STATE_LABEL[r.state])}${r.note ? `, “${esc(r.note.slice(0, 120))}”` : ""}</li>`).join("");
  } catch {}
}

function openDrawer(id) {
  openId = id;
  renderDrawer(id);
  $("#drawer").scrollTop = 0;
  history.replaceState(null, "", `#${encodeURIComponent(id)}`);
}
function closeDrawer() {
  openId = null;
  hooksOpen = false;
  accountOpen = false;
  $("#drawer").hidden = true;
  $("#scrim").hidden = true;
  history.replaceState(null, "", location.pathname);
}

async function saveTriage(id) {
  const state = $("#tri-seg button.on")?.dataset.state || "untriaged";
  const note = $("#tri-note").value;
  const r = await post("/api/triage", { id, state, note });
  if (!r.ok) return toast(r.status === 401 ? "Signed out. Sign in again" : "Couldn't save");
  const it = data.items.find((i) => i.id === id);
  it.triage = await r.json();
  toast(`Marked ${STATE_LABEL[state]}`);
  render();
}

// --- webhooks -------------------------------------------------------------------------

let hooksOpen = false;
let hooksData = null;
let editing = null;      // null = list, {} = new, {...} = editing one
let confirmDelete = null;

const KIND_HELP = {
  rocketchat: "In Rocket.Chat: Administration → Workspace → Integrations → New → Incoming. Choose the channel, turn it on, save, then copy the Webhook URL.",
  slack: "In Slack: create an app with Incoming Webhooks turned on, add it to a channel, then copy the webhook URL.",
  teams: "In Teams: open the channel → ⋯ → Workflows → “Post to a channel when a webhook request is received”, then copy the URL it gives you.",
  discord: "In Discord: Channel settings → Integrations → Webhooks → New Webhook → Copy Webhook URL.",
  json: "Any URL that accepts a JSON POST. If you set a secret, every request carries X-HeadsUp-Signature: sha256=<HMAC-SHA256 of the body>.",
};
const EVENT_HELP = {
  act: "A vulnerability appears in, or moves into, Act now (attackers are using it).",
  soon: "A vulnerability appears in Patch soon (critical, not exploited yet).",
  updated: "Cloudflare changes its advice on something in Act now or Patch soon.",
  status: "Someone marks an item Investigating, Not affected or Patched.",
  patch: "Microsoft publishes a month's security updates: one summary with zero-days, criticals and what to patch first.",
};

async function openHooks() {
  openId = null;
  accountOpen = false;
  hooksOpen = true;
  editing = null;
  history.replaceState(null, "", location.pathname);
  await loadHooks();
}

async function loadHooks() {
  const r = await fetch("/api/webhooks");
  if (!r.ok) { toast("Sign in first"); return closeDrawer(); }
  hooksData = await r.json();
  renderHooks();
}

function deliveryText(h) {
  if (!h.lastAt) return `<span class="muted">Nothing sent yet</span>`;
  return h.lastOk ? `<span class="ok-text">Delivered ${ago(h.lastAt)}</span>` : `<span class="bad-text">Failed ${ago(h.lastAt)}: ${esc(h.lastDetail)}</span>`;
}

function hookCard(h) {
  const kind = hooksData.kinds[h.kind] || h.kind;
  const evs = h.events.map((e) => `<span class="chip">${esc(hooksData.events[e] || e)}</span>`).join("");
  const recent = h.recent.length ? `<details class="recent"><summary>Recent deliveries</summary><ul>${h.recent.map((d) =>
    `<li><span class="${d.ok ? "ok-text" : "bad-text"}">${d.ok ? "✓" : "✕"}</span> ${new Date(d.at * 1000).toLocaleString()} · ${esc(hooksData.events[d.event] || d.event)} · ${esc(d.title)}${d.ok ? "" : ` · ${esc(d.detail)}`}</li>`).join("")}</ul></details>` : "";
  return `<div class="box hook ${h.enabled ? "" : "off"}">
    <div class="hook-head"><div><b>${esc(h.name)}</b> <span class="muted small">· ${esc(kind)}${h.enabled ? "" : " · paused"}</span>
      <div class="mono small muted">${esc(h.url)}</div></div>
      <div class="hook-actions">
        <button class="ghost" data-hook-test="${h.id}">Send test</button>
        <button class="ghost" data-hook-edit="${h.id}">Edit</button>
        <button class="ghost danger" data-hook-del="${h.id}">${confirmDelete === h.id ? "Click again to delete" : "Delete"}</button>
      </div></div>
    <div class="chips">${evs}</div>
    <div class="small">${deliveryText(h)}</div>${recent}</div>`;
}

function hookForm(h) {
  const isNew = !h.id;
  const kind = h.kind || "rocketchat";
  const events = h.events || hooksData.defaultEvents;
  return `<form class="box hook-form" id="hook-form">
    <h4>${isNew ? "Add a webhook" : `Edit “${esc(h.name)}”`}</h4>
    <label>Name<input name="name" maxlength="60" value="${esc(h.name || "")}" placeholder="e.g. #security channel"></label>
    <label>Type<select name="kind">${Object.entries(hooksData.kinds).map(([k, l]) => `<option value="${k}" ${k === kind ? "selected" : ""}>${esc(l)}</option>`).join("")}</select></label>
    <p class="help small" id="kind-help">${esc(KIND_HELP[kind])}</p>
    <label>Webhook URL<input name="url" autocomplete="off" spellcheck="false" placeholder="${isNew ? "https://…" : "Leave empty to keep the current URL"}"></label>
    <label class="secret-row" ${kind === "json" ? "" : "hidden"}>Signing secret (optional)<input name="secret" autocomplete="off" placeholder="${h.hasSecret ? "Leave empty to keep the current secret" : ""}"></label>
    <fieldset><legend>Tell us when…</legend>${Object.entries(hooksData.events).map(([k, l]) =>
      `<label class="ev"><input type="checkbox" name="ev" value="${k}" ${events.includes(k) ? "checked" : ""}><span><b>${esc(l)}</b><br><span class="muted small">${esc(EVENT_HELP[k])}</span></span></label>`).join("")}</fieldset>
    <label class="ev"><input type="checkbox" name="enabled" ${h.enabled === false ? "" : "checked"}><span>Turned on</span></label>
    <p class="err" id="hook-err"></p>
    <div class="actions"><button type="button" class="ghost" id="hook-cancel">Cancel</button><button class="primary">${isNew ? "Add webhook" : "Save"}</button></div>
  </form>`;
}

function renderHooks() {
  const drawer = $("#drawer");
  const list = hooksData.webhooks;
  drawer.innerHTML = `<div class="d-head">
      <button class="ghost d-close" id="d-close" title="Close (Esc)">✕</button>
      <div class="d-group">Settings</div>
      <h3>Webhooks</h3>
      <p class="d-why">Post alerts to Rocket.Chat, Slack, Teams, Discord or any URL when something changes. Each webhook picks what it wants to hear about. Several changes at once arrive as one summary message.</p>
    </div>
    <div class="d-body">
      ${hooksData.available ? "" : `<div class="box"><b>Webhooks are switched off on this server</b> (no settings key). Re-run the installer.</div>`}
      ${editing ? hookForm(editing) : ""}
      ${list.map(hookCard).join("") || (editing ? "" : `<div class="box empty">No webhooks yet.</div>`)}
      ${editing || !hooksData.available ? "" : `<button class="primary add-hook" id="hook-add">Add webhook</button>`}
    </div>`;
  drawer.hidden = false;
  $("#scrim").hidden = false;
  $("#d-close").onclick = closeDrawer;
  const add = $("#hook-add");
  if (add) add.onclick = () => { editing = {}; renderHooks(); };
  const form = $("#hook-form");
  if (form) {
    form.kind.onchange = () => {
      $("#kind-help").textContent = KIND_HELP[form.kind.value];
      $(".secret-row").hidden = form.kind.value !== "json";
    };
    $("#hook-cancel").onclick = () => { editing = null; renderHooks(); };
    form.onsubmit = async (e) => {
      e.preventDefault();
      const body = {
        id: editing.id, name: form.name.value, kind: form.kind.value, url: form.url.value,
        secret: form.secret.value, enabled: form.enabled.checked,
        events: [...form.querySelectorAll("input[name=ev]:checked")].map((x) => x.value),
      };
      const r = await post("/api/webhooks/save", body);
      const j = await r.json().catch(() => ({}));
      if (!r.ok) { $("#hook-err").textContent = j.error || "Couldn't save"; return; }
      editing = null;
      await loadHooks();
      toast("Saved. Use “Send test” to check it");
    };
    form.name.focus();
  }
}

document.addEventListener("click", async (e) => {
  if (!hooksOpen) return;
  const t = e.target.closest("[data-hook-test],[data-hook-edit],[data-hook-del]");
  if (!t) return;
  if (t.dataset.hookEdit) { editing = { ...hooksData.webhooks.find((h) => h.id === t.dataset.hookEdit) }; return renderHooks(); }
  if (t.dataset.hookDel) {
    if (confirmDelete !== t.dataset.hookDel) { confirmDelete = t.dataset.hookDel; return renderHooks(); }
    confirmDelete = null;
    await post("/api/webhooks/delete", { id: t.dataset.hookDel });
    toast("Webhook deleted");
    return loadHooks();
  }
  if (t.dataset.hookTest) {
    t.disabled = true;
    t.textContent = "Sending…";
    const r = await post("/api/webhooks/test", { id: t.dataset.hookTest });
    const j = await r.json().catch(() => ({}));
    toast(j.ok ? "Test delivered. Check the channel" : `Test failed: ${j.detail || j.error || r.status}`);
    return loadHooks();
  }
});

// --- account & users -------------------------------------------------------------------

let accountOpen = false;
let usersData = null;
let userForm = null;          // null, {} (new) or a user being edited
let revealed = null;          // {username, password} shown once after create/reset
let confirmUserDel = null;
const ROLE_LABEL = { admin: "Admin", member: "Member" };
const ROLE_HELP = { admin: "Can do everything, including managing users and webhooks.", member: "Can set statuses and refresh sources." };

async function openAccount() {
  openId = null;
  hooksOpen = false;
  accountOpen = true;
  userForm = null;
  revealed = null;
  history.replaceState(null, "", location.pathname);
  await loadUsers();
}

let settingsData = null;

async function loadUsers() {
  usersData = null;
  settingsData = null;
  if (data.user?.role === "admin") {
    const [r, s] = await Promise.all([fetch("/api/users"), fetch("/api/settings")]);
    if (r.ok) usersData = await r.json();
    if (s.ok) settingsData = await s.json();
  }
  renderAccount();
}

function radarBox() {
  const r = settingsData?.radar;
  if (!r) return "";
  const status = r.configured
    ? (r.error && !r.okAt ? `<span class="bad-text">Turned on, but the last update failed: ${esc(r.error)}</span>` : `<span class="ok-text">On</span>${r.okAt ? ` · updated ${ago(r.okAt)}` : " · first update running"}`)
    : `<span class="muted">Off</span>`;
  return `<form class="box hook-form" id="radar-form">
    <h4><span class="badge cf">Cloudflare Radar</span> attack maps · ${status}</h4>
    <p class="small muted">Adds a world map of where attacks come from and who they target, attack volume, routes and industries to the Charts tab. It needs a free Cloudflare API token that can only read Radar:</p>
    <ol class="small steps">
      <li>Sign in (or sign up free) at <b>dash.cloudflare.com</b>.</li>
      <li>Profile icon → <b>My Profile</b> → <b>API Tokens</b> → <b>Create Token</b> → <b>Custom token: Get started</b>.</li>
      <li>Name it “Heads Up”. Under <b>Permissions</b> choose <b>Account</b> · <b>Radar</b> · <b>Read</b>. Nothing else.</li>
      <li><b>Continue to summary</b> → <b>Create Token</b>, then copy it and paste it here.</li>
    </ol>
    <label>API token<input name="token" autocomplete="off" spellcheck="false" placeholder="${r.configured ? "Leave empty to keep the current token" : "Paste the token"}"></label>
    <p class="err" id="radar-err"></p>
    <div class="actions">${r.configured ? `<button type="button" class="ghost danger" id="radar-remove">Turn off</button>` : ""}<button class="primary">${r.configured ? "Replace token" : "Turn on"}</button></div>
  </form>`;
}

function wireRadarBox() {
  const f = $("#radar-form");
  if (!f) return;
  f.onsubmit = async (e) => {
    e.preventDefault();
    if (!f.token.value.trim()) { $("#radar-err").textContent = "Paste the token first"; return; }
    $("#radar-err").textContent = "Checking the token with Cloudflare…";
    const r = await post("/api/settings/radar", { token: f.token.value.trim() });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) { $("#radar-err").textContent = j.error || "Couldn't save it"; return; }
    toast("Cloudflare Radar is on. The maps fill in within a minute");
    await loadUsers();
  };
  const rm = $("#radar-remove");
  if (rm) rm.onclick = async () => { await post("/api/settings/radar", { remove: true }); toast("Cloudflare Radar turned off"); await loadUsers(); };
}

function revealBox() {
  if (!revealed) return "";
  return `<div class="box reveal"><h4>Password for ${esc(revealed.username)}</h4>
    <p class="small muted">Give this to them. It won't be shown again; they can change it after signing in.</p>
    <div class="pw-row"><code id="pw-text">${esc(revealed.password)}</code><button class="ghost" id="pw-copy">Copy</button></div>
    <div class="actions"><button class="ghost" id="pw-done">Done</button></div></div>`;
}

function userRow(u) {
  const me = u.username === data.user.username;
  return `<tr class="${u.disabled ? "off" : ""}">
    <td><b>${esc(u.name)}</b>${me ? ` <span class="chip">you</span>` : ""}<div class="mono small muted">${esc(u.username)}</div></td>
    <td>${ROLE_LABEL[u.role]}${u.disabled ? `<div class="small bad-text">Turned off</div>` : ""}</td>
    <td class="small muted">${u.lastLogin ? ago(u.lastLogin) : "Never"}</td>
    <td class="u-actions">
      <button class="ghost" data-u-edit="${esc(u.username)}">Edit</button>
      <button class="ghost" data-u-reset="${esc(u.username)}">New password</button>
      ${me ? "" : `<button class="ghost danger" data-u-del="${esc(u.username)}">${confirmUserDel === u.username ? "Click again" : "Delete"}</button>`}
    </td></tr>`;
}

function userFormBox(u) {
  const isNew = !u.username;
  const role = u.role || "member";
  const me = u.username === data.user.username;
  return `<form class="box hook-form" id="user-form">
    <h4>${isNew ? "Add a user" : `Edit ${esc(u.name)}`}</h4>
    ${isNew ? `<label>Username<input name="username" maxlength="32" autocapitalize="none" spellcheck="false" placeholder="e.g. jsmith" required></label>` : ""}
    <label>Name<input name="name" maxlength="40" value="${esc(u.name || "")}" placeholder="Shown next to statuses they set"></label>
    <fieldset><legend>Role</legend>${Object.entries(ROLE_LABEL).map(([k, l]) =>
      `<label class="ev"><input type="radio" name="role" value="${k}" ${k === role ? "checked" : ""} ${me ? "disabled" : ""}><span><b>${l}</b><br><span class="muted small">${ROLE_HELP[k]}</span></span></label>`).join("")}</fieldset>
    ${isNew ? `<label>Password<input name="password" type="text" autocomplete="off" placeholder="Leave empty to create one (recommended)"></label>` : ""}
    ${!isNew && !me ? `<label class="ev"><input type="checkbox" name="disabled" ${u.disabled ? "checked" : ""}><span>Turn off this account (they can't sign in)</span></label>` : ""}
    <p class="err" id="user-err"></p>
    <div class="actions"><button type="button" class="ghost" id="user-cancel">Cancel</button><button class="primary">${isNew ? "Add user" : "Save"}</button></div>
  </form>`;
}

function renderAccount() {
  const drawer = $("#drawer");
  const u = data.user;
  const users = usersData ? `
    <div class="box"><h4>Users <span class="muted small">${usersData.users.length}</span>
      ${userForm ? "" : `<button class="primary small-btn" id="user-add">Add user</button>`}</h4>
      <table class="users"><thead><tr><th>Name</th><th>Role</th><th>Last sign-in</th><th></th></tr></thead>
      <tbody>${usersData.users.map(userRow).join("")}</tbody></table></div>` : "";
  drawer.innerHTML = `<div class="d-head">
      <button class="ghost d-close" id="d-close" title="Close (Esc)">✕</button>
      <div class="d-group">Account</div>
      <h3>${esc(u.name)}</h3>
      <p class="d-why">Signed in as <span class="mono">${esc(u.username)}</span> · ${ROLE_LABEL[u.role]}</p>
    </div>
    <div class="d-body">
      ${revealBox()}
      ${userForm ? userFormBox(userForm) : ""}
      ${users}
      ${u.role === "admin" ? radarBox() : ""}
      <form class="box hook-form" id="pw-form">
        <h4>Change your password</h4>
        <label>Current password<input name="current" type="password" autocomplete="current-password" required></label>
        <label>New password<input name="new" type="password" autocomplete="new-password" minlength="${usersData?.minPassword || 10}" required></label>
        <label>New password again<input name="again" type="password" autocomplete="new-password" required></label>
        <p class="err" id="pw-err"></p>
        <div class="actions"><button class="primary">Change password</button></div>
      </form>
      <button class="ghost signout" id="signout">Sign out</button>
    </div>`;
  drawer.hidden = false;
  $("#scrim").hidden = false;
  $("#d-close").onclick = closeDrawer;
  $("#signout").onclick = async () => { await post("/api/logout", {}); closeDrawer(); await load(); toast("Signed out"); };
  wireRadarBox();
  const add = $("#user-add");
  if (add) add.onclick = () => { userForm = {}; revealed = null; renderAccount(); $("#user-form").username.focus(); };
  const copy = $("#pw-copy");
  if (copy) copy.onclick = async () => {
    try { await navigator.clipboard.writeText(revealed.password); toast("Copied"); }
    catch { getSelection().selectAllChildren($("#pw-text")); toast("Selected. Press Ctrl+C"); }
  };
  const done = $("#pw-done");
  if (done) done.onclick = () => { revealed = null; renderAccount(); };
  $("#pw-form").onsubmit = async (e) => {
    e.preventDefault();
    const f = e.target;
    if (f.new.value !== f.again.value) { $("#pw-err").textContent = "The new passwords don't match"; return; }
    const r = await post("/api/me/password", { current: f.current.value, new: f.new.value });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) { $("#pw-err").textContent = j.error || "Couldn't change it"; return; }
    f.reset();
    $("#pw-err").textContent = "";
    toast("Password changed");
  };
  const uf = $("#user-form");
  if (uf) {
    $("#user-cancel").onclick = () => { userForm = null; renderAccount(); };
    uf.onsubmit = async (e) => {
      e.preventDefault();
      const isNew = !userForm.username;
      const body = { name: uf.name.value, role: uf.querySelector("input[name=role]:checked")?.value || userForm.role };
      let r;
      if (isNew) r = await post("/api/users/create", { ...body, username: uf.username.value, password: uf.password.value });
      else r = await post("/api/users/update", { ...body, username: userForm.username, disabled: uf.disabled?.checked ?? false });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) { $("#user-err").textContent = j.error || "Couldn't save"; return; }
      if (isNew) revealed = { username: j.username, password: j.password };
      userForm = null;
      toast(isNew ? "User added" : "Saved");
      if (!isNew && body.name && userForm === null) await load();
      await loadUsers();
    };
  }
}

document.addEventListener("click", async (e) => {
  if (!accountOpen) return;
  const t = e.target.closest("[data-u-edit],[data-u-reset],[data-u-del]");
  if (!t) return;
  if (t.dataset.uEdit) { userForm = { ...usersData.users.find((u) => u.username === t.dataset.uEdit) }; revealed = null; return renderAccount(); }
  if (t.dataset.uReset) {
    const r = await post("/api/users/reset", { username: t.dataset.uReset });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) return toast(j.error || "Couldn't reset it");
    revealed = { username: t.dataset.uReset, password: j.password };
    if (t.dataset.uReset === data.user.username) { toast("You'll need to sign in again with the new password"); }
    return loadUsers();
  }
  if (t.dataset.uDel) {
    if (confirmUserDel !== t.dataset.uDel) { confirmUserDel = t.dataset.uDel; return renderAccount(); }
    confirmUserDel = null;
    const r = await post("/api/users/delete", { username: t.dataset.uDel });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) return toast(j.error || "Couldn't delete");
    toast("User deleted");
    return loadUsers();
  }
});

// --- network ------------------------------------------------------------------------

function post(url, body) {
  return fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
}

async function load() {
  try {
    const r = await fetch("/api/state");
    if (!r.ok) throw new Error(r.status);
    data = await r.json();
    render();
    if (typeof tab !== "undefined" && tab === "charts") loadCharts();
    if (!openId && location.hash.length > 1) {
      const id = decodeURIComponent(location.hash.slice(1));
      if (vulns.some((v) => v.id === id)) openDrawer(id);
    }
  } catch (e) {
    toast("Can't reach the server");
  }
}

let toastTimer;
function toast(msg) {
  let el = $(".toast");
  if (!el) { el = document.createElement("div"); el.className = "toast"; document.body.append(el); }
  el.textContent = msg;
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (el.hidden = true), 2600);
}

// --- login --------------------------------------------------------------------------

function openLogin() {
  $("#login-err").textContent = "";
  try { $("#login-form").username.value = localStorage.getItem("hu.username") || ""; } catch {}
  $("#login").showModal();
  (($("#login-form").username.value && $("#login-form").password) || $("#login-form").username).focus();
}

$("#login-cancel").onclick = () => $("#login").close();
$("#login-form").addEventListener("submit", async (e) => {
  // Enter in either field and the Sign in button both land here.
  e.preventDefault();
  const f = e.target;
  const r = await post("/api/login", { username: f.username.value, password: f.password.value });
  if (!r.ok) {
    const j = await r.json().catch(() => ({}));
    $("#login-err").textContent = j.error || (r.status === 429 ? "Too many attempts; wait 10 minutes" : "Sign-in failed");
    return;
  }
  try { localStorage.setItem("hu.username", f.username.value.trim().toLowerCase()); } catch {}
  f.password.value = "";
  $("#login").close();
  await load();
  toast("Signed in");
});

$("#account").onclick = () => (data?.user ? openAccount() : openLogin());

$("#hooks-btn").onclick = openHooks;

$("#refresh").onclick = async () => {
  $("#refresh").classList.add("spin");
  const r = await post("/api/refresh", {});
  toast(r.ok ? "Checking all sources. This can take a few minutes" : "Couldn't start a refresh");
  setTimeout(() => $("#refresh").classList.remove("spin"), 4000);
  setTimeout(load, 15000);
};

// --- events -------------------------------------------------------------------------

document.addEventListener("click", (e) => {
  const more = e.target.closest("[data-more]");
  if (more) { shown[more.dataset.more] += 25; return render(); }
  if (e.target.closest("[data-toggle-done]")) { showDone = !showDone; return render(); }
  const jump = e.target.closest("[data-jump]");
  if (jump) {
    if (jump.dataset.jump === "done" && !showDone) { showDone = true; render(); }
    return $(`#group-${jump.dataset.jump}`).scrollIntoView({ behavior: "smooth", block: "start" });
  }
  const open = e.target.closest("[data-id]");
  if (open && !e.target.closest("a")) return openDrawer(open.dataset.id);
});
$("#scrim").onclick = closeDrawer;
$("#q").addEventListener("input", (e) => { query = e.target.value.trim().toLowerCase(); render(); });
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && (openId || hooksOpen || accountOpen) && !$("#login").open) closeDrawer();
  if (e.key === "/" && !["INPUT", "TEXTAREA"].includes(document.activeElement?.tagName)) { e.preventDefault(); $("#q").focus(); }
});

load();
setInterval(() => { if (!document.hidden && !$("#login").open && !hooksOpen && !accountOpen && document.activeElement?.id !== "tri-note") load(); }, 120000);
