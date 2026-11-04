"use strict";
// Charts tab: hand-drawn SVG (no libraries; the page's CSP allows only its own
// scripts). Uses helpers from app.js: $, esc, ago, day, openDrawer, openAccount.

let chartsData = null;
let world = null;
let mapMode = { layer: "l7", side: "Origin" };
let tab = "list";
try { tab = localStorage.getItem("hu.tab") || "list"; } catch {}

const NS = "http://www.w3.org/2000/svg";
const fmt = (n) => (n == null ? "" : Number(n).toLocaleString());
const pct = (v, d = 1) => `${Number(v).toFixed(v < 1 ? Math.max(d, 1) : d)}%`;
const monthName = (m) => new Date(m + "-01T00:00:00").toLocaleDateString(undefined, { month: "short", year: "2-digit" });

// --- tab switching ------------------------------------------------------------------

function showTab(name) {
  tab = name;
  try { localStorage.setItem("hu.tab", name); } catch {}
  for (const b of document.querySelectorAll(".tabs button")) b.classList.toggle("on", b.dataset.tab === name);
  $("#summary").hidden = name !== "list";
  $("#groups").hidden = name !== "list";
  $("#charts").hidden = name !== "charts";
  if (name === "charts") loadCharts();
}

async function loadCharts() {
  try {
    const [c, w] = await Promise.all([
      fetch("/api/charts").then((r) => r.json()),
      world ? Promise.resolve(world) : fetch("/static/world.json").then((r) => r.json()),
    ]);
    chartsData = c;
    world = w;
    renderCharts();
  } catch {
    $("#charts").innerHTML = `<div class="box empty">Couldn't load the charts.</div>`;
  }
}

// --- building blocks -------------------------------------------------------------

function card(id, title, sub, plot, table, extra = "") {
  return `<section class="chart-card" id="${id}">
    <header><div><h3>${title}</h3><p class="sub">${sub}</p></div>
      <div class="card-tools">${extra}${table ? `<button class="ghost tbl-toggle" data-tbl="${id}">Table</button>` : ""}</div></header>
    <div class="plot">${plot}</div>
    ${table ? `<div class="tbl" hidden>${table}</div>` : ""}
  </section>`;
}

function table(headers, rows) {
  return `<table class="data"><thead><tr>${headers.map((h) => `<th>${h}</th>`).join("")}</tr></thead>
    <tbody>${rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("")}</tbody></table>`;
}

function niceMax(v) {
  if (v <= 0) return 1;
  const p = 10 ** Math.floor(Math.log10(v));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}

// Horizontal ranked bars: one series, one colour; value at the bar end.
function hbars(rows, { label, value, tip, fmtValue = fmt, width = 560 }) {
  if (!rows.length) return `<p class="muted">No data yet.</p>`;
  const rowH = 26, labelW = 210, valueW = 56, top = 4;
  const plotW = width - labelW - valueW;
  const max = niceMax(Math.max(...rows.map(value)));
  const h = top + rows.length * rowH;
  const bars = rows.map((r, i) => {
    const y = top + i * rowH;
    const w = Math.max(2, (value(r) / max) * plotW);
    return `<g class="hit" data-tip="${esc(tip(r))}">
      <rect x="0" y="${y}" width="${width}" height="${rowH}" fill="transparent"/>
      <text x="${labelW - 10}" y="${y + rowH / 2 + 4}" text-anchor="end" class="lbl">${esc(label(r))}</text>
      <rect x="${labelW}" y="${y + 7}" width="${w}" height="${rowH - 14}" rx="3" class="bar s1"/>
      <text x="${labelW + w + 6}" y="${y + rowH / 2 + 4}" class="val">${esc(fmtValue(value(r)))}</text></g>`;
  }).join("");
  return `<svg viewBox="0 0 ${width} ${h}" class="chart" role="img">${bars}</svg>`;
}

// --- right now -----------------------------------------------------------------------

function progressTiles(p) {
  const tile = (n, t, d, cls = "") => `<div class="stat ${cls}"><div class="n">${n}</div><div class="t">${t}</div><div class="d">${d}</div></div>`;
  return `<div class="stats">
    ${tile(p.untriagedUrgent, "Waiting for a look", "Act now and Patch soon items nobody has checked", p.untriagedUrgent ? "warn" : "")}
    ${tile(p.investigating, "Investigating", "Someone is on it")}
    ${tile(p.patched, "Patched", "Fixed on our side", "good")}
    ${tile(p.notAffected, "Not affected", "Checked; we don't run it")}
    ${tile(p.medianDaysToClose == null ? "–" : `${p.medianDaysToClose} d`, "Typical time to close", p.closedCount ? `median over ${p.closedCount} closed item${p.closedCount === 1 ? "" : "s"}` : "nothing closed yet")}
  </div>`;
}

function scatter(points) {
  const W = 620, H = 340, L = 48, R = 14, T = 24, B = 40;
  const pw = W - L - R, ph = H - T - B;
  const ylo = Math.log10(0.0001), yhi = 0;
  const x = (c) => L + (c / 10) * pw;
  const y = (e) => T + (1 - (Math.log10(Math.max(e, 0.0001)) - ylo) / (yhi - ylo)) * ph;
  const grid = [0, 2, 4, 6, 8, 10].map((c) => `<line x1="${x(c)}" x2="${x(c)}" y1="${T}" y2="${T + ph}" class="grid"/><text x="${x(c)}" y="${H - B + 16}" text-anchor="middle" class="tick">${c}</text>`).join("")
    + [0.0001, 0.001, 0.01, 0.1, 1].map((e) => `<line x1="${L}" x2="${L + pw}" y1="${y(e)}" y2="${y(e)}" class="grid"/><text x="${L - 6}" y="${y(e) + 4}" text-anchor="end" class="tick">${e >= 0.01 ? e * 100 : e * 100}%</text>`).join("");
  const zone = `<rect x="${x(9)}" y="${T}" width="${x(10) - x(9)}" height="${y(0.1) - T}" class="zone"/>
    <text x="${x(10)}" y="${T - 8}" text-anchor="end" class="zone-lbl">Critical and likely ↓</text>`;
  const order = { aware: 0, soon: 1, act: 2 };
  const marks = [...points].sort((a, b) => order[a.group] - order[b.group]).map((p) => {
    const cx = x(p.cvss).toFixed(1), cy = y(p.epss).toFixed(1);
    const tip = `${p.title} · severity ${p.cvss.toFixed(1)} · exploit chance ${(p.epss * 100).toFixed(p.epss < 0.1 ? 1 : 0)}%${p.exploited ? " · exploited" : ""}`;
    const shape = p.group === "act" ? `<circle cx="${cx}" cy="${cy}" r="5.5" class="pt act"/>`
      : p.group === "soon" ? `<circle cx="${cx}" cy="${cy}" r="5" class="pt soon"/>`
      : `<circle cx="${cx}" cy="${cy}" r="3.5" class="pt aware"/>`;
    return `<g class="hit" data-tip="${esc(tip)}" data-open="${esc(p.id)}"><circle cx="${cx}" cy="${cy}" r="10" fill="transparent"/>${shape}</g>`;
  }).join("");
  const axes = `<text x="${L + pw / 2}" y="${H - 6}" text-anchor="middle" class="axis-lbl">Severity (CVSS 0–10) →</text>
    <text transform="translate(12 ${T + ph / 2}) rotate(-90)" text-anchor="middle" class="axis-lbl">Exploit chance, next 30 days →</text>`;
  const legend = `<div class="legend">
    <span><svg width="14" height="14"><circle cx="7" cy="7" r="5.5" class="pt act"/></svg>Act now</span>
    <span><svg width="14" height="14"><circle cx="7" cy="7" r="5" class="pt soon"/></svg>Patch soon</span>
    <span><svg width="14" height="14"><circle cx="7" cy="7" r="3.5" class="pt aware"/></svg>For awareness</span>
    <span class="muted">Click a dot to open it</span></div>`;
  return `${legend}<svg viewBox="0 0 ${W} ${H}" class="chart">${zone}${grid}${axes}${marks}</svg>`;
}

// --- CISA over time ---------------------------------------------------------------

function monthlyColumns(rows) {
  const W = 620, H = 260, L = 36, R = 8, T = 18, B = 30;
  const pw = W - L - R, ph = H - T - B;
  const max = niceMax(Math.max(...rows.map((r) => r.total), 1));
  const step = pw / rows.length, bw = Math.max(4, step - 4);
  const y = (v) => T + ph - (v / max) * ph;
  const ticks = [0, max / 2, max].map((v) => `<line x1="${L}" x2="${L + pw}" y1="${y(v)}" y2="${y(v)}" class="grid"/><text x="${L - 6}" y="${y(v) + 4}" text-anchor="end" class="tick">${fmt(v)}</text>`).join("");
  const cols = rows.map((r, i) => {
    const x0 = L + i * step + (step - bw) / 2;
    const other = r.total - r.ransomware;
    const yo = y(other), yr = y(r.total);
    const tip = `${monthName(r.month)}: ${r.total} newly exploited${r.ransomware ? `, ${r.ransomware} linked to ransomware` : ""}`;
    const label = i % 3 === 0 || i === rows.length - 1 ? `<text x="${x0 + bw / 2}" y="${H - B + 16}" text-anchor="middle" class="tick">${monthName(r.month)}</text>` : "";
    return `<g class="hit" data-tip="${esc(tip)}"><rect x="${x0 - 2}" y="${T}" width="${bw + 4}" height="${ph}" fill="transparent"/>
      ${other ? `<rect x="${x0}" y="${yo}" width="${bw}" height="${T + ph - yo}" rx="2" class="bar s1"/>` : ""}
      ${r.ransomware ? `<rect x="${x0}" y="${yr}" width="${bw}" height="${Math.max(1, yo - yr - 2)}" rx="2" class="bar s2"/>` : ""}
      ${label}</g>`;
  }).join("");
  const last = rows[rows.length - 1];
  const lastLbl = `<text x="${L + (rows.length - 1) * step + step / 2}" y="${y(last.total) - 5}" text-anchor="middle" class="val">${last.total}</text>`;
  const legend = `<div class="legend"><span><i class="sw s1"></i>Newly exploited</span><span><i class="sw s2"></i>…of which linked to ransomware</span></div>`;
  return `${legend}<svg viewBox="0 0 ${W} ${H}" class="chart">${ticks}${cols}${lastLbl}</svg>`;
}

// --- Radar --------------------------------------------------------------------------

const RAMP = 5;
function binOf(v, max) {
  if (v == null) return -1;
  const r = v / max;
  return r >= 0.6 ? 4 : r >= 0.3 ? 3 : r >= 0.12 ? 2 : r >= 0.04 ? 1 : 0;
}

function worldMap(rows, what, opts = {}) {
  const byIso = new Map(rows.map((r) => [r.iso, r]));
  const max = Math.max(...rows.map((r) => r.value), 0.0001);
  const fmtV = opts.fmt || ((v) => pct(v));
  const tipOf = opts.tip || ((r, c) => `${r.name || c.n}: ${pct(r.value)} of ${what}`);
  const paths = Object.entries(world.countries).map(([iso, c]) => {
    const r = byIso.get(iso);
    const b = r ? (opts.bins ? opts.bins(r.value) : binOf(r.value, max)) : -1;
    const tip = r ? tipOf(r, c) : `${c.n}: ${opts.none || "not in the top countries"}`;
    return `<path d="${c.d}" class="land ${b >= 0 ? `q${b}` : "nodata"}" data-tip="${esc(tip)}"/>`;
  }).join("");
  const steps = [0.04, 0.12, 0.3, 0.6].map((f) => fmtV(f * max));
  const legend = opts.legend || `<div class="legend scale"><span>Share of ${what}:</span>
    <i class="sw q0"></i><span>&lt; ${steps[0]}</span><i class="sw q1"></i><i class="sw q2"></i><i class="sw q3"></i><i class="sw q4"></i><span>≥ ${steps[3]}</span>
    <i class="sw nodata"></i><span>not in top ${rows.length}</span></div>`;
  return `${legend}<svg viewBox="${world.viewBox}" class="chart map">${paths}</svg>`;
}

function lineChart(rows) {
  if (!rows.length) return `<p class="muted">No data yet.</p>`;
  const W = 620, H = 200, L = 12, R = 12, T = 14, B = 26;
  const pw = W - L - R, ph = H - T - B;
  const max = Math.max(...rows.map((r) => r.value), 0.0001);
  const x = (i) => L + (i / Math.max(1, rows.length - 1)) * pw;
  const y = (v) => T + ph - (v / max) * ph;
  const d = rows.map((r, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(r.value).toFixed(1)}`).join("");
  const peak = rows.reduce((a, r, i) => (r.value > rows[a].value ? i : a), 0);
  const dayLbl = (t) => new Date(t).toLocaleDateString(undefined, { month: "short", day: "numeric" });
  const hits = rows.map((r, i) => `<g class="hit" data-tip="${esc(`${dayLbl(r.t)}: ${Math.round((r.value / max) * 100)}% of the busiest day`)}">
    <rect x="${x(i) - pw / rows.length / 2}" y="${T}" width="${pw / rows.length}" height="${ph}" fill="transparent"/>
    <circle cx="${x(i)}" cy="${y(r.value)}" r="3" class="dot s1"/></g>`).join("");
  const ticks = [0, Math.floor(rows.length / 2), rows.length - 1].map((i) => `<text x="${x(i)}" y="${H - 8}" text-anchor="${i === 0 ? "start" : i === rows.length - 1 ? "end" : "middle"}" class="tick">${dayLbl(rows[i].t)}</text>`).join("");
  return `<svg viewBox="0 0 ${W} ${H}" class="chart">
    <line x1="${L}" x2="${L + pw}" y1="${T + ph}" y2="${T + ph}" class="grid"/>
    <path d="${d}" class="line s1"/>${hits}${ticks}
    <text x="${x(peak)}" y="${y(rows[peak].value) - 8}" text-anchor="middle" class="val">busiest: ${dayLbl(rows[peak].t)}</text></svg>`;
}

const PRODUCT_NAMES = { DDOS: "DDoS protection", WAF: "Web application firewall", BOT_MANAGEMENT: "Bot management", ACCESS_RULES: "Access rules",
  IP_REPUTATION: "IP reputation", API_SHIELD: "API shield", DATA_LOSS_PREVENTION: "Data loss prevention" };
const nice = (s) => PRODUCT_NAMES[s] || String(s).replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()).replace(/\B\w+/g, (w) => w.toLowerCase());

function radarSection(radar) {
  const isAdmin = data?.user?.role === "admin";
  if (!radar.configured) {
    return `<h2 class="sec">Internet attacks <span class="badge cf">Cloudflare Radar</span></h2>
      <div class="box radar-off"><b>See where attacks come from and who they target</b>
      <p class="muted">Cloudflare Radar shows attack traffic seen across Cloudflare's network: a world map of attack origins and targets, attack volume over the last 4 weeks, the busiest attack routes and the industries targeted. It needs a free Cloudflare API token.</p>
      ${isAdmin ? `<button class="primary" id="radar-setup">Add a Cloudflare token</button>` : `<p class="muted">Ask an admin to add a Cloudflare token.</p>`}</div>`;
  }
  const d = radar.data || {};
  const key = `${mapMode.layer}${mapMode.side}`;
  const rows = d[key] || [];
  const what = mapMode.layer === "l7" ? "web attacks" : "DDoS attacks";
  const sideTxt = mapMode.side === "Origin" ? "come from" : "are aimed at";
  const seg = (k, v, l) => `<button data-map="${k}:${v}" class="${mapMode[k] === v ? "on" : ""}">${l}</button>`;
  const tools = `<div class="seg">${seg("layer", "l7", "Web attacks")}${seg("layer", "l3", "DDoS attacks")}</div>
    <div class="seg">${seg("side", "Origin", "Where from")}${seg("side", "Target", "Who's targeted")}</div>`;
  const top = rows.slice(0, 10);
  const pairs = d.l7Pairs || [];
  const status = radar.error ? `<span class="bad-text">Last update failed: ${esc(radar.error)}</span>` : radar.at ? `Updated ${ago(radar.at)}` : "Fetching for the first time…";
  return `<h2 class="sec">Internet attacks <span class="badge cf">Cloudflare Radar</span> <span class="muted small">last 7 days · ${status}</span></h2>
    <div class="charts-grid">
      ${card("c-map", `Where ${what} ${sideTxt}`, `Share of ${what} seen by Cloudflare, by country. Countries outside the top ${rows.length} are grey.`,
        rows.length ? worldMap(rows, what) : `<p class="muted">No data yet.</p>`,
        table(["Country", `Share of ${what}`], rows.map((r) => [esc(r.name || r.iso), pct(r.value)])), tools)}
      ${card("c-top", `Top 10 countries`, `${what[0].toUpperCase() + what.slice(1)} that ${sideTxt} each country`,
        hbars(top, { label: (r) => r.name || r.iso, value: (r) => r.value, tip: (r) => `${r.name}: ${pct(r.value)} of ${what}`, fmtValue: (v) => pct(v) }), null)}
      ${card("c-series", "Web attack volume, last 4 weeks", "Daily attack traffic relative to the busiest day",
        lineChart(d.l7Series || []), table(["Day", "Relative volume"], (d.l7Series || []).map((r) => [new Date(r.t).toLocaleDateString(), `${Math.round(r.value * 100) / 100}`])))}
      ${card("c-pairs", "Busiest attack routes", "Web attacks from one country to another, share of all web attacks",
        pairs.length ? table(["From", "To", "Share"], pairs.map((p) => [esc(p.fromName || p.from), esc(p.toName || p.to), pct(p.value)])) : `<p class="muted">No data yet.</p>`, null)}
      ${card("c-industry", "Industries targeted", "Share of web attacks by the target's industry",
        hbars((d.l7Industry || []).slice(0, 10), { label: (r) => nice(r.name), value: (r) => r.value, tip: (r) => `${nice(r.name)}: ${pct(r.value)}`, fmtValue: (v) => pct(v) }), null)}
      ${outageCards(d)}
      ${card("c-rules", "Types of web attacks", "What the blocked web attacks were trying to do (Cloudflare managed rules)",
        hbars((d.l7Rules || []).slice(0, 10), { label: (r) => r.name[0].toUpperCase() + r.name.slice(1), value: (r) => r.value, tip: (r) => `${r.name}: ${pct(r.value)} of web attacks caught by managed rules`, fmtValue: (v) => pct(v) }),
        table(["Attack type", "Share"], (d.l7Rules || []).map((r) => [esc(r.name), pct(r.value)])))}
      ${card("c-product", "How attacks were stopped", "Share of web attacks by the Cloudflare defence that caught them",
        hbars((d.l7Product || []).slice(0, 8), { label: (r) => nice(r.name), value: (r) => r.value, tip: (r) => `${nice(r.name)}: ${pct(r.value)}`, fmtValue: (v) => pct(v) }), null)}
    </div>`;
}

// --- exploits ----------------------------------------------------------------------

function risingTable() {
  const rows = (typeof vulns !== "undefined" ? vulns : [])
    .filter((v) => !v.done && v.epssWas != null && v.epss != null && v.epss > v.epssWas)
    .map((v) => ({ v, delta: v.epss - v.epssWas }))
    .sort((a, b) => b.delta - a.delta).slice(0, 8);
  if (!rows.length) return `<p class="muted">Nothing is rising right now (history fills in over the first hour).</p>`;
  return `<table class="data rising"><thead><tr><th>Vulnerability</th><th>Month ago</th><th>Now</th><th>Trend</th></tr></thead><tbody>${rows.map(({ v }) => {
    const top = v.cveList.reduce((a, c) => (c.epss != null && (!a || c.epss > a.epss) ? c : a), null);
    return `<tr class="click" data-open="${esc(v.id)}"><td>${esc(v.title)}</td><td>${(v.epssWas * 100).toFixed(1)}%</td><td><b>${(v.epss * 100).toFixed(1)}%</b></td><td>${sparkline(top?.epssSeries)}</td></tr>`;
  }).join("")}</tbody></table>`;
}

function exploitBars() {
  const open = (typeof vulns !== "undefined" ? vulns : []).filter((v) => !v.done && !v.usnPrimary);
  const count = (k) => open.filter((v) => v.exploit === k).length;
  const rows = [
    { name: "Metasploit module", value: count("metasploit"), k: "metasploit" },
    { name: "Exploit-DB entry", value: count("exploitdb"), k: "exploitdb" },
    { name: "GitHub proof of concept", value: count("poc"), k: "poc" },
    { name: "None known", value: open.filter((v) => !v.exploit).length, k: "none" },
  ];
  return hbars(rows, { label: (r) => r.name, value: (r) => r.value, tip: (r) => `${r.name}: ${r.value} of ${open.length} open vulnerabilities` });
}

// --- outages -----------------------------------------------------------------------

const CAUSES = { POWER_OUTAGE: "Power outage", CABLE_CUT: "Cable cut", GOVERNMENT_DIRECTED: "Government-ordered shutdown",
  WEATHER: "Weather", MILITARY_ACTION: "Military action", TECHNICAL_PROBLEM: "Technical problem", MAINTENANCE: "Maintenance",
  FIRE: "Fire", EARTHQUAKE: "Earthquake", CYBERATTACK: "Cyberattack", UNKNOWN: "Unknown" };
const cause = (c) => CAUSES[c] || (c ? nice(c) : "Unknown");
function duration(start, end) {
  if (!start) return "";
  if (!end) return `<b class="v crit">Ongoing</b> · ${hoursText((Date.now() - new Date(start)) / 3600000)}`;
  return hoursText((new Date(end) - new Date(start)) / 3600000);
}
function hoursText(h) { return h < 1 ? "under an hour" : h < 48 ? `${Math.round(h)} h` : `${Math.round(h / 24)} days`; }
const when = (iso) => (iso ? new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric" }) : "");

function outageCards(d) {
  const outages = (d.outages || []).slice().sort((a, b) => String(b.start).localeCompare(String(a.start)));
  const anomalies = (d.anomalies || []).slice().sort((a, b) => String(b.start).localeCompare(String(a.start)));
  const counts = new Map();
  for (const o of outages) for (const pl of new Set(o.places.map((x) => x.iso).filter(Boolean))) {
    const c = counts.get(pl) || { iso: pl, name: o.places.find((x) => x.iso === pl)?.name, value: 0, ongoing: 0 };
    c.value += 1; c.ongoing += o.end ? 0 : 1; counts.set(pl, c);
  }
  const rows = [...counts.values()];
  const ongoing = outages.filter((o) => !o.end).length;
  const legend = `<div class="legend scale"><span>Outages per country:</span><i class="sw q1"></i><span>1</span><i class="sw q2"></i><span>2</span><i class="sw q3"></i><span>3–4</span><i class="sw q4"></i><span>5+</span><i class="sw nodata"></i><span>none reported</span></div>`;
  const map = rows.length ? worldMap(rows, "outages", {
    bins: (v) => (v >= 5 ? 4 : v >= 3 ? 3 : v >= 2 ? 2 : 1), legend, none: "no outage reported",
    tip: (r, c) => `${c.n}: ${r.value} outage${r.value === 1 ? "" : "s"} in 30 days${r.ongoing ? `, ${r.ongoing} ongoing` : ""}`,
  }) : `<p class="muted">No outages reported in the last 30 days.</p>`;
  const place = (o) => [...new Set(o.places.map((x) => x.name || x.iso))].join(", ") || o.asns.map((a) => a.name).join(", ") || "–";
  const table = outages.length ? `<table class="data"><thead><tr><th>Started</th><th>Where</th><th>Cause</th><th>How long</th><th></th></tr></thead><tbody>${outages.slice(0, 40).map((o) => `<tr>
      <td>${esc(when(o.start))}</td><td><b>${esc(place(o))}</b>${o.asns.length ? `<div class="small muted">${esc(o.asns.slice(0, 3).map((a) => a.name).join(", "))}</div>` : ""}<div class="small muted">${esc(o.description || "")}</div></td>
      <td>${esc(cause(o.cause))}${o.type ? `<div class="small muted">${esc(nice(o.type))}</div>` : ""}</td><td>${duration(o.start, o.end)}</td>
      <td>${o.url ? `<a href="${esc(o.url)}" target="_blank" rel="noopener">Details ↗</a>` : ""}</td></tr>`).join("")}</tbody></table>` : `<p class="muted">None.</p>`;
  const anomTable = anomalies.length ? `<table class="data"><thead><tr><th>Started</th><th>Network or place</th><th>Status</th><th>How long</th></tr></thead><tbody>${anomalies.slice(0, 30).map((a) => `<tr>
      <td>${esc(when(a.start))}</td><td><b>${esc(a.asnName ? `${a.asnName} (AS${a.asn})` : a.place || "–")}</b>${a.place && a.asnName ? `<div class="small muted">${esc(a.place)}</div>` : ""}</td>
      <td>${a.status === "VERIFIED" ? "Confirmed" : "Not yet confirmed"}</td><td>${duration(a.start, a.end)}</td></tr>`).join("")}</tbody></table>` : `<p class="muted">No traffic drops in the last 7 days.</p>`;
  return `${card("c-outmap", `Internet outages, last 30 days${ongoing ? ` · ${ongoing} ongoing` : ""}`, "Outages Cloudflare confirmed and explained (power cuts, cable cuts, shutdowns, …)", map,
      table.replace('<table class="data">', '<table class="data">'), "")}
    ${card("c-outlist", "Outage details", "Newest first; “Details” links to Cloudflare's write-up", `<div class="tbl-scroll">${table}</div>`, null)}
    ${card("c-anom", "Sudden traffic drops, last 7 days", "Networks or places whose traffic suddenly fell; often an outage before it's confirmed", `<div class="tbl-scroll">${anomTable}</div>`, null)}`;
}

// --- Patch Tuesday -----------------------------------------------------------------

let ptIndex = 0;
function patchTuesdaySection(list) {
  const head = `<h2 class="sec">Microsoft Patch Tuesday <span class="badge ms">Microsoft</span></h2>`;
  if (!list || !list.length) return `${head}<div class="box muted">Microsoft's updates arrive with the first fetch (within a few minutes).</div>`;
  const m = list[Math.min(ptIndex, list.length - 1)];
  const tools = `<div class="seg">${list.map((x, i) => `<button data-pt="${i}" class="${x === m ? "on" : ""}">${esc(x.label.split(" ")[0])}</button>`).join("")}</div>`;
  const tile = (n, t, d, cls = "") => `<div class="stat ${cls}"><div class="n">${fmt(n)}</div><div class="t">${t}</div><div class="d">${d}</div></div>`;
  const flags = (r) => [r.exploited ? `<span class="pill crit">Exploited</span>` : "", r.disclosed ? `<span class="pill high">Disclosed</span>` : "",
    (r.likelihood || "").startsWith("Exploitation More Likely") ? `<span class="pill">More likely</span>` : ""].join(" ");
  return `${head}
    <div class="pt-head"><div class="muted">${esc(m.label)} · released ${esc(m.date ? day(m.date) : "")} · Microsoft's own products only</div>${tools}</div>
    <div class="stats">
      ${tile(m.total, "Fixes", "Vulnerabilities fixed this month")}
      ${tile(m.exploited, "Already exploited", "Zero-days: attacked before the fix", m.exploited ? "warn bad" : "")}
      ${tile(m.disclosed, "Publicly disclosed", "Details were out before the fix", m.disclosed ? "warn" : "")}
      ${tile(m.critical, "Critical", "Microsoft's highest rating")}
      ${tile(m.likely, "Exploitation more likely", "Microsoft expects attacks on these")}
    </div>
    <div class="charts-grid">
      ${card("c-pt-first", "Patch these first", "Exploited, disclosed, and critical fixes Microsoft expects to be attacked",
        m.first.length ? `<div class="tbl-scroll"><table class="data"><thead><tr><th>CVE</th><th>What</th><th>Product</th><th>Rating</th><th>Flags</th></tr></thead><tbody>${m.first.map((r) => `<tr>
          <td><a class="mono" href="https://msrc.microsoft.com/update-guide/vulnerability/${esc(r.cve)}" target="_blank" rel="noopener">${esc(r.cve)}</a></td>
          <td>${esc(r.title)}</td><td>${esc(r.product || "")}</td><td>${esc(r.severity || "")}${r.cvss ? ` · ${r.cvss.toFixed(1)}` : ""}</td><td>${flags(r)}</td></tr>`).join("")}</tbody></table></div>` : `<p class="muted">Nothing stands out this month.</p>`, null)}
      ${card("c-pt-products", "Most-fixed products", "Number of fixes per product this month; hover for how many are critical",
        hbars(m.byProduct, { label: (r) => r.name, value: (r) => r.count, tip: (r) => `${r.name}: ${r.count} fixes, ${r.critical} critical` }),
        table(["Product", "Fixes", "Critical"], m.byProduct.map((r) => [esc(r.name), r.count, r.critical])))}
      ${card("c-pt-impact", "What attackers could do", "Fixes by impact, e.g. run code remotely or gain higher privileges",
        hbars(m.byImpact, { label: (r) => r.name, value: (r) => r.count, tip: (r) => `${r.name}: ${r.count} fixes` }),
        table(["Impact", "Fixes"], m.byImpact.map((r) => [esc(r.name), r.count])))}
    </div>`;
}

// --- page ---------------------------------------------------------------------------

function renderCharts() {
  const c = chartsData;
  if (!c) return;
  const kevYear = c.kevYear;
  $("#charts").innerHTML = `
    <h2 class="sec">Right now <span class="muted small">from this dashboard</span></h2>
    ${progressTiles(c.progress)}
    <div class="charts-grid">
      ${card("c-scatter", "Severity against exploit chance", "Each dot is an open vulnerability. Top right is where to look first.",
        scatter(c.scatter), table(["Vulnerability", "Group", "Severity", "Exploit chance"], c.scatter.map((p) => [esc(p.title), { act: "Act now", soon: "Patch soon", aware: "For awareness", done: "Done" }[p.group], p.cvss.toFixed(1), `${(p.epss * 100).toFixed(1)}%`])))}
      ${card("c-monthly", "Newly exploited vulnerabilities per month", `Added to CISA's exploited list · ${fmt(kevYear.total)} in the last 12 months, ${fmt(kevYear.ransomware)} linked to ransomware`,
        monthlyColumns(c.kevMonthly), table(["Month", "Newly exploited", "Linked to ransomware"], c.kevMonthly.map((r) => [monthName(r.month), r.total, r.ransomware])))}
      ${card("c-vendors", "Most exploited vendors", "Vendors with the most entries on CISA's exploited list, last 12 months",
        hbars(c.kevVendors, { label: (r) => r.vendor, value: (r) => r.count, tip: (r) => `${r.vendor}: ${r.count} newly exploited${r.ransomware ? `, ${r.ransomware} linked to ransomware` : ""}` }),
        table(["Vendor", "Newly exploited", "Linked to ransomware"], c.kevVendors.map((r) => [esc(r.vendor), r.count, r.ransomware])))}
      ${card("c-cwes", "Most common weakness types", "What kind of flaw attackers used, CISA's exploited list, last 12 months",
        c.kevCwes.length ? hbars(c.kevCwes, { label: (r) => r.name, value: (r) => r.count, tip: (r) => `${r.name} (${r.cwe}): ${r.count}` }) : `<p class="muted">Weakness types arrive with the next CISA update (within 3 hours).</p>`,
        table(["Weakness", "CWE", "Count"], c.kevCwes.map((r) => [esc(r.name), esc(r.cwe), r.count])))}
    </div>
    <div class="charts-grid">
      ${card("c-rising", "Exploit chance rising fastest", "Open vulnerabilities whose exploit chance went up most in the last month (FIRST EPSS)",
        risingTable(), null)}
      ${card("c-exploits", "Open vulnerabilities with public exploit code", "Strongest signal per vulnerability",
        exploitBars(), null)}
    </div>
    ${patchTuesdaySection(c.patchTuesday)}
    ${radarSection(c.radar)}
    <p class="muted small charts-foot">Sources: CISA Known Exploited Vulnerabilities, FIRST EPSS, NVD, Cloudflare Radar (attack data, CC BY-NC 4.0). Map outlines: Natural Earth.</p>`;
  const setup = $("#radar-setup");
  if (setup) setup.onclick = () => openAccount();
}

// tooltip + interactions
const tipEl = document.createElement("div");
tipEl.className = "chart-tip";
tipEl.hidden = true;
document.body.append(tipEl);
document.addEventListener("mousemove", (e) => {
  const t = e.target.closest?.("#charts [data-tip]");
  if (!t) { tipEl.hidden = true; return; }
  tipEl.textContent = t.dataset.tip;
  tipEl.hidden = false;
  const x = Math.min(e.clientX + 14, window.innerWidth - tipEl.offsetWidth - 8);
  const y = e.clientY + 18 + tipEl.offsetHeight > window.innerHeight ? e.clientY - tipEl.offsetHeight - 10 : e.clientY + 18;
  tipEl.style.left = `${x}px`;
  tipEl.style.top = `${y}px`;
});
document.addEventListener("click", (e) => {
  const tabBtn = e.target.closest(".tabs button");
  if (tabBtn) return showTab(tabBtn.dataset.tab);
  const tbl = e.target.closest("[data-tbl]");
  if (tbl) {
    const cardEl = document.getElementById(tbl.dataset.tbl);
    const t = cardEl.querySelector(".tbl"), p = cardEl.querySelector(".plot");
    t.hidden = !t.hidden; p.hidden = !t.hidden;
    tbl.textContent = t.hidden ? "Table" : "Chart";
    return;
  }
  const m = e.target.closest("[data-map]");
  if (m) { const [k, v] = m.dataset.map.split(":"); mapMode[k] = v; return renderCharts(); }
  const pt = e.target.closest("[data-pt]");
  if (pt) { ptIndex = Number(pt.dataset.pt); return renderCharts(); }
  const o = e.target.closest("#charts [data-open]");
  if (o) return openDrawer(o.dataset.open);
});

showTab(tab);
