# Heads Up

An internal dashboard of critical vulnerabilities for system administrators:
one list, most urgent first, with where each piece of information came from
and what to do about it. Optional alerts to Rocket.Chat, Slack, Microsoft
Teams, Discord or any URL.

- [What it shows](#what-it-shows)
- [First-time install](#first-time-install)
- [First sign-in](#first-sign-in)
- [Adding people](#adding-people)
- [Alerts to chat (webhooks)](#alerts-to-chat-webhooks)
- [Updating, passwords and troubleshooting](#updating)

## What it shows

Every vulnerability appears once, in one of four groups:

| Group | Meaning |
| --- | --- |
| **Act now** | Attackers are using it (CISA), and Cloudflare flagged it or CISA added it in the last 14 days |
| **Patch soon** | Critical, but not confirmed as exploited yet |
| **For awareness** | Exploited more than 2 weeks ago, Cloudflare reference briefings, high-priority Ubuntu updates |
| **Done** | Marked Patched or Not affected |

Sources, each with its own colour on the page:

- **Cloudflare**: [Zero Wire](https://radar.cloudflare.com/security/zero-wire) briefings (RSS, every 30 min)
- **CISA**: the [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog (every 3 h)
- **Ubuntu**: Security Notices and per-release fix status (hourly), rated by Ubuntu's own priority (via [OSV](https://osv.dev))
- **VulnCheck KEV** (optional, free Community token, every 6 h): exploited vulnerabilities beyond CISA's list, often days earlier, with citations. VulnCheck-only items go to For awareness unless there is a strong signal (VulnCheck's honeypots saw attacks, public exploit code, severity 9+, or Cloudflare/Microsoft flag it)
- **Microsoft**: Patch Tuesday from the [Security Update Guide](https://msrc.microsoft.com/update-guide) (every 6 h): zero-days (exploited or publicly disclosed) join the list; every CVE Microsoft fixed is marked
- **Exploit code**: [Metasploit](https://github.com/rapid7/metasploit-framework) exploit modules and [Exploit-DB](https://www.exploit-db.com) entries (daily), and proof-of-concept repositories on GitHub via [PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- Scores per CVE: severity from [NVD](https://nvd.nist.gov) (CVSS), and exploit chance from [FIRST EPSS](https://www.first.org/epss/) with its trend over the last month

Not yet exploited items move to **Patch soon** when they are critical, rated
critical by Ubuntu, likely to be exploited, publicly disclosed by Microsoft,
or have a Metasploit module / Exploit-DB entry and High severity or more.

### Charts tab

- **Right now**: items waiting for a look, statuses, typical time to close;
  severity against exploit chance; exploit chance rising fastest; open items
  with public exploit code
- **CISA trends**: newly exploited per month, most exploited vendors, most
  common weakness types
- **Microsoft Patch Tuesday** (last three months): fixes, zero-days, criticals,
  "exploitation more likely", what to patch first, by product and impact
- **Internet attacks** ([Cloudflare Radar](https://radar.cloudflare.com),
  optional, needs a free read-only token): world map of where web and DDoS
  attacks come from and who they target, attack volume, attack routes,
  industries, attack types, internet outages (30 days), sudden traffic
  drops (7 days), and route hijacks and leaks (7 days). Admins can name up to
  five networks (AS numbers) to watch; hijacks or leaks involving them are
  listed separately and can trigger a webhook

Anyone who can reach the page can read it. Signed-in users mark items
**Investigating**, **Not affected** or **Patched** with a note; every change is
logged under their name.

## First-time install

### What you need

- A Linux server with **systemd 250 or newer**, **Python 3.11+** and **OpenSSL**.
  Tested on Ubuntu 26.04; Ubuntu 24.04 and Debian 12 or newer work the same way.
- Outbound HTTPS from the server to radar.cloudflare.com, api.cloudflare.com,
  cisa.gov, ubuntu.com, api.osv.dev, api.first.org, services.nvd.nist.gov,
  api.msrc.microsoft.com, gitlab.com (Exploit-DB), raw.githubusercontent.com
  and (with a token) api.vulncheck.com / serve.vulncheck.com.
- Two free ports: **9443** (the dashboard, HTTPS) and **9080** (redirects to
  HTTPS and serves the certificate to trust). Both can be changed.
- `sudo` on the server.

The installer adds `python3-aiohttp` and `python3-cryptography` with apt if
they're missing.

### 1. Get the code onto the server

```sh
git clone https://github.com/martythedev-tech/heads-up.git
cd heads-up
```

### 2. Tell it its address

```sh
cp deploy/config.env.example deploy/config.env
nano deploy/config.env
```

Set `SERVER_NAME` to the address people will type in their browser: the
server's IP (e.g. `10.0.0.5`) or its DNS name (e.g. `heads-up.example.lan`).
The HTTPS certificate is made for exactly this address. `HU_UBUNTU_RELEASES`
lists the Ubuntu releases you want fix status for (codenames, e.g.
`"resolute noble jammy"` for 26.04, 24.04 and 22.04).

### 3. Set the admin password

```sh
sudo bash deploy/set-admin-password
```

Press **Enter** without typing anything to have a strong password generated.
It's printed **once** together with the username `admin`; put it in your
password manager. (Or type your own: at least 10 characters.)

### 4. Install

```sh
sudo bash deploy/install.sh
```

It copies the app to `/opt/heads-up`, creates its own HTTPS certificate,
installs and starts the `heads-up` service, and prints `active`. The first
fetch of all sources takes a few minutes; the page fills in as each arrives.

Check it's running at any time with `systemctl status heads-up` and read its
log with `journalctl -u heads-up -f`.

## First sign-in

### 1. Trust the certificate (once per computer)

Heads Up makes its own small certificate authority, limited to your server's
address only (it can't vouch for any other site, and its signing key is
deleted after use). Download it from:

```
http://SERVER_NAME:9080/ca.crt
```

and import it:

- **Windows (Chrome, Edge):** double-click `heads-up-ca.crt` → **Install
  Certificate** → *Current User* → **Place all certificates in the following
  store** → *Trusted Root Certification Authorities* → Finish. Restart the browser.
- **macOS (Safari, Chrome):** double-click it to add it to *Keychain Access*,
  open it there, expand **Trust** and set *When using this certificate* to
  **Always Trust**.
- **Firefox (any system):** Settings → search "certificates" → **View
  Certificates** → **Authorities** → **Import** → tick *Trust this CA to
  identify websites*.
- **Linux (Chrome, Brave, Chromium):** Settings → Privacy and security →
  Security → **Manage certificates** → **Authorities** (or *Custom*) → **Import**.

You can skip this and click through the browser's warning instead, but you'd
see it on every visit.

### 2. Sign in

1. Open **`https://SERVER_NAME:9443`**.
2. Click **Sign in** (top right).
3. Username **`admin`**, and the password from step 3 of the install.
4. Press **Enter** or click **Sign in**. Your name replaces the Sign in button.

### 3. Change the admin password (if it was generated)

Click your name (top right) → **Change your password**.

## Adding people

Admins add everyone else; there is no self-registration.

1. Click your name (top right) → **Add user**.
2. Enter a **username** (lowercase, e.g. `jsmith`), a **name** shown next to
   the statuses they set, and a **role**:
   - **Member**: reads, sets statuses, refreshes sources.
   - **Admin**: also manages users and webhooks.
3. Leave **Password** empty to generate a strong one. It's shown **once** with a
   **Copy** button; give it to them and they can change it after signing in.

In the same list you can rename someone, change their role, give them a
**New password** (signs them out everywhere), turn an account off, or delete
it (click twice). Nobody can remove their own admin rights, and there's always
at least one admin.

## Alerts to chat (webhooks)

Admins see a **Webhooks** button. Each webhook has a type, a URL, and its own
choice of what to be told about:

- **New in Act now**: a vulnerability appears in, or moves into, Act now
- **New in Patch soon**
- **Cloudflare updated its guidance** on something in Act now or Patch soon
  (the message says what changed)
- **Status changed**: someone marked an item Investigating, Not affected or Patched
- **Patch Tuesday is out**: one summary when Microsoft publishes a month's updates
- **Routing incident on a watched network**: a route hijack or leak involves a network you watch

Nothing is sent for what already exists when Heads Up first starts. More than
four alerts at once arrive as one summary. Webhook URLs are stored encrypted.
Use **Send test** after adding one; the last result (and a plain-words reason
if it failed) shows under each webhook.

### Rocket.Chat

1. In Rocket.Chat: **Administration → Workspace → Integrations → New →
   Incoming**.
2. Turn it **on**, set **Post to Channel** (e.g. `#security`) and **Post as**
   (a bot user such as `rocket.cat`). Name and avatar shown on messages are set
   here too.
3. **If the channel is private, add the "Post as" user to the channel.**
   Otherwise Rocket.Chat rejects every message with `error-not-allowed`.
   Also make sure the channel isn't read-only for that user.
4. Save and copy the **Webhook URL**.
5. In Heads Up: **Webhooks → Add webhook**, type **Rocket.Chat**, paste the URL,
   pick events, **Add webhook**, then **Send test**.

### Cloudflare Radar (optional)

1. At [dash.cloudflare.com](https://dash.cloudflare.com) (a free account works):
   **My Profile → API Tokens → Create Token → Custom token**.
2. Permissions: **Account · Radar · Read**, nothing else. Leave IP filtering
   empty. Create it and copy the token.
3. In Heads Up: click your name → **Cloudflare Radar** → paste → **Turn on**.
   The token is checked with Cloudflare and stored encrypted.

### VulnCheck KEV (optional)

1. Sign up free at [console.vulncheck.com](https://console.vulncheck.com) (Community).
2. Gear icon (top right) → **API Keys / Tokens** → create one named "Heads Up"; copy it.
3. In Heads Up: click your name → **VulnCheck KEV** → paste → **Turn on**.

Data from VulnCheck is labelled "VulnCheck KEV" wherever it appears, as
VulnCheck's terms ask.

### Slack, Microsoft Teams, Discord, anything else

- **Slack:** create an app with *Incoming Webhooks* on, add it to a channel,
  copy the webhook URL.
- **Microsoft Teams:** in the channel → ⋯ → **Workflows** → *Post to a channel
  when a webhook request is received*; copy the URL it gives you.
- **Discord:** Channel settings → Integrations → Webhooks → New Webhook → Copy
  Webhook URL.
- **Plain JSON:** any URL that accepts a JSON POST. With a signing secret,
  every request carries `X-HeadsUp-Signature: sha256=<HMAC-SHA256 of the raw body>`
  and `X-HeadsUp-Event`.

## Updating

```sh
cd heads-up
git pull
sudo bash deploy/install.sh
```

Settings, users, statuses, webhooks and the certificate are kept.

### Lost the admin password

On the server, from the source directory:

```sh
sudo bash deploy/set-admin-password
```

This resets the `admin` account's password (and turns it back on if it was
off). Other users' passwords are reset from the Users panel.

### Troubleshooting

- **Clicking Sign in does nothing:** reload once with **Ctrl+Shift+R**
  (**Cmd+Shift+R** on a Mac) so the browser drops an old copy of the page.
- **"Wrong username or password":** check the password (usernames aren't
  case-sensitive). After 8 wrong tries, sign-in from that computer pauses for
  10 minutes.
- **The certificate warning came back:** the server's address changed. Update
  `SERVER_NAME`, run the installer again, and import the new `ca.crt`.
- **A source's dot (top of the page) is orange or red:** that source is late or
  failing; the page keeps showing its last good data. Details:
  `journalctl -u heads-up`.
- **A webhook test fails:** the reason is shown under the webhook. For
  Rocket.Chat `error-not-allowed`, see step 3 above.

### Deploying from a laptop instead (optional)

`deploy/deploy.sh` copies the source over SSH and runs the installer, taking
the server's sudo password and the admin password from your desktop keyring
(`secret-tool`). Copy `deploy/local.env.example` to `deploy/local.env`, fill
it in, then:

```sh
deploy/deploy.sh admin   # first time: creates an admin password in your keyring and sets it
deploy/deploy.sh         # install or update
```

`deploy/deploy.sh admin --new` replaces the admin password with a new random
one (the keyring entry is `service heads-up purpose admin`).

## How it's built

A small aiohttp app (`app.py`; grouping in `vulns.py`, alerts in
`webhooks.py`, accounts in `users.py`, charts and Radar in `charts.py`,
exploit code in `exploits.py`, Microsoft in `msrc.py`, VulnCheck in
`vulncheck.py`, transaction helper in `dbutil.py`) with a static front end and SQLite
state, run by a hardened systemd unit (`DynamicUser`, read-only system,
secrets via `systemd-creds`). Run it locally without TLS:

```sh
HU_DEV=1 HU_DEV_ADMIN_HASH=$(echo a-long-password | deploy/hash-password) python3 app.py
# http://127.0.0.1:8765  (admin / a-long-password)
```

## License

MIT (see LICENSE). The data it shows belongs to its sources (Cloudflare, CISA,
Ubuntu, FIRST, NVD); check their terms before republishing it.
