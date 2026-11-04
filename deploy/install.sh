#!/bin/bash
# Install or update Heads Up on this server. Run as root from the unpacked
# source directory. Safe to re-run: config, certificates, secrets and the
# database that already exist are left alone.
set -euo pipefail
cd "$(dirname "$0")/.."

ETC=/etc/heads-up
TLS=$ETC/tls

for module in aiohttp cryptography; do
  python3 -c "import $module" 2>/dev/null \
    || DEBIAN_FRONTEND=noninteractive apt-get install -y -q "python3-$module"
done

install -d -m 755 /opt/heads-up /opt/heads-up/static
rm -f /opt/heads-up/*.py
install -m 644 ./*.py /opt/heads-up/
rm -f /opt/heads-up/static/*
install -m 644 static/* /opt/heads-up/static/

install -d -m 755 "$ETC"
if [[ -f deploy/config.env ]]; then
  install -m 644 deploy/config.env "$ETC/config.env"
elif [[ ! -f $ETC/config.env ]]; then
  install -m 644 deploy/config.env.example "$ETC/config.env"
  echo "Created $ETC/config.env — edit it, then re-run." >&2
  exit 1
fi
# shellcheck source=/dev/null
source "$ETC/config.env"

# A one-off private CA so browsers can trust the dashboard once (import
# ca.crt) instead of clicking through a warning. It is name-constrained to
# this server's address only, and its key is deleted right after signing the
# server certificate, so it can never sign anything else.
install -d -m 711 "$TLS"
if [[ ! -f $TLS/server.crt ]] || [[ ! -f $TLS/ca.crt ]] \
   || ! openssl x509 -checkend $((30 * 86400)) -noout -in "$TLS/server.crt" >/dev/null \
   || ! openssl x509 -noout -ext subjectAltName -in "$TLS/server.crt" | grep -qF "$SERVER_NAME"; then
  if [[ $SERVER_NAME =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    san="IP:$SERVER_NAME"
    constraints="permitted;IP:$SERVER_NAME/255.255.255.255,excluded;IP:0:0:0:0:0:0:0:0/0:0:0:0:0:0:0:0,permitted;DNS:heads-up.invalid"
  else
    san="DNS:$SERVER_NAME"
    constraints="permitted;DNS:$SERVER_NAME,excluded;IP:0.0.0.0/0.0.0.0,excluded;IP:0:0:0:0:0:0:0:0/0:0:0:0:0:0:0:0"
  fi
  rm -f "$TLS"/*
  work=$(mktemp -d /run/heads-up-ca.XXXXXX)
  trap 'rm -rf "$work"' EXIT
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 830 \
    -subj "/CN=Heads Up CA ($SERVER_NAME only)" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign" \
    -addext "nameConstraints=critical,$constraints" \
    -keyout "$work/ca.key" -out "$TLS/ca.crt" 2>/dev/null
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=Heads Up" \
    -keyout "$TLS/server.key" -out "$work/server.csr" 2>/dev/null
  openssl x509 -req -in "$work/server.csr" -CA "$TLS/ca.crt" -CAkey "$work/ca.key" \
    -set_serial "0x$(openssl rand -hex 16)" -days 825 -out "$TLS/server.crt" -extfile <(printf '%s\n' \
      "subjectAltName=$san" "extendedKeyUsage=serverAuth" \
      "keyUsage=critical,digitalSignature" "basicConstraints=critical,CA:FALSE") 2>/dev/null
  rm -rf "$work"
  chmod 600 "$TLS/server.key"
  chmod 644 "$TLS/server.crt" "$TLS/ca.crt"
  echo "New certificate issued; browsers need the new ca.crt (http://$SERVER_NAME:${HU_HTTP_PORT:-9080}/ca.crt)." >&2
fi

# Key that encrypts stored webhook URLs (they carry their own tokens). Made once.
if [[ ! -f /etc/credstore.encrypted/heads-up.settings-key ]]; then
  install -d -m 700 /etc/credstore.encrypted
  openssl rand -hex 32 | tr -d '\n' \
    | systemd-creds encrypt --name=settings-key - /etc/credstore.encrypted/heads-up.settings-key
  chmod 600 /etc/credstore.encrypted/heads-up.settings-key
fi

install -m 644 deploy/heads-up.service /etc/systemd/system/heads-up.service
systemctl daemon-reload
# 0.3 and earlier used one shared password; accounts replace it.
rm -f /etc/credstore.encrypted/heads-up.login-hash
if [[ ! -f /etc/credstore.encrypted/heads-up.admin-hash ]]; then
  echo "Set the admin password first:  sudo bash deploy/set-admin-password" >&2
  exit 1
fi
systemctl enable heads-up.service >/dev/null 2>&1
systemctl restart heads-up.service
sleep 1
systemctl is-active heads-up.service
