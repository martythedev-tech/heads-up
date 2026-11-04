#!/bin/bash
# Run from the laptop.
#   deploy/deploy.sh            copy the source to the server and install/update it
#   deploy/deploy.sh secrets    store the shared sign-in password (from the keyring)
# Passwords go from the laptop keyring straight into ssh's stdin; they are
# never put on a command line or in a file. Settings: deploy/local.env.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=/dev/null
source deploy/local.env
export SSH_ASKPASS SSH_ASKPASS_REQUIRE=force

lookup() { secret-tool lookup "$@" || { echo "not in keyring: $*" >&2; exit 1; }; }
sudo_password() { read -ra attrs <<<"$SUDO_SECRET"; lookup "${attrs[@]}"; }
login_password() { lookup service heads-up purpose login; }

remote_sudo() {  # remote_sudo SCRIPT — the sudo password is the first stdin line
  ssh "$SSH_HOST" "IFS= read -r PW; printf '%s\n' \"\$PW\" | sudo -S -p '' -v && unset PW && $1"
}

upload() {
  tar -cz ./*.py static deploy | ssh "$SSH_HOST" 'rm -rf ~/heads-up-src && mkdir ~/heads-up-src && tar -xz -C ~/heads-up-src'
}

case ${1:-install} in
  install)
    upload
    { sudo_password; echo; } | remote_sudo 'sudo bash ~/heads-up-src/deploy/install.sh'
    ;;
  secrets)
    upload
    { sudo_password; echo; login_password; echo; } | remote_sudo '
      IFS= read -r v
      hash=$(printf "%s\n" "$v" | python3 ~/heads-up-src/deploy/hash-password); unset v
      sudo install -d -m 700 /etc/credstore.encrypted
      printf "%s" "$hash" | sudo systemd-creds encrypt --name=login-hash - /etc/credstore.encrypted/heads-up.login-hash
      sudo chmod 600 /etc/credstore.encrypted/heads-up.login-hash
      echo "stored login-hash"
      ! systemctl is-active -q heads-up || sudo systemctl restart heads-up'
    ;;
  *) echo "usage: $0 [install|secrets]" >&2; exit 2 ;;
esac
