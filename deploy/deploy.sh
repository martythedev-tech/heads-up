#!/bin/bash
# Run from the laptop.
#   deploy/deploy.sh            copy the source to the server and install/update it
#   deploy/deploy.sh admin      set the built-in "admin" account's password from the
#                               keyring (creates a new random one there if missing;
#                               add --new to replace it)
# Passwords go from the laptop keyring straight into ssh's stdin; they are
# never put on a command line or in a file. Settings: deploy/local.env.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=/dev/null
source deploy/local.env
if [[ -n ${SSH_ASKPASS:-} ]]; then export SSH_ASKPASS SSH_ASKPASS_REQUIRE=force; fi

lookup() { secret-tool lookup "$@" || { echo "not in keyring: $*" >&2; exit 1; }; }
sudo_password() { read -ra attrs <<<"$SUDO_SECRET"; lookup "${attrs[@]}"; }
admin_password() { lookup service heads-up purpose admin; }

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
  admin)
    if [[ ${2:-} == --new ]] || ! secret-tool lookup service heads-up purpose admin >/dev/null 2>&1; then
      python3 -c 'import users; print(users.new_password(), end="")' \
        | secret-tool store --label="Heads Up admin password (username: admin)" service heads-up purpose admin
      echo "New admin password stored in the keyring (secret-tool lookup service heads-up purpose admin)"
    fi
    upload
    { sudo_password; echo; admin_password; echo; } \
      | remote_sudo 'cd ~/heads-up-src && sudo bash deploy/set-admin-password'
    ;;
  *) echo "usage: $0 [install|admin [--new]]" >&2; exit 2 ;;
esac
