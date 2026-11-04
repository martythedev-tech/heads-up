"""User accounts.

Roles:
  admin   everything, incl. managing users and webhooks
  member  read, set statuses, refresh sources

The first admin ("admin") comes from the `admin-hash` systemd credential
(deploy/deploy.sh admin). Re-running that with a new password resets the
admin's password; password changes made in the app are kept otherwise.
"""
import hashlib
import hmac
import os
import re
import secrets
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  username TEXT PRIMARY KEY, name TEXT, pw_hash TEXT, role TEXT,
  disabled INTEGER DEFAULT 0, created REAL, created_by TEXT, last_login REAL);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""
ROLES = ("admin", "member")
USERNAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]{1,31}")
MIN_PASSWORD = 10


class UserError(ValueError):
    pass


def hash_password(password):
    n, r, p = 2**14, 8, 1
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=32)
    return f"scrypt:{n}:{r}:{p}:{salt.hex()}:{digest.hex()}"


def check_password(password, stored):
    try:
        scheme, n, r, p, salt, expected = stored.split(":")
        if scheme != "scrypt":
            return False
        actual = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt),
                                n=int(n), r=int(r), p=int(p), dklen=len(expected) // 2)
    except (ValueError, AttributeError):
        return False
    return hmac.compare_digest(actual.hex(), expected)


def new_password():
    """Readable random password, e.g. kq4f-Zr8m-pw2T-x9Lc (about 95 bits)."""
    alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "-".join("".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(4))


def check_new_password(pw):
    if len(pw) < MIN_PASSWORD:
        raise UserError(f"Passwords need at least {MIN_PASSWORD} characters")


class Users:
    def __init__(self, db):
        self.db = db
        db.executescript(SCHEMA)

    def count(self):
        return self.db.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    def get(self, username):
        r = self.db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        return dict(r) if r else None

    def public(self, u):
        return {"username": u["username"], "name": u["name"], "role": u["role"],
                "disabled": bool(u["disabled"]), "created": u["created"], "createdBy": u["created_by"],
                "lastLogin": u["last_login"]}

    def list(self):
        return [self.public(dict(r)) for r in self.db.execute("SELECT * FROM users ORDER BY role, username")]

    def sync_bootstrap_admin(self, cred_hash, log=print):
        """Create or reset the 'admin' account from the deploy-time credential."""
        if not cred_hash:
            return
        applied = self.db.execute("SELECT value FROM meta WHERE key='admin_cred'").fetchone()
        if applied and applied[0] == cred_hash and self.get("admin"):
            return
        if self.get("admin"):
            self.db.execute("UPDATE users SET pw_hash=?, role='admin', disabled=0 WHERE username='admin'", (cred_hash,))
            self.end_sessions("admin")
            log("users: admin password reset from the deploy credential")
        else:
            self.db.execute("INSERT INTO users(username, name, pw_hash, role, created, created_by) VALUES(?,?,?,?,?,?)",
                            ("admin", "Admin", cred_hash, "admin", time.time(), "setup"))
            log("users: created the admin account")
        self.db.execute("INSERT OR REPLACE INTO meta VALUES('admin_cred', ?)", (cred_hash,))

    def authenticate(self, username, password):
        u = self.get(username.strip().lower())
        if not u or u["disabled"] or not check_password(password, u["pw_hash"]):
            return None
        self.db.execute("UPDATE users SET last_login=? WHERE username=?", (time.time(), u["username"]))
        return u

    def end_sessions(self, username):
        self.db.execute("DELETE FROM sessions WHERE username=?", (username,))

    def _admins(self):
        return self.db.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND disabled=0").fetchone()[0]

    def create(self, body, by):
        username = str(body.get("username") or "").strip().lower()
        if not USERNAME_RE.fullmatch(username):
            raise UserError("Usernames are 2–32 characters: lowercase letters, numbers, dot, dash or underscore")
        if self.get(username):
            raise UserError("That username is taken")
        name = str(body.get("name") or "").strip()[:40] or username
        role = body.get("role") if body.get("role") in ROLES else "member"
        password = str(body.get("password") or "") or new_password()
        check_new_password(password)
        self.db.execute("INSERT INTO users(username, name, pw_hash, role, created, created_by) VALUES(?,?,?,?,?,?)",
                        (username, name, hash_password(password), role, time.time(), by))
        return username, password

    def update(self, username, body, by_username):
        u = self.get(username)
        if not u:
            raise UserError("No such user")
        name = str(body.get("name") or u["name"]).strip()[:40] or u["username"]
        role = body.get("role", u["role"])
        disabled = int(bool(body.get("disabled", u["disabled"])))
        if role not in ROLES:
            raise UserError("Unknown role")
        if username == by_username and (role != "admin" or disabled):
            raise UserError("You can't remove your own admin rights or turn off your own account")
        if u["role"] == "admin" and not u["disabled"] and (role != "admin" or disabled) and self._admins() <= 1:
            raise UserError("There has to be at least one admin")
        self.db.execute("UPDATE users SET name=?, role=?, disabled=? WHERE username=?", (name, role, disabled, username))
        if disabled:
            self.end_sessions(username)

    def reset_password(self, username):
        if not self.get(username):
            raise UserError("No such user")
        password = new_password()
        self.db.execute("UPDATE users SET pw_hash=? WHERE username=?", (hash_password(password), username))
        self.end_sessions(username)
        return password

    def change_own_password(self, username, current, new):
        u = self.get(username)
        if not u or not check_password(current, u["pw_hash"]):
            raise UserError("Your current password is wrong")
        check_new_password(new)
        self.db.execute("UPDATE users SET pw_hash=? WHERE username=?", (hash_password(new), username))

    def delete(self, username, by_username):
        u = self.get(username)
        if not u:
            return
        if username == by_username:
            raise UserError("You can't delete your own account")
        if u["role"] == "admin" and not u["disabled"] and self._admins() <= 1:
            raise UserError("There has to be at least one admin")
        self.db.execute("DELETE FROM users WHERE username=?", (username,))
        self.end_sessions(username)
