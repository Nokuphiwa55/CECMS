import base64
import hashlib
import hmac
import math
import os
import secrets
import socket
import sqlite3
import struct
import time
from datetime import datetime, timedelta

ROLES = ("Administrator", "Investigator", "Authorized user")
ROLE_ALIASES = {
    "administrator": "Administrator",
    "investigator": "Investigator",
    "reviewer": "Investigator",
    "authorized user": "Authorized user",
    "analyst": "Authorized user",
}
MIN_PASSWORD_LENGTH = 12
PBKDF2_ITERATIONS = 600_000
LOGIN_FAILURE_LIMIT = 3
LOCKOUT_MINUTES = 15
TOTP_STEP_SECONDS = 30
TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"


def initialize_authentication(database_path):

    connection = sqlite3.connect(database_path)

    try:

        connection.execute("""
            CREATE TABLE IF NOT EXISTS app_users (
                username TEXT PRIMARY KEY COLLATE NOCASE,
                salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT NOT NULL,
                totp_secret TEXT NOT NULL DEFAULT '',
                mfa_enabled INTEGER NOT NULL DEFAULT 0
            )
        """)

        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(app_users)")
        }
        schema_row = connection.execute("""
            SELECT sql FROM sqlite_master
            WHERE type = 'table' AND name = 'app_users'
        """).fetchone()
        schema = schema_row[0].casefold() if schema_row else ""

        if ("administrator" not in schema
                or not {"totp_secret", "mfa_enabled"}.issubset(columns)):

            secret_expression = "totp_secret" if "totp_secret" in columns else "''"
            enabled_expression = "mfa_enabled" if "mfa_enabled" in columns else "0"
            connection.execute("""
                CREATE TABLE app_users_new (
                    username TEXT PRIMARY KEY COLLATE NOCASE,
                    salt TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK (
                        role IN ('Administrator', 'Investigator', 'Authorized user')
                    ),
                    created_at TEXT NOT NULL,
                    totp_secret TEXT NOT NULL DEFAULT '',
                    mfa_enabled INTEGER NOT NULL DEFAULT 0
                )
            """)
            connection.execute(f"""
                INSERT INTO app_users_new (
                    username, salt, password_hash, role, created_at,
                    totp_secret, mfa_enabled
                )
                SELECT username, salt, password_hash,
                    CASE role
                        WHEN 'Reviewer' THEN 'Investigator'
                        WHEN 'Analyst' THEN 'Authorized user'
                        ELSE role
                    END,
                    created_at,
                    {secret_expression},
                    {enabled_expression}
                FROM app_users
            """)
            connection.execute("DROP TABLE app_users")
            connection.execute(
                "ALTER TABLE app_users_new RENAME TO app_users"
            )

        connection.execute("""
            CREATE TABLE IF NOT EXISTS login_failures (
                username TEXT PRIMARY KEY COLLATE NOCASE,
                attempts INTEGER NOT NULL DEFAULT 0,
                last_failed_at TEXT NOT NULL,
                ip_address TEXT NOT NULL DEFAULT 'unknown',
                hostname TEXT NOT NULL DEFAULT 'unknown',
                locked_until TEXT
            )
        """)
        failure_columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(login_failures)")
        }
        for column, definition in (
            ("ip_address", "TEXT NOT NULL DEFAULT 'unknown'"),
            ("hostname", "TEXT NOT NULL DEFAULT 'unknown'"),
            ("locked_until", "TEXT"),
        ):
            if column not in failure_columns:
                connection.execute(
                    f"ALTER TABLE login_failures ADD COLUMN {column} {definition}"
                )

        connection.execute("""
            CREATE TABLE IF NOT EXISTS security_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                attempted_username TEXT NOT NULL,
                failed_attempts INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                acknowledged_by TEXT,
                acknowledged_at TEXT,
                ip_address TEXT NOT NULL DEFAULT 'unknown',
                hostname TEXT NOT NULL DEFAULT 'unknown',
                locked_until TEXT
            )
        """)
        alert_columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(security_alerts)")
        }
        for column in ("ip_address", "hostname", "locked_until"):
            if column not in alert_columns:
                definition = (
                    "TEXT" if column == "locked_until"
                    else "TEXT NOT NULL DEFAULT 'unknown'"
                )
                connection.execute(
                    f"ALTER TABLE security_alerts ADD COLUMN {column} {definition}"
                )

        connection.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                event_time TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                hostname TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT ''
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS setup_state (
                state_id INTEGER PRIMARY KEY CHECK (state_id = 1),
                setup_completed INTEGER NOT NULL DEFAULT 0
            )
        """)
        connection.execute("""
            INSERT OR IGNORE INTO setup_state (state_id, setup_completed)
            VALUES (1, 0)
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS system_control (
                state_id INTEGER PRIMARY KEY CHECK (state_id = 1),
                is_locked INTEGER NOT NULL DEFAULT 0,
                locked_by TEXT,
                locked_at TEXT,
                lock_reason TEXT NOT NULL DEFAULT ''
            )
        """)
        connection.execute("""
            INSERT OR IGNORE INTO system_control (state_id, is_locked)
            VALUES (1, 0)
        """)
        account_count = connection.execute(
            "SELECT COUNT(*) FROM app_users"
        ).fetchone()[0]
        has_administrator = connection.execute("""
            SELECT 1 FROM app_users
            WHERE role = 'Administrator' LIMIT 1
        """).fetchone()
        if account_count and not has_administrator:
            connection.execute("""
                UPDATE app_users
                SET role = 'Administrator'
                WHERE username = (
                    SELECT username FROM app_users
                    ORDER BY created_at, username LIMIT 1
                )
            """)

        if account_count:

            connection.execute("""
                UPDATE setup_state
                SET setup_completed = 1
                WHERE state_id = 1
            """)

        connection.commit()
        return connection.execute(
            "SELECT setup_completed FROM setup_state WHERE state_id = 1"
        ).fetchone()[0]

    finally:

        connection.close()


def generate_totp_secret():

    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def totp_code(secret, timestamp=None):

    timestamp = time.time() if timestamp is None else timestamp
    counter = math.floor(timestamp / TOTP_STEP_SECONDS)
    padded_secret = secret + "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded_secret, casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF

    return f"{number % 1_000_000:06d}"


def verify_totp(secret, code, timestamp=None):

    if not code or not code.isdigit() or len(code) != 6:
        return False

    timestamp = time.time() if timestamp is None else timestamp
    return any(
        hmac.compare_digest(
            totp_code(secret, timestamp + offset * TOTP_STEP_SECONDS),
            code
        )
        for offset in (-1, 0, 1)
    )


def create_user(database_path, username, password, role, totp_secret, setup_code):

    username = username.strip()
    if len(username) < 3 or len(username) > 48:
        raise ValueError("Username must be 3 to 48 characters.")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
        )

    role = ROLE_ALIASES.get(role.strip().casefold())
    if role not in ROLES:
        raise ValueError("Choose an Administrator, Investigator, or Authorized user role.")
    if not verify_totp(totp_secret, setup_code):
        raise ValueError("The authenticator code is invalid.")

    salt = secrets.token_bytes(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    connection = sqlite3.connect(database_path)
    try:
        setup_row = connection.execute("""
            SELECT setup_completed FROM setup_state WHERE state_id = 1
        """).fetchone()
        setup_completed = bool(setup_row and setup_row[0])

        if not setup_completed and role != "Administrator":

            raise ValueError("Create the Administrator account before staff accounts.")

        if role == "Administrator" and setup_completed:

            raise ValueError("Administrator setup has already been completed.")

        if role == "Administrator" and connection.execute(
            "SELECT 1 FROM app_users WHERE role = 'Administrator' LIMIT 1"
        ).fetchone():
            raise ValueError("Administrator setup has already been completed.")

        connection.execute("""
            INSERT INTO app_users (
                username, salt, password_hash, role, created_at,
                totp_secret, mfa_enabled
            ) VALUES (?, ?, ?, ?, ?, ?, 1)
        """, (
            username,
            salt.hex(),
            password_hash.hex(),
            role,
            datetime.now().strftime(TIMESTAMP_FORMAT),
            totp_secret
        ))

        if role == "Administrator":

            connection.execute("""
                UPDATE setup_state
                SET setup_completed = 1
                WHERE state_id = 1
            """)

        connection.commit()
    except sqlite3.IntegrityError as error:
        if "unique" in str(error).casefold():
            raise ValueError(
                "That username is already in use. Please choose a different username."
            ) from error
        raise
    finally:
        connection.close()


def host_identity():

    hostname = socket.gethostname() or "unknown"
    try:
        addresses = socket.getaddrinfo(hostname, None, socket.AF_INET)
        ip_address = next(
            (item[4][0] for item in addresses if not item[4][0].startswith("127.")),
            "127.0.0.1 (local)"
        )
    except OSError:
        ip_address = "unknown"
    return ip_address, hostname


def audit_event(database_path, username, action, details=""):

    ip_address, hostname = host_identity()
    connection = sqlite3.connect(database_path)
    try:
        connection.execute("""
            INSERT INTO audit_log (
                username, action, event_time, ip_address, hostname, details
            ) VALUES (?, ?, ?, ?, ?, ?)
        """, (
            username or "unknown",
            action,
            datetime.now().strftime(TIMESTAMP_FORMAT),
            ip_address,
            hostname,
            details[:500]
        ))
        connection.commit()
    finally:
        connection.close()


def record_failed_login(database_path, username, reason="login failed"):

    username = username.strip() or "(blank username)"
    now = datetime.now()
    ip_address, hostname = host_identity()
    connection = sqlite3.connect(database_path)
    try:
        row = connection.execute("""
            SELECT attempts, locked_until FROM login_failures
            WHERE username = ? COLLATE NOCASE
        """, (username,)).fetchone()
        attempts = row[0] + 1 if row else 1
        active_lock = False
        if row and row[1]:
            lock_expiry = datetime.strptime(row[1], TIMESTAMP_FORMAT)
            active_lock = now < lock_expiry
        if active_lock:
            attempts = row[0]
            locked_until = row[1]
        else:
            locked_until = None
            if attempts >= LOGIN_FAILURE_LIMIT:
                locked_until = (now + timedelta(minutes=LOCKOUT_MINUTES)).strftime(
                    TIMESTAMP_FORMAT
                )

        connection.execute("""
            INSERT INTO login_failures (
                username, attempts, last_failed_at, ip_address, hostname,
                locked_until
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(username) DO UPDATE SET
                attempts = excluded.attempts,
                last_failed_at = excluded.last_failed_at,
                ip_address = excluded.ip_address,
                hostname = excluded.hostname,
                locked_until = excluded.locked_until
        """, (
            username, attempts, now.strftime(TIMESTAMP_FORMAT),
            ip_address, hostname, locked_until
        ))

        crossed_lockout_threshold = (
            attempts >= LOGIN_FAILURE_LIMIT
            and (not row or row[0] < LOGIN_FAILURE_LIMIT)
        )

        if crossed_lockout_threshold and not active_lock:
            connection.execute("""
                INSERT INTO security_alerts (
                    attempted_username, failed_attempts, created_at,
                    ip_address, hostname, locked_until
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                username, attempts, now.strftime(TIMESTAMP_FORMAT),
                ip_address, hostname, locked_until
            ))

        connection.execute("""
            INSERT INTO audit_log (
                username, action, event_time, ip_address, hostname, details
            ) VALUES (?, 'FAILED LOGIN', ?, ?, ?, ?)
        """, (
            username,
            now.strftime(TIMESTAMP_FORMAT),
            ip_address,
            hostname,
            f"{reason}; failed attempts: {attempts}; locked until: {locked_until or 'not locked'}"
        ))
        connection.commit()
        return attempts, locked_until
    finally:
        connection.close()


def authenticate_user(database_path, username, password, verification_code=None):

    initialize_authentication(database_path)
    username = username.strip() or "(blank username)"
    connection = sqlite3.connect(database_path)
    try:
        row = connection.execute("""
            SELECT username, salt, password_hash, role, totp_secret,
                mfa_enabled
            FROM app_users
            WHERE username = ? COLLATE NOCASE
        """, (username,)).fetchone()
        lock_row = connection.execute("""
            SELECT attempts, locked_until
            FROM login_failures
            WHERE username = ? COLLATE NOCASE
        """, (username,)).fetchone()
    finally:
        connection.close()

    if lock_row and lock_row[1]:
        lock_expiry = datetime.strptime(lock_row[1], TIMESTAMP_FORMAT)
        if datetime.now() < lock_expiry:
            audit_event(database_path, username, "FAILED LOGIN", "Account is locked")
            return None
        clear_lockout(database_path, username)

    if row is None:
        record_failed_login(database_path, username, "unknown username")
        return None

    expected_hash = bytes.fromhex(row[2])
    actual_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(row[1]),
        PBKDF2_ITERATIONS
    )
    if not hmac.compare_digest(actual_hash, expected_hash):
        record_failed_login(database_path, username, "password mismatch")
        return None

    if not row[5] or not row[4]:
        clear_lockout(database_path, username)
        return {
            "username": row[0],
            "role": row[3],
            "mfa_enrollment_required": True
        }

    if verification_code is None:
        return {
            "username": row[0],
            "role": row[3],
            "mfa_challenge_required": True
        }

    if not verify_totp(row[4], verification_code):
        record_failed_login(database_path, username, "verification code mismatch")
        return None

    clear_lockout(database_path, username)

    if system_lock_status(database_path)[0]:

        audit_event(
            database_path,
            row[0],
            "LOGIN BLOCKED BY SYSTEM LOCK",
            "System is locked by an Administrator"
        )
        return {
            "username": row[0],
            "role": row[3],
            "system_locked": True
        }

    audit_event(database_path, row[0], "USER LOGIN")
    return {"username": row[0], "role": row[3]}


def set_totp_secret(database_path, username, secret):

    connection = sqlite3.connect(database_path)
    try:
        cursor = connection.execute("""
            UPDATE app_users
            SET totp_secret = ?, mfa_enabled = 0
            WHERE username = ? COLLATE NOCASE
        """, (secret, username.strip()))
        if cursor.rowcount == 0:
            raise ValueError("Account was not found.")
        connection.commit()
    finally:
        connection.close()


def complete_totp_enrollment(database_path, username, code):

    connection = sqlite3.connect(database_path)
    try:
        row = connection.execute("""
            SELECT totp_secret FROM app_users
            WHERE username = ? COLLATE NOCASE
        """, (username.strip(),)).fetchone()
        if not row or not verify_totp(row[0], code):
            return False
        connection.execute("""
            UPDATE app_users SET mfa_enabled = 1
            WHERE username = ? COLLATE NOCASE
        """, (username.strip(),))
        connection.commit()
    finally:
        connection.close()

    audit_event(database_path, username, "MFA ENROLLED")
    return True


def reset_administrator_mfa(database_path, username):

    username = username.strip()
    connection = sqlite3.connect(database_path)
    try:
        with connection:
            row = connection.execute("""
                SELECT username
                FROM app_users
                WHERE username = ? COLLATE NOCASE
                    AND role = 'Administrator'
            """, (username,)).fetchone()
            if not row:
                raise ValueError("No Administrator account was found with that username.")

            connection.execute("""
                UPDATE app_users
                SET totp_secret = '', mfa_enabled = 0
                WHERE username = ? COLLATE NOCASE
                    AND role = 'Administrator'
            """, (username,))
            connection.execute("""
                DELETE FROM login_failures
                WHERE username = ? COLLATE NOCASE
            """, (username,))
    finally:
        connection.close()

    audit_event(
        database_path,
        row[0],
        "ADMINISTRATOR MFA RECOVERY",
        "Authenticator reset through the local recovery command; "
        "password unchanged; authenticator re-enrollment required."
    )
    return row[0]


def reset_administrator_password(database_path, username, new_password):

    username = username.strip()
    if len(new_password) < MIN_PASSWORD_LENGTH:
        raise ValueError(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
        )

    salt = secrets.token_bytes(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        new_password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    )
    connection = sqlite3.connect(database_path)
    try:
        with connection:
            row = connection.execute("""
                SELECT username
                FROM app_users
                WHERE username = ? COLLATE NOCASE
                    AND role = 'Administrator'
            """, (username,)).fetchone()
            if not row:
                raise ValueError(
                    "No Administrator account was found with that username."
                )

            connection.execute("""
                UPDATE app_users
                SET salt = ?, password_hash = ?
                WHERE username = ? COLLATE NOCASE
                    AND role = 'Administrator'
            """, (salt.hex(), password_hash.hex(), username))
            connection.execute("""
                DELETE FROM login_failures
                WHERE username = ? COLLATE NOCASE
            """, (username,))
    finally:
        connection.close()

    audit_event(
        database_path,
        row[0],
        "ADMINISTRATOR PASSWORD RECOVERY",
        "Password reset through the local recovery command; "
        "existing MFA enrollment state unchanged."
    )
    return row[0]


def clear_lockout(database_path, username):

    connection = sqlite3.connect(database_path)
    try:
        connection.execute(
            "DELETE FROM login_failures WHERE username = ? COLLATE NOCASE",
            (username.strip(),)
        )
        connection.commit()
    finally:
        connection.close()


def lockout_status(database_path, username):

    connection = sqlite3.connect(database_path)
    try:
        row = connection.execute("""
            SELECT attempts, locked_until
            FROM login_failures
            WHERE username = ? COLLATE NOCASE
        """, (username.strip() or "(blank username)",)).fetchone()
        if not row or not row[1]:
            return (row[0] if row else 0), None
        expiry = datetime.strptime(row[1], TIMESTAMP_FORMAT)
        if datetime.now() >= expiry:
            return row[0], None
        return row[0], row[1]
    finally:
        connection.close()


def unlock_user(database_path, username, administrator):

    if not administrator or administrator.get("role") != "Administrator":
        raise PermissionError("Administrator access required.")
    clear_lockout(database_path, username)
    audit_event(database_path, administrator["username"], "USER UNLOCKED", username)


def system_lock_status(database_path):

    connection = sqlite3.connect(database_path)
    try:
        row = connection.execute("""
            SELECT is_locked, locked_by, locked_at, lock_reason
            FROM system_control WHERE state_id = 1
        """).fetchone()
        return row if row else (False, None, None, "")
    finally:
        connection.close()


def set_system_lock(database_path, administrator, locked, reason=""):

    if not is_administrator(administrator):
        raise PermissionError("Administrator access required.")

    timestamp = datetime.now().strftime(TIMESTAMP_FORMAT) if locked else None
    connection = sqlite3.connect(database_path)
    try:
        connection.execute("""
            UPDATE system_control
            SET is_locked = ?, locked_by = ?, locked_at = ?, lock_reason = ?
            WHERE state_id = 1
        """, (
            int(locked),
            administrator["username"] if locked else None,
            timestamp,
            reason[:250] if locked else ""
        ))
        connection.commit()
    finally:
        connection.close()

    action = "SYSTEM LOCKED" if locked else "SYSTEM UNLOCKED"
    audit_event(database_path, administrator["username"], action, reason)


def list_locked_users(database_path, administrator):

    if not is_administrator(administrator):
        return []
    connection = sqlite3.connect(database_path)
    try:
        return connection.execute("""
            SELECT username, attempts, last_failed_at, ip_address, hostname,
                locked_until
            FROM login_failures
            WHERE locked_until IS NOT NULL
                AND locked_until > ?
            ORDER BY last_failed_at DESC
        """, (datetime.now().strftime(TIMESTAMP_FORMAT),)).fetchall()
    finally:
        connection.close()


def recent_audit_events(database_path, administrator, limit=100):

    if not is_administrator(administrator):
        return []
    connection = sqlite3.connect(database_path)
    try:
        return connection.execute("""
            SELECT username, action, event_time, ip_address, hostname, details
            FROM audit_log
            ORDER BY id DESC
            LIMIT ?
        """, (max(1, min(limit, 500)),)).fetchall()
    finally:
        connection.close()


def backup_database(database_path, administrator):

    if not is_administrator(administrator):
        raise PermissionError("Administrator access required.")

    initialize_authentication(database_path)

    backup_directory = os.path.join(
        os.path.dirname(os.path.abspath(database_path)),
        "backups"
    )
    os.makedirs(backup_directory, exist_ok=True)
    filename = "cecms_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".sqlite3"
    backup_path = os.path.join(backup_directory, filename)
    source = sqlite3.connect(database_path)
    destination = sqlite3.connect(backup_path)

    try:
        source.backup(destination)
        destination.commit()
    finally:
        destination.close()
        source.close()

    audit_event(database_path, administrator["username"], "DATABASE BACKUP", backup_path)
    return backup_path


def check_database_integrity(database_path, administrator):

    if not is_administrator(administrator):
        raise PermissionError("Administrator access required.")

    initialize_authentication(database_path)

    connection = sqlite3.connect(database_path)
    try:
        result = connection.execute("PRAGMA integrity_check").fetchone()[0]
    finally:
        connection.close()

    audit_event(
        database_path,
        administrator["username"],
        "DATABASE INTEGRITY CHECK",
        str(result)
    )
    return result


def daily_backup_if_due(database_path, administrator):

    if not is_administrator(administrator):
        raise PermissionError("Administrator access required.")

    initialize_authentication(database_path)
    connection = sqlite3.connect(database_path)
    try:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS maintenance_state (
                setting TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        row = connection.execute(
            "SELECT value FROM maintenance_state WHERE setting = 'last_backup_at'"
        ).fetchone()
        last_backup = (
            datetime.strptime(row[0], TIMESTAMP_FORMAT) if row else None
        )
    finally:
        connection.close()

    if last_backup and datetime.now() - last_backup < timedelta(days=1):
        return None

    backup_path = backup_database(database_path, administrator)
    connection = sqlite3.connect(database_path)
    try:
        connection.execute("""
            INSERT INTO maintenance_state (setting, value)
            VALUES ('last_backup_at', ?)
            ON CONFLICT(setting) DO UPDATE SET value = excluded.value
        """, (datetime.now().strftime(TIMESTAMP_FORMAT),))
        connection.commit()
    finally:
        connection.close()

    return backup_path


def login_failure_count(database_path, username):

    connection = sqlite3.connect(database_path)
    try:
        row = connection.execute("""
            SELECT attempts FROM login_failures
            WHERE username = ? COLLATE NOCASE
        """, (username.strip() or "(blank username)",)).fetchone()
        return row[0] if row else 0
    finally:
        connection.close()


def is_reviewer(user):

    return bool(user) and user.get("role") in ("Administrator", "Investigator", "Reviewer")


def is_administrator(user):

    return bool(user) and user.get("role") == "Administrator"


def pending_security_alerts(database_path, administrator):

    if not is_administrator(administrator):
        return []
    connection = sqlite3.connect(database_path)
    try:
        return connection.execute("""
            SELECT id, attempted_username, failed_attempts, created_at,
                ip_address, hostname, locked_until
            FROM security_alerts
            WHERE acknowledged_at IS NULL
            ORDER BY id
        """).fetchall()
    finally:
        connection.close()


def acknowledge_security_alerts(database_path, alert_ids, administrator):

    if not is_administrator(administrator) or not alert_ids:
        return
    placeholders = ", ".join("?" for _ in alert_ids)
    connection = sqlite3.connect(database_path)
    try:
        connection.execute(f"""
            UPDATE security_alerts
            SET acknowledged_by = ?, acknowledged_at = ?
            WHERE id IN ({placeholders}) AND acknowledged_at IS NULL
        """, (
            administrator["username"],
            datetime.now().strftime(TIMESTAMP_FORMAT),
            *alert_ids
        ))
        connection.commit()
    finally:
        connection.close()
