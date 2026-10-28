import sqlite3
import json
from contextlib import contextmanager
from datetime import datetime, timezone

def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

@contextmanager
def connect(db_path):
    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 30000")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db(db_path):
    with connect(db_path) as conn:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            created_at TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Open',
            priority TEXT NOT NULL DEFAULT 'Routine',
            assignee TEXT NOT NULL DEFAULT '',
            tags TEXT NOT NULL DEFAULT '',
            owner_id INTEGER REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'user')),
            created_at TEXT NOT NULL,
            email TEXT NOT NULL DEFAULT '',
            disabled INTEGER NOT NULL DEFAULT 0,
            totp_secret TEXT NOT NULL DEFAULT '',
            totp_enabled INTEGER NOT NULL DEFAULT 0,
            totp_last_counter INTEGER NOT NULL DEFAULT -1,
            pending_totp_secret TEXT NOT NULL DEFAULT '',
            pending_totp_expires TEXT NOT NULL DEFAULT '',
            session_version INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subject_hash TEXT NOT NULL,
            attempted_at TEXT NOT NULL,
            succeeded INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS login_attempts_subject_time
            ON login_attempts(subject_hash, attempted_at);
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            expires_at TEXT NOT NULL,
            used_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS totp_recovery_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            code_hash TEXT NOT NULL,
            used_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS background_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_type TEXT NOT NULL,
            case_id INTEGER NOT NULL,
            image_id TEXT NOT NULL,
            actor TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'queued',
            error TEXT NOT NULL DEFAULT '',
            retry_count INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            started_at TEXT NOT NULL DEFAULT '',
            completed_at TEXT NOT NULL DEFAULT '',
            FOREIGN KEY(case_id) REFERENCES cases(id)
        );
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            original_name TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            event_count INTEGER NOT NULL DEFAULT 0,
            size_bytes INTEGER NOT NULL DEFAULT 0,
            uploaded_at TEXT NOT NULL,
            FOREIGN KEY(case_id) REFERENCES cases(id)
        );
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            timestamp TEXT,
            severity TEXT NOT NULL,
            event_type TEXT,
            source_ip TEXT,
            username TEXT,
            summary TEXT NOT NULL,
            evidence_name TEXT,
            details TEXT,
            FOREIGN KEY(case_id) REFERENCES cases(id)
        );
        CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            previous_hash TEXT NOT NULL DEFAULT '',
            entry_hash TEXT NOT NULL DEFAULT '',
            FOREIGN KEY(case_id) REFERENCES cases(id)
        );
        CREATE TABLE IF NOT EXISTS disk_images (
            id TEXT PRIMARY KEY,
            case_id INTEGER NOT NULL,
            original_name TEXT NOT NULL,
            stored_dir TEXT NOT NULL,
            root_name TEXT NOT NULL,
            image_type TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            container_sha256 TEXT NOT NULL,
            segment_manifest TEXT NOT NULL,
            analysis_status TEXT NOT NULL DEFAULT 'pending',
            analysis_json TEXT,
            recovery_status TEXT NOT NULL DEFAULT 'pending',
            recovery_json TEXT,
            last_error TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(case_id) REFERENCES cases(id)
        );
        CREATE TABLE IF NOT EXISTS case_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            note TEXT NOT NULL,
            actor TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(case_id) REFERENCES cases(id)
        );
        CREATE TABLE IF NOT EXISTS custody_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            evidence_type TEXT NOT NULL,
            evidence_id TEXT NOT NULL,
            evidence_name TEXT NOT NULL,
            action TEXT NOT NULL,
            actor TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            details TEXT NOT NULL DEFAULT '',
            sha256_before TEXT,
            sha256_after TEXT,
            from_actor TEXT,
            to_actor TEXT,
            FOREIGN KEY(case_id) REFERENCES cases(id)
        );
        CREATE TABLE IF NOT EXISTS packet_captures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            original_name TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            packet_count INTEGER NOT NULL,
            summary_json TEXT NOT NULL,
            uploaded_at TEXT NOT NULL,
            FOREIGN KEY(case_id) REFERENCES cases(id)
        );
        CREATE TABLE IF NOT EXISTS network_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            capture_id INTEGER NOT NULL,
            timestamp TEXT,
            severity TEXT NOT NULL,
            event_type TEXT NOT NULL,
            source_ip TEXT NOT NULL DEFAULT '',
            destination_ip TEXT NOT NULL DEFAULT '',
            destination_port INTEGER,
            summary TEXT NOT NULL,
            details TEXT NOT NULL DEFAULT '{}',
            FOREIGN KEY(case_id) REFERENCES cases(id),
            FOREIGN KEY(capture_id) REFERENCES packet_captures(id)
        );
        CREATE TABLE IF NOT EXISTS indicator_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider TEXT NOT NULL,
            indicator_type TEXT NOT NULL,
            indicator TEXT NOT NULL,
            verdict TEXT NOT NULL,
            response_json TEXT NOT NULL,
            retrieved_at TEXT NOT NULL,
            UNIQUE(provider, indicator_type, indicator)
        );
        CREATE TABLE IF NOT EXISTS finding_feedback (
            event_id INTEGER PRIMARY KEY,
            case_id INTEGER NOT NULL,
            decision TEXT NOT NULL,
            note TEXT NOT NULL DEFAULT '',
            actor TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(case_id) REFERENCES cases(id)
        );
        CREATE TABLE IF NOT EXISTS network_feedback (
            network_event_id INTEGER PRIMARY KEY,
            case_id INTEGER NOT NULL,
            decision TEXT NOT NULL,
            note TEXT NOT NULL DEFAULT '',
            actor TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(case_id) REFERENCES cases(id)
        );
        """)
        _ensure_column(conn, "cases", "status", "TEXT NOT NULL DEFAULT 'Open'")
        _ensure_column(conn, "cases", "priority", "TEXT NOT NULL DEFAULT 'Routine'")
        _ensure_column(conn, "cases", "assignee", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(conn, "cases", "tags", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(conn, "cases", "owner_id", "INTEGER REFERENCES users(id)")
        _ensure_column(conn, "users", "email", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(conn, "users", "disabled", "INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "users", "totp_secret", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(conn, "users", "totp_enabled", "INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "users", "totp_last_counter", "INTEGER NOT NULL DEFAULT -1")
        _ensure_column(conn, "users", "pending_totp_secret", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(conn, "users", "pending_totp_expires", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(conn, "users", "session_version", "INTEGER NOT NULL DEFAULT 0")
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique "
            "ON users(email COLLATE NOCASE) WHERE email <> ''"
        )
        _ensure_column(conn, "evidence", "size_bytes", "INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "background_jobs", "retry_count", "INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "audit", "actor", "TEXT NOT NULL DEFAULT 'Unattributed legacy action'")
        _ensure_column(conn, "audit", "previous_hash", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(conn, "audit", "entry_hash", "TEXT NOT NULL DEFAULT ''")
        _backfill_audit_hashes(conn)


def _ensure_column(conn, table, column, declaration):
    existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in existing:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")


def _audit_entry_hash(row, previous_hash):
    payload = {
        "id": row["id"],
        "case_id": row["case_id"],
        "timestamp": row["timestamp"],
        "action": row["action"],
        "details": row["details"] or "",
        "actor": row["actor"] or "",
        "previous_hash": previous_hash,
    }
    serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    import hashlib
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _backfill_audit_hashes(conn):
    if conn.execute(
        "SELECT 1 FROM audit WHERE entry_hash='' LIMIT 1"
    ).fetchone() is None:
        return
    previous_by_case = {}
    rows = conn.execute("SELECT * FROM audit ORDER BY case_id, id").fetchall()
    for row in rows:
        previous = previous_by_case.get(row["case_id"], "")
        entry_hash = _audit_entry_hash(row, previous)
        conn.execute(
            "UPDATE audit SET previous_hash=?, entry_hash=? WHERE id=?",
            (previous, entry_hash, row["id"]),
        )
        previous_by_case[row["case_id"]] = entry_hash


def create_user(db_path, username, password_hash, role="user", email=""):
    if role not in {"admin", "user"}:
        raise ValueError("Unsupported account role.")
    with connect(db_path) as conn:
        cursor = conn.execute(
            "INSERT INTO users(username, password_hash, role, created_at, email) VALUES(?,?,?,?,?)",
            (username, password_hash, role, now(), email),
        )
        return cursor.lastrowid


def get_user_by_username(db_path, username):
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username=? COLLATE NOCASE", (username,)
        ).fetchone()
        return dict(row) if row else None


def list_users(db_path):
    with connect(db_path) as conn:
        return rows_to_dicts(conn.execute(
            "SELECT id, username, email, role, disabled, totp_enabled, created_at "
            "FROM users ORDER BY username COLLATE NOCASE"
        ).fetchall())


def update_user(db_path, user_id, **fields):
    allowed = {
        "disabled", "role", "email", "totp_secret", "totp_enabled",
        "totp_last_counter", "pending_totp_secret", "pending_totp_expires",
        "password_hash",
    }
    if not fields or not fields.keys() <= allowed:
        raise ValueError("Unsupported user update.")
    if "role" in fields and fields["role"] not in {"admin", "user"}:
        raise ValueError("Unsupported account role.")
    assignments = ", ".join(f"{name}=?" for name in fields)
    with connect(db_path) as conn:
        conn.execute(f"UPDATE users SET {assignments} WHERE id=?", (*fields.values(), user_id))


def update_user_profile(db_path, user_id, username, email):
    with connect(db_path) as conn:
        conn.execute(
            "UPDATE users SET username=?, email=? WHERE id=?",
            (username, email, user_id),
        )


def update_user_password(db_path, user_id, password_hash):
    with connect(db_path) as conn:
        conn.execute(
            "UPDATE users SET password_hash=?, session_version=session_version+1 WHERE id=?",
            (password_hash, user_id),
        )
        row = conn.execute(
            "SELECT session_version FROM users WHERE id=?", (user_id,)
        ).fetchone()
        return row["session_version"] if row else None


def count_enabled_admins(db_path):
    with connect(db_path) as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM users WHERE role='admin' AND disabled=0"
        ).fetchone()[0]


def record_login_attempt(db_path, subject_hash, succeeded, attempted_at):
    with connect(db_path) as conn:
        conn.execute(
            "INSERT INTO login_attempts(subject_hash, attempted_at, succeeded) VALUES(?,?,?)",
            (subject_hash, attempted_at, int(succeeded)),
        )
        conn.execute(
            "DELETE FROM login_attempts WHERE attempted_at < datetime(?, '-1 day')",
            (attempted_at,),
        )


def count_recent_login_failures(db_path, subject_hash, since):
    with connect(db_path) as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM login_attempts "
            "WHERE subject_hash=? AND succeeded=0 AND attempted_at>=?",
            (subject_hash, since),
        ).fetchone()[0]


def add_password_reset_token(db_path, token_hash, user_id, expires_at):
    with connect(db_path) as conn:
        conn.execute(
            "INSERT INTO password_reset_tokens(token_hash,user_id,expires_at) VALUES(?,?,?)",
            (token_hash, user_id, expires_at),
        )


def get_password_reset_token(db_path, token_hash):
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM password_reset_tokens WHERE token_hash=? AND used_at IS NULL",
            (token_hash,),
        ).fetchone()
        return dict(row) if row else None


def consume_password_reset_token(db_path, token_hash, password_hash, user_id):
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT user_id, expires_at, used_at FROM password_reset_tokens WHERE token_hash=?",
            (token_hash,),
        ).fetchone()
        if not row or row["user_id"] != user_id or row["used_at"]:
            return False
        if row["expires_at"] <= now():
            return False
        conn.execute(
            "UPDATE password_reset_tokens SET used_at=? WHERE token_hash=?",
            (now(), token_hash),
        )
        conn.execute(
            "UPDATE users SET password_hash=?, totp_secret='', totp_enabled=0, "
            "totp_last_counter=-1, pending_totp_secret='', pending_totp_expires='', "
            "session_version=session_version+1 WHERE id=?",
            (password_hash, user_id),
        )
        conn.execute("DELETE FROM totp_recovery_codes WHERE user_id=?", (user_id,))
        return True


def replace_totp_recovery_codes(db_path, user_id, code_hashes):
    with connect(db_path) as conn:
        conn.execute("DELETE FROM totp_recovery_codes WHERE user_id=?", (user_id,))
        conn.executemany(
            "INSERT INTO totp_recovery_codes(user_id,code_hash) VALUES(?,?)",
            ((user_id, code_hash) for code_hash in code_hashes),
        )


def consume_totp_recovery_code(db_path, user_id, code_hash):
    with connect(db_path) as conn:
        cursor = conn.execute(
            "UPDATE totp_recovery_codes SET used_at=? "
            "WHERE user_id=? AND code_hash=? AND used_at IS NULL",
            (now(), user_id, code_hash),
        )
        return cursor.rowcount == 1


def cancel_background_job(db_path, job_id):
    with connect(db_path) as conn:
        cursor = conn.execute(
            "UPDATE background_jobs SET status='cancelled',completed_at=?,"
            "error='Cancelled before processing began.' WHERE id=? AND status='queued'",
            (now(), job_id),
        )
        return cursor.rowcount == 1


def retry_background_job(db_path, job_id, case_id, actor):
    with connect(db_path) as conn:
        cursor = conn.execute(
            "UPDATE background_jobs SET status='queued',actor=?,error='',"
            "started_at='',completed_at='',retry_count=retry_count+1 "
            "WHERE id=? AND case_id=? AND status='failed' AND retry_count<3",
            (actor, job_id, case_id),
        )
        if cursor.rowcount != 1:
            return None
        return dict(conn.execute(
            "SELECT * FROM background_jobs WHERE id=?", (job_id,)
        ).fetchone())


def get_case_background_jobs(db_path, case_id):
    with connect(db_path) as conn:
        return rows_to_dicts(conn.execute(
            "SELECT * FROM background_jobs WHERE case_id=? ORDER BY id DESC LIMIT 50",
            (case_id,),
        ).fetchall())


def get_background_job(db_path, job_id):
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM background_jobs WHERE id=?", (job_id,)
        ).fetchone()
        return dict(row) if row else None


def consume_totp_counter(db_path, user_id, counter):
    with connect(db_path) as conn:
        cursor = conn.execute(
            "UPDATE users SET totp_last_counter=? "
            "WHERE id=? AND totp_enabled=1 AND totp_last_counter<?",
            (counter, user_id, counter),
        )
        return cursor.rowcount == 1


def get_user_by_id(db_path, user_id):
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE id=?", (user_id,)
        ).fetchone()
        return dict(row) if row else None


def get_user_by_email(db_path, email):
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE email=? COLLATE NOCASE LIMIT 1", (email,)
        ).fetchone()
        return dict(row) if row else None


def enqueue_background_job(db_path, job_type, case_id, image_id, actor):
    if job_type not in {"image_analysis", "image_recovery"}:
        raise ValueError("Unsupported background job type.")
    with connect(db_path) as conn:
        cursor = conn.execute(
            "INSERT INTO background_jobs(job_type,case_id,image_id,actor,created_at) "
            "VALUES(?,?,?,?,?)",
            (job_type, case_id, image_id, actor, now()),
        )
        return cursor.lastrowid


def update_background_job(db_path, job_id, status, error=""):
    if status not in {"queued", "running", "complete", "failed", "cancelled"}:
        raise ValueError("Unsupported background job status.")
    started_at = now() if status == "running" else ""
    completed_at = now() if status in {"complete", "failed", "cancelled"} else ""
    with connect(db_path) as conn:
        conn.execute(
            "UPDATE background_jobs SET status=?,error=?,"
            "started_at=CASE WHEN ?='' THEN started_at ELSE ? END,"
            "completed_at=? WHERE id=?",
            (status, error[:2000], started_at, started_at, completed_at, job_id),
        )


def claim_background_job(db_path, job_id):
    with connect(db_path) as conn:
        cursor = conn.execute(
            "UPDATE background_jobs SET status='running',started_at=?,error='' "
            "WHERE id=? AND status='queued'",
            (now(), job_id),
        )
        return cursor.rowcount == 1


def recover_background_jobs(db_path):
    with connect(db_path) as conn:
        running = rows_to_dicts(conn.execute(
            "SELECT * FROM background_jobs WHERE status='running'"
        ).fetchall())
        conn.execute(
            "UPDATE background_jobs SET status='queued',started_at='',error='' "
            "WHERE status='running'"
        )
        for job in running:
            if job["job_type"] == "image_analysis":
                conn.execute(
                    "UPDATE disk_images SET analysis_status='queued' WHERE id=?",
                    (job["image_id"],),
                )
            elif job["job_type"] == "image_recovery":
                conn.execute(
                    "UPDATE disk_images SET recovery_status='queued' WHERE id=?",
                    (job["image_id"],),
                )
        return rows_to_dicts(conn.execute(
            "SELECT * FROM background_jobs WHERE status='queued' ORDER BY id"
        ).fetchall())


def get_background_jobs(db_path, limit=100):
    with connect(db_path) as conn:
        return rows_to_dicts(conn.execute(
            "SELECT * FROM background_jobs ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall())


def has_admin_user(db_path):
    with connect(db_path) as conn:
        return conn.execute("SELECT 1 FROM users WHERE role='admin' LIMIT 1").fetchone() is not None


def create_case(db_path, title, description, owner_id):
    with connect(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO cases(title, description, created_at, owner_id) VALUES(?,?,?,?)",
            (title, description, now(), owner_id),
        )
        return cur.lastrowid

def add_evidence(db_path, case_id, original_name, stored_name, digest, event_count, size_bytes):
    with connect(db_path) as conn:
        cursor = conn.execute("""INSERT INTO evidence(
                                    case_id, original_name, stored_name, sha256,
                                    event_count, size_bytes, uploaded_at
                                ) VALUES(?,?,?,?,?,?,?)""",
                              (case_id, original_name, stored_name, digest, event_count, size_bytes, now()))
        return cursor.lastrowid

def add_disk_image(db_path, image_id, case_id, original_name, stored_dir, root_name,
                   image_type, size_bytes, container_sha256, segment_manifest):
    with connect(db_path) as conn:
        conn.execute("""INSERT INTO disk_images(
                            id, case_id, original_name, stored_dir, root_name, image_type,
                            size_bytes, container_sha256, segment_manifest, created_at, updated_at
                        ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                     (image_id, case_id, original_name, stored_dir, root_name, image_type,
                      size_bytes, container_sha256, json.dumps(segment_manifest, ensure_ascii=False),
                      now(), now()))

def update_disk_image(db_path, image_id, **fields):
    allowed_fields = {
        "analysis_status", "analysis_json", "recovery_status", "recovery_json", "last_error",
    }
    if not fields or not fields.keys() <= allowed_fields:
        raise ValueError("Unsupported disk-image update.")
    fields["updated_at"] = now()
    assignments = ", ".join(f"{name}=?" for name in fields)
    with connect(db_path) as conn:
        conn.execute(f"UPDATE disk_images SET {assignments} WHERE id=?",
                     (*fields.values(), image_id))

def get_disk_images(db_path, case_id):
    with connect(db_path) as conn:
        return rows_to_dicts(conn.execute(
            "SELECT * FROM disk_images WHERE case_id=? ORDER BY created_at DESC",
            (case_id,)
        ).fetchall())

def get_disk_image(db_path, image_id):
    with connect(db_path) as conn:
        row = conn.execute("SELECT * FROM disk_images WHERE id=?", (image_id,)).fetchone()
        return dict(row) if row else None

def add_events(db_path, case_id, events):
    with connect(db_path) as conn:
        conn.execute("DELETE FROM events WHERE case_id=?", (case_id,))
        conn.execute("DELETE FROM finding_feedback WHERE case_id=?", (case_id,))
        inserted_ids = []
        for e in events:
            cur = conn.execute("""INSERT INTO events(case_id,timestamp,severity,event_type,source_ip,username,summary,evidence_name,details)
                            VALUES(?,?,?,?,?,?,?,?,?)""",
                         (case_id, e.get("timestamp"), e.get("severity","info"), e.get("event_type","event"),
                          e.get("source_ip",""), e.get("username",""), e.get("summary",""),
                          e.get("evidence_name",""), json.dumps(e.get("details",{}), ensure_ascii=False)))
            inserted_ids.append(cur.lastrowid)
        return inserted_ids

def add_audit(db_path, case_id, action, details, actor="Unattributed local action"):
    with connect(db_path) as conn:
        previous_row = conn.execute(
            "SELECT entry_hash FROM audit WHERE case_id=? ORDER BY id DESC LIMIT 1",
            (case_id,),
        ).fetchone()
        previous_hash = previous_row["entry_hash"] if previous_row else ""
        timestamp = now()
        cursor = conn.execute(
            "INSERT INTO audit(case_id,timestamp,action,details,actor,previous_hash) "
            "VALUES(?,?,?,?,?,?)",
            (case_id, timestamp, action, details, actor, previous_hash),
        )
        row = conn.execute("SELECT * FROM audit WHERE id=?", (cursor.lastrowid,)).fetchone()
        conn.execute(
            "UPDATE audit SET entry_hash=? WHERE id=?",
            (_audit_entry_hash(row, previous_hash), cursor.lastrowid),
        )


def verify_audit_chain(db_path):
    valid = True
    count = 0
    with connect(db_path) as conn:
        previous_by_case = {}
        rows = conn.execute("SELECT * FROM audit ORDER BY case_id, id").fetchall()
        for row in rows:
            count += 1
            previous = previous_by_case.get(row["case_id"], "")
            expected_hash = _audit_entry_hash(row, previous)
            if row["previous_hash"] != previous or row["entry_hash"] != expected_hash:
                valid = False
            previous_by_case[row["case_id"]] = row["entry_hash"]
    return {"valid": valid, "entries": count}


def get_recent_audit_entries(db_path, limit=200):
    with connect(db_path) as conn:
        return rows_to_dicts(conn.execute(
            "SELECT audit.*, cases.title AS case_title "
            "FROM audit JOIN cases ON cases.id=audit.case_id "
            "ORDER BY audit.id DESC LIMIT ?",
            (limit,),
        ).fetchall())

def add_custody_event(db_path, case_id, evidence_type, evidence_id, evidence_name,
                      action, actor, details="", sha256_before=None, sha256_after=None,
                      from_actor=None, to_actor=None):
    with connect(db_path) as conn:
        conn.execute("""INSERT INTO custody_events(
            case_id,evidence_type,evidence_id,evidence_name,action,actor,occurred_at,
            details,sha256_before,sha256_after,from_actor,to_actor
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""", (
            case_id, evidence_type, str(evidence_id), evidence_name, action, actor, now(),
            details, sha256_before, sha256_after, from_actor, to_actor,
        ))

def get_custody_events(db_path, case_id):
    with connect(db_path) as conn:
        return rows_to_dicts(conn.execute(
            "SELECT * FROM custody_events WHERE case_id=? ORDER BY id DESC LIMIT 500",
            (case_id,),
        ).fetchall())

def update_case(db_path, case_id, **fields):
    allowed = {"status", "priority", "assignee", "tags"}
    if not fields or not fields.keys() <= allowed:
        raise ValueError("Unsupported case update.")
    assignments = ", ".join(f"{field}=?" for field in fields)
    with connect(db_path) as conn:
        conn.execute(f"UPDATE cases SET {assignments} WHERE id=?", (*fields.values(), case_id))

def add_case_note(db_path, case_id, note, actor):
    with connect(db_path) as conn:
        conn.execute(
            "INSERT INTO case_notes(case_id,note,actor,created_at) VALUES(?,?,?,?)",
            (case_id, note, actor, now()),
        )

def get_case_notes(db_path, case_id):
    with connect(db_path) as conn:
        return rows_to_dicts(conn.execute(
            "SELECT * FROM case_notes WHERE case_id=? ORDER BY id DESC LIMIT 200",
            (case_id,),
        ).fetchall())

def add_packet_capture(db_path, case_id, original_name, stored_name, sha256,
                       size_bytes, packet_count, summary):
    with connect(db_path) as conn:
        cursor = conn.execute("""INSERT INTO packet_captures(
            case_id,original_name,stored_name,sha256,size_bytes,packet_count,summary_json,uploaded_at
        ) VALUES(?,?,?,?,?,?,?,?)""", (
            case_id, original_name, stored_name, sha256, size_bytes, packet_count,
            json.dumps(summary, ensure_ascii=False), now(),
        ))
        return cursor.lastrowid

def get_packet_captures(db_path, case_id):
    with connect(db_path) as conn:
        captures = rows_to_dicts(conn.execute(
            "SELECT * FROM packet_captures WHERE case_id=? ORDER BY id DESC",
            (case_id,),
        ).fetchall())
        for capture in captures:
            capture["summary"] = json.loads(capture.pop("summary_json"))
        return captures

def add_network_events(db_path, case_id, capture_id, events):
    with connect(db_path) as conn:
        inserted_ids = []
        for event in events:
            cursor = conn.execute("""INSERT INTO network_events(
                case_id,capture_id,timestamp,severity,event_type,source_ip,destination_ip,
                destination_port,summary,details
            ) VALUES(?,?,?,?,?,?,?,?,?,?)""", (
                case_id, capture_id, event.get("timestamp"), event.get("severity", "info"),
                event.get("event_type", "network_event"), event.get("source_ip", ""),
                event.get("destination_ip", ""), event.get("destination_port"),
                event.get("summary", ""), json.dumps(event.get("details", {}), ensure_ascii=False),
            ))
            inserted_ids.append(cursor.lastrowid)
        return inserted_ids

def get_network_events(db_path, case_id):
    with connect(db_path) as conn:
        results = rows_to_dicts(conn.execute(
            "SELECT network_events.*, packet_captures.original_name AS evidence_name, "
            "network_feedback.decision AS feedback_decision, network_feedback.note AS feedback_note, "
            "network_feedback.actor AS feedback_actor, network_feedback.updated_at AS feedback_updated_at "
            "FROM network_events JOIN packet_captures ON packet_captures.id=network_events.capture_id "
            "LEFT JOIN network_feedback ON network_feedback.network_event_id=network_events.id "
            "WHERE network_events.case_id=? ORDER BY COALESCE(timestamp,''), network_events.id",
            (case_id,),
        ).fetchall())
        for event in results:
            try:
                event["details"] = json.loads(event["details"])
            except json.JSONDecodeError:
                event["details"] = {"parse_error": True}
            event["record_key"] = f"net-{event['id']}"
        return results

def upsert_indicator_cache(db_path, provider, indicator_type, indicator, verdict, response):
    with connect(db_path) as conn:
        conn.execute("""INSERT INTO indicator_cache(
            provider,indicator_type,indicator,verdict,response_json,retrieved_at
        ) VALUES(?,?,?,?,?,?)
        ON CONFLICT(provider,indicator_type,indicator) DO UPDATE SET
            verdict=excluded.verdict,response_json=excluded.response_json,
            retrieved_at=excluded.retrieved_at""", (
            provider, indicator_type, indicator, verdict,
            json.dumps(response, ensure_ascii=False), now(),
        ))

def get_indicator_cache(db_path, provider, indicator_type, indicator):
    with connect(db_path) as conn:
        row = conn.execute("""SELECT * FROM indicator_cache
            WHERE provider=? AND indicator_type=? AND indicator=?""",
            (provider, indicator_type, indicator),
        ).fetchone()
        if not row:
            return None
        result = dict(row)
        result["response"] = json.loads(result.pop("response_json"))
        return result

def save_finding_feedback(db_path, case_id, event_id, decision, note, actor):
    with connect(db_path) as conn:
        exists = conn.execute(
            "SELECT 1 FROM events WHERE id=? AND case_id=?", (event_id, case_id),
        ).fetchone()
        if not exists:
            return False
        conn.execute("""INSERT INTO finding_feedback(
            event_id,case_id,decision,note,actor,updated_at
        ) VALUES(?,?,?,?,?,?)
        ON CONFLICT(event_id) DO UPDATE SET decision=excluded.decision,note=excluded.note,
            actor=excluded.actor,updated_at=excluded.updated_at""",
            (event_id, case_id, decision, note, actor, now()),
        )
        return True

def save_network_feedback(db_path, case_id, event_id, decision, note, actor):
    with connect(db_path) as conn:
        exists = conn.execute(
            "SELECT 1 FROM network_events WHERE id=? AND case_id=?", (event_id, case_id),
        ).fetchone()
        if not exists:
            return False
        conn.execute("""INSERT INTO network_feedback(
            network_event_id,case_id,decision,note,actor,updated_at
        ) VALUES(?,?,?,?,?,?)
        ON CONFLICT(network_event_id) DO UPDATE SET decision=excluded.decision,note=excluded.note,
            actor=excluded.actor,updated_at=excluded.updated_at""",
            (event_id, case_id, decision, note, actor, now()),
        )
        return True

def get_feedback(db_path, case_id):
    with connect(db_path) as conn:
        return rows_to_dicts(conn.execute("""
            SELECT decision FROM finding_feedback WHERE case_id=?
            UNION ALL
            SELECT decision FROM network_feedback WHERE case_id=?
        """, (case_id, case_id)).fetchall())

def rows_to_dicts(rows):
    return [dict(row) for row in rows]

def get_cases(db_path, owner_id=None):
    with connect(db_path) as conn:
        query = """
            SELECT c.*,
                (SELECT COUNT(*) FROM evidence e WHERE e.case_id=c.id) +
                (SELECT COUNT(*) FROM disk_images d WHERE d.case_id=c.id) +
                (SELECT COUNT(*) FROM packet_captures p WHERE p.case_id=c.id) AS evidence_count,
                COALESCE((SELECT MAX(a.timestamp) FROM audit a WHERE a.case_id=c.id), c.created_at)
                    AS last_updated_at,
                owners.username AS owner_username
            FROM cases c
            LEFT JOIN users AS owners ON owners.id=c.owner_id
        """
        if owner_id is not None:
            query += " WHERE c.owner_id=?"
            params = (owner_id,)
        else:
            params = ()
        query += " ORDER BY last_updated_at DESC, c.id DESC"
        return rows_to_dicts(conn.execute(query, params).fetchall())


def get_workspace_review_summary(db_path, owner_id=None):
    case_filter = "WHERE owner_id=?" if owner_id is not None else ""
    params = (owner_id,) if owner_id is not None else ()
    with connect(db_path) as conn:
        row = conn.execute(f"""
            WITH scoped_cases AS (
                SELECT id FROM cases {case_filter}
            ),
            reviewable_findings AS (
                SELECT e.severity, f.decision
                FROM events e
                JOIN scoped_cases c ON c.id=e.case_id
                LEFT JOIN finding_feedback f ON f.event_id=e.id
                WHERE e.severity IN ('medium', 'high')
                UNION ALL
                SELECT n.severity, f.decision
                FROM network_events n
                JOIN scoped_cases c ON c.id=n.case_id
                LEFT JOIN network_feedback f ON f.network_event_id=n.id
                WHERE n.severity IN ('medium', 'high')
            )
            SELECT
                COALESCE(SUM(CASE WHEN severity='high' THEN 1 ELSE 0 END), 0) AS high_findings,
                COALESCE(SUM(CASE WHEN decision IS NULL THEN 1 ELSE 0 END), 0) AS pending_reviews
            FROM reviewable_findings
        """, params).fetchone()
        return dict(row)


def get_user_storage_usage(db_path, user_id):
    with connect(db_path) as conn:
        return conn.execute("""
            SELECT
                COALESCE((SELECT SUM(e.size_bytes) FROM evidence e
                          JOIN cases c ON c.id=e.case_id WHERE c.owner_id=?),0) +
                COALESCE((SELECT SUM(i.size_bytes) FROM disk_images i
                          JOIN cases c ON c.id=i.case_id WHERE c.owner_id=?),0) +
                COALESCE((SELECT SUM(p.size_bytes) FROM packet_captures p
                          JOIN cases c ON c.id=p.case_id WHERE c.owner_id=?),0)
        """, (user_id, user_id, user_id)).fetchone()[0]


def backfill_evidence_sizes(db_path, sizes_by_name):
    with connect(db_path) as conn:
        for stored_name, size_bytes in sizes_by_name.items():
            conn.execute(
                "UPDATE evidence SET size_bytes=? WHERE stored_name=? AND size_bytes=0",
                (size_bytes, stored_name),
            )


def get_unmeasured_evidence(db_path):
    with connect(db_path) as conn:
        return rows_to_dicts(conn.execute(
            "SELECT stored_name FROM evidence WHERE size_bytes=0"
        ).fetchall())

def get_case(db_path, case_id):
    with connect(db_path) as conn:
        row = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        return dict(row) if row else None

def get_evidence(db_path, case_id):
    with connect(db_path) as conn:
        return rows_to_dicts(conn.execute("SELECT * FROM evidence WHERE case_id=? ORDER BY id DESC", (case_id,)).fetchall())

def get_events(db_path, case_id):
    with connect(db_path) as conn:
        results = rows_to_dicts(conn.execute("""
            SELECT events.*, finding_feedback.decision AS feedback_decision,
                finding_feedback.note AS feedback_note, finding_feedback.actor AS feedback_actor,
                finding_feedback.updated_at AS feedback_updated_at
            FROM events LEFT JOIN finding_feedback ON finding_feedback.event_id=events.id
            WHERE events.case_id=? ORDER BY COALESCE(events.timestamp,''), events.id
        """, (case_id,)).fetchall())
        for event in results:
            try:
                event["details"] = json.loads(event["details"] or "{}")
            except json.JSONDecodeError:
                event["details"] = {"parse_error": True}
            event["record_key"] = f"evt-{event['id']}"
        return results

def get_audit(db_path, case_id):
    with connect(db_path) as conn:
        return rows_to_dicts(conn.execute("SELECT * FROM audit WHERE case_id=? ORDER BY id DESC LIMIT 100", (case_id,)).fetchall())
