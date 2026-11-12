"""SQLite persistence layer.

Concurrency model
-----------------
* WAL journal + a 30 s busy timeout allow many concurrent readers alongside a
  single writer. Each HTTP request opens its own connection (sqlite3 objects
  must not be shared across threads) and every batch is committed in one
  ``BEGIN IMMEDIATE`` transaction, so two concurrent batches serialize cleanly
  and either the whole batch lands or nothing does.
* All identity/mapping rows carry a UNIQUE constraint on
  ``(center_id, original_uid)`` and ``(center_id, original_sop_uid, sha256)``;
  a conflicting insert is detected and turned into a batch-level rejection.

Integrity / inspection model
----------------------------
* ``instances.stored_sha256`` is the SHA-256 of the *rewritten* file actually
  stored on disk (the trust anchor used by center inspections). Rows created
  before this feature existed carry NULL and are reported as
  ``no_fingerprint``; a current disk file is never treated as their baseline.
* ``instances.quarantine_state`` / ``state_version`` drive the lifecycle
  ``active <-> quarantined`` and let late, stale inspections lose against a
  repair that already happened (compare-and-swap on the version).
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from typing import Iterator

from . import config
from .config import BUSY_TIMEOUT_MS

SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS centers (
    center_id   TEXT PRIMARY KEY,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- One row per (center, original UID) ever observed. The mapping value itself
-- is derivable with app.uid.remap_uid; the table exists so reference-first
-- uploads can reserve rows before the referenced image arrives.
CREATE TABLE IF NOT EXISTS uid_mappings (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    center_id         TEXT NOT NULL,
    original_uid      TEXT NOT NULL,
    new_uid           TEXT NOT NULL,
    uid_kind          TEXT NOT NULL,                 -- study | series | sop | other_ui
    present           INTEGER NOT NULL DEFAULT 0,    -- 1 once an object carrying this SOP exists
    first_seen_batch  TEXT,
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE (center_id, original_uid)
);
CREATE INDEX IF NOT EXISTS idx_uid_mappings_new
    ON uid_mappings (center_id, new_uid);

-- Ingested DICOM objects (one physical rewritten file per row).
CREATE TABLE IF NOT EXISTS instances (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    center_id              TEXT NOT NULL,
    batch_id               TEXT NOT NULL,
    original_sop_uid       TEXT NOT NULL,
    new_sop_uid            TEXT NOT NULL,
    original_study_uid     TEXT NOT NULL,
    new_study_uid          TEXT NOT NULL,
    original_series_uid    TEXT NOT NULL,
    new_series_uid         TEXT NOT NULL,
    modality               TEXT,
    transfer_syntax_uid    TEXT NOT NULL,
    sha256                 TEXT NOT NULL,
    byte_size              INTEGER NOT NULL,
    stored_path            TEXT NOT NULL,
    created_at             TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE (center_id, original_sop_uid, sha256),
    UNIQUE (new_sop_uid),
    FOREIGN KEY (center_id) REFERENCES centers (center_id)
);
CREATE INDEX IF NOT EXISTS idx_instances_batch ON instances (batch_id);
CREATE INDEX IF NOT EXISTS idx_instances_lookup
    ON instances (center_id, original_sop_uid);

-- Every reference encountered while rewriting, including not-yet-resolved ones.
CREATE TABLE IF NOT EXISTS instance_references (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    center_id                TEXT NOT NULL,
    source_instance_id       INTEGER NOT NULL,
    original_referenced_uid  TEXT NOT NULL,
    new_referenced_uid       TEXT NOT NULL,
    resolved                 INTEGER NOT NULL DEFAULT 0,
    created_at               TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE (source_instance_id, original_referenced_uid),
    FOREIGN KEY (source_instance_id) REFERENCES instances (id)
);
CREATE INDEX IF NOT EXISTS idx_references_pending
    ON instance_references (center_id, resolved);

CREATE TABLE IF NOT EXISTS batches (
    batch_id     TEXT PRIMARY KEY,
    center_id    TEXT NOT NULL,
    status       TEXT NOT NULL CHECK (status IN ('committed', 'rejected')),
    file_count   INTEGER NOT NULL,
    reason       TEXT,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    FOREIGN KEY (center_id) REFERENCES centers (center_id)
);
CREATE INDEX IF NOT EXISTS idx_batches_center ON batches (center_id);

-- One row per center inspection run. Runs execute synchronously; at most one
-- run per center may be in 'running' state at any time.
CREATE TABLE IF NOT EXISTS inspection_runs (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id            TEXT NOT NULL UNIQUE,
    center_id         TEXT NOT NULL,
    status            TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed')),
    total_instances   INTEGER NOT NULL DEFAULT 0,
    ok_count          INTEGER NOT NULL DEFAULT 0,
    no_fingerprint_count INTEGER NOT NULL DEFAULT 0,
    missing_count     INTEGER NOT NULL DEFAULT 0,
    digest_mismatch_count INTEGER NOT NULL DEFAULT 0,
    quarantined_count INTEGER NOT NULL DEFAULT 0,
    repair_count      INTEGER NOT NULL DEFAULT 0,
    reason            TEXT,
    started_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    finished_at       TEXT,
    FOREIGN KEY (center_id) REFERENCES centers (center_id)
);
CREATE INDEX IF NOT EXISTS idx_inspection_runs_center
    ON inspection_runs (center_id, id DESC);

-- Per-instance outcome of an inspection run. The state_version captured here
-- records the exact instance generation that was observed.
CREATE TABLE IF NOT EXISTS inspection_findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          TEXT NOT NULL,
    instance_id     INTEGER NOT NULL,
    center_id       TEXT NOT NULL,
    check_status    TEXT NOT NULL CHECK (check_status IN (
                        'ok', 'no_fingerprint', 'missing', 'digest_mismatch',
                        'quarantine_failed', 'skipped_repaired'
                    )),
    expected_sha256 TEXT,
    actual_sha256   TEXT,
    detail          TEXT,
    state_version   INTEGER NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE (run_id, instance_id),
    FOREIGN KEY (run_id) REFERENCES inspection_runs (run_id),
    FOREIGN KEY (instance_id) REFERENCES instances (id)
);
CREATE INDEX IF NOT EXISTS idx_findings_run ON inspection_findings (run_id);
CREATE INDEX IF NOT EXISTS idx_findings_instance
    ON inspection_findings (instance_id);
"""

# Columns added after the first release. Each entry is
# (table, column, DDL fragment). Applied once, guarded by PRAGMA table_info,
# so databases created by older images migrate in place.
ADDED_COLUMNS: list[tuple[str, str, str]] = [
    (
        "instances",
        "stored_sha256",
        "TEXT",  # SHA-256 of the rewritten file on disk; NULL = legacy object
    ),
    (
        "instances",
        "quarantine_state",
        "TEXT NOT NULL DEFAULT 'active' "
        "CHECK (quarantine_state IN ('active', 'quarantined'))",
    ),
    (
        "instances",
        "quarantine_path",
        "TEXT",  # location inside the quarantine area while isolated
    ),
    (
        "instances",
        "quarantine_reason",
        "TEXT",  # 'missing' | 'digest_mismatch'
    ),
    (
        "instances",
        "quarantined_at",
        "TEXT",
    ),
    (
        "instances",
        "state_version",
        "INTEGER NOT NULL DEFAULT 0",  # bumped on every quarantine / repair
    ),
    (
        "instances",
        "fingerprint_established_at",
        "TEXT",  # when a legacy object first got a stored_sha256
    ),
]


def get_connection() -> sqlite3.Connection:
    """Open a read/write SQLite connection with safe pragmas and row access."""
    config.ensure_dirs()
    conn = sqlite3.connect(
        config.DB_PATH,
        timeout=BUSY_TIMEOUT_MS / 1000.0,
        isolation_level=None,  # transactions managed explicitly below
        check_same_thread=False,
    )
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    return conn


def get_readonly_connection() -> sqlite3.Connection:
    """Open a connection that can only read.

    Inspection file checks use this so hashing the objects on disk never opens
    a writer transaction and never blocks (or gets blocked by) ingestion.
    """
    config.ensure_dirs()
    uri = f"file:{config.DB_PATH}?mode=ro"
    conn = sqlite3.connect(
        uri,
        uri=True,
        timeout=BUSY_TIMEOUT_MS / 1000.0,
        isolation_level=None,
        check_same_thread=False,
    )
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
    conn.execute("PRAGMA query_only = ON")
    return conn


def init_db() -> None:
    conn = get_connection()
    try:
        conn.executescript(SCHEMA)
        _migrate_columns(conn)
    finally:
        conn.close()


def _migrate_columns(conn: sqlite3.Connection) -> None:
    """Apply additive ALTER TABLE migrations for pre-existing databases."""
    columns_by_table: dict[str, set[str]] = {}
    for table, column, ddl in ADDED_COLUMNS:
        if table not in columns_by_table:
            columns_by_table[table] = {
                row["name"] for row in conn.execute(f"PRAGMA table_info({table})")
            }
        if column not in columns_by_table[table]:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")
            columns_by_table[table].add(column)


@contextmanager
def immediate_transaction() -> Iterator[sqlite3.Connection]:
    """Acquire a writer lock up front; commit on success, roll back on error."""
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        yield conn
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()
