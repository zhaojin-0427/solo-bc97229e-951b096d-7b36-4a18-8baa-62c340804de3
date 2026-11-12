"""Center-scoped integrity inspections and quarantine.

An inspection walks every instance of one center, hashes the rewritten file on
disk and compares it against the fingerprint captured at ingest time
(``instances.stored_sha256``):

* ``ok``               - file present, hash matches the stored fingerprint
* ``no_fingerprint``   - legacy object with no fingerprint; the current file is
                         never promoted to a trusted baseline automatically
* ``missing``          - the stored file has vanished from disk
* ``digest_mismatch``  - the file is present but its hash differs

Missing or mismatched objects are *quarantined*: the live file is atomically
moved out of the storage tree (missing objects only update the row) and the
instance switches to ``quarantine_state = 'quarantined'``, after which
downloads are refused until a same-center original re-upload repairs it.

Concurrency
-----------
* File hashing runs on a **read-only** SQLite connection; it never opens a
  writer transaction and never blocks ingestion.
* One short ``BEGIN IMMEDIATE`` writer transaction per actual quarantine.
* Every quarantine is a compare-and-swap on ``state_version``. A repair bumps
  that version, so a late inspection snapshot taken before the repair cannot
  re-quarantine the already-repaired object.
* A per-center in-process lock rejects overlapping inspection runs.
"""
from __future__ import annotations

import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from . import config, storage
from .db import get_connection, get_readonly_connection, immediate_transaction

# Lifecycle statuses returned to operators.
CHECK_OK = "ok"
CHECK_NO_FINGERPRINT = "no_fingerprint"
CHECK_MISSING = "missing"
CHECK_DIGEST_MISMATCH = "digest_mismatch"
CHECK_QUARANTINE_FAILED = "quarantine_failed"
CHECK_SKIPPED_REPAIRED = "skipped_repaired"

# Instance lifecycle states.
STATE_ACTIVE = "active"
STATE_QUARANTINED = "quarantined"

# At most one running inspection per center, inside this process.
_run_locks: dict[str, threading.Lock] = {}
_run_locks_guard = threading.Lock()

# Test seam: invoked with (instance_id, check_status) after the read-only
# check of a bad object and immediately before it is quarantined. Production
# code leaves this at None. It lets tests interleave a concurrent repair and
# prove the stale inspection cannot re-quarantine the repaired object.
_before_quarantine_hook: Callable[[int, str], None] | None = None


class InspectionError(Exception):
    """Operator-facing inspection error (carries an HTTP status)."""

    def __init__(self, message: str, http_status: int = 409) -> None:
        super().__init__(message)
        self.http_status = http_status


def _center_lock(center_id: str) -> threading.Lock:
    with _run_locks_guard:
        lock = _run_locks.get(center_id)
        if lock is None:
            lock = threading.Lock()
            _run_locks[center_id] = lock
        return lock


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%fZ")


def _check_one_file(row) -> tuple[str, str | None, str | None, str]:
    """Hash one object without touching any writer transaction.

    Returns ``(check_status, expected_sha256, actual_sha256, detail)``.
    """
    expected = row["stored_sha256"]
    path = config.STORAGE_DIR / row["stored_path"]

    if expected is None:
        # Legacy object: explicitly do NOT hash-and-trust. Report whether the
        # file happens to exist, but never treat its bytes as the baseline.
        if path.is_file():
            detail = "legacy object has no stored fingerprint; current file not trusted"
        else:
            detail = "legacy object has no stored fingerprint and its file is missing"
        return CHECK_NO_FINGERPRINT, None, None, detail

    if not path.is_file():
        return (
            CHECK_MISSING,
            expected,
            None,
            f"stored object missing at {row['stored_path']}",
        )

    actual = storage.sha256_file(path)
    if actual != expected:
        return (
            CHECK_DIGEST_MISMATCH,
            expected,
            actual,
            "stored file SHA-256 does not match the ingest-time fingerprint",
        )
    return CHECK_OK, expected, actual, "fingerprint matches"


def _record_finding(
    conn,
    run_id: str,
    instance_id: int,
    center_id: str,
    check_status: str,
    state_version: int,
    detail: str,
    expected: str | None,
    actual: str | None,
) -> None:
    conn.execute(
        """
        INSERT INTO inspection_findings (
            run_id, instance_id, center_id, check_status, expected_sha256,
            actual_sha256, detail, state_version
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            instance_id,
            center_id,
            check_status,
            expected,
            actual,
            detail,
            state_version,
        ),
    )


def _quarantine(
    run_id: str,
    row,
    check_status: str,
    detail: str,
) -> tuple[str, int]:
    """Isolate one object inside a short writer transaction.

    The on-disk rename happens *inside* the ``BEGIN IMMEDIATE`` transaction.
    SQLite allows only one writer at a time, so this strictly orders the
    inspection against any concurrent repair: whichever flow commits first
    wins, and the loser's compare-and-swap on ``state_version`` detects it.

    Returns ``(final_check_status, quarantined_flag)``.
    """
    instance_id = row["id"]
    center_id = row["center_id"]
    baseline_version = row["state_version"]
    live_path = config.STORAGE_DIR / row["stored_path"]
    target = storage.quarantine_target(center_id, run_id, instance_id)
    file_existed = live_path.is_file()

    with immediate_transaction() as conn:
        # Re-read the current generation under the writer lock. If a repair
        # already bumped state_version (and restored the file), this snapshot
        # is stale and must not isolate anything.
        latest = conn.execute(
            "SELECT quarantine_state, state_version, stored_sha256 "
            "FROM instances WHERE id = ?",
            (instance_id,),
        ).fetchone()
        if latest is None:
            _record_finding(
                conn, run_id, instance_id, center_id, CHECK_SKIPPED_REPAIRED,
                baseline_version, "instance vanished before quarantine",
                row["stored_sha256"], None,
            )
            return CHECK_SKIPPED_REPAIRED, 0

        if latest["state_version"] != baseline_version or (
            latest["quarantine_state"] != STATE_ACTIVE
        ):
            if latest["quarantine_state"] == STATE_ACTIVE:
                final_status = CHECK_SKIPPED_REPAIRED
                final_detail = (
                    "object was repaired concurrently after this inspection "
                    "snapshot; quarantine skipped"
                )
            else:
                final_status = check_status
                final_detail = detail + " (already quarantined by a concurrent run)"
            _record_finding(
                conn, run_id, instance_id, center_id, final_status,
                latest["state_version"], final_detail,
                row["stored_sha256"], None,
            )
            return (
                final_status,
                1 if final_status in (CHECK_MISSING, CHECK_DIGEST_MISMATCH) else 0,
            )

        move_failed: OSError | None = None
        moved_target: Path | None = None
        if file_existed:
            # Same volume -> atomic directory-entry rename, observable only
            # once this writer transaction is the active one.
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                live_path.replace(target)
                moved_target = target
            except OSError as exc:
                move_failed = exc

        if move_failed is not None:
            _record_finding(
                conn, run_id, instance_id, center_id, CHECK_QUARANTINE_FAILED,
                baseline_version,
                f"could not move object into quarantine: {move_failed}",
                row["stored_sha256"], None,
            )
            return CHECK_QUARANTINE_FAILED, 0

        if moved_target is not None:
            conn.execute(
                """
                UPDATE instances
                SET quarantine_state = 'quarantined',
                    quarantine_path = ?,
                    quarantine_reason = ?,
                    quarantined_at = ?,
                    state_version = state_version + 1
                WHERE id = ? AND quarantine_state = 'active'
                  AND state_version = ?
                """,
                (
                    str(target.relative_to(config.DATA_DIR)),
                    check_status,
                    _utcnow(),
                    instance_id,
                    baseline_version,
                ),
            )
        else:
            conn.execute(
                """
                UPDATE instances
                SET quarantine_state = 'quarantined',
                    quarantine_path = NULL,
                    quarantine_reason = ?,
                    quarantined_at = ?,
                    state_version = state_version + 1
                WHERE id = ? AND quarantine_state = 'active'
                  AND state_version = ?
                """,
                (check_status, _utcnow(), instance_id, baseline_version),
            )

        _record_finding(
            conn, run_id, instance_id, center_id, check_status,
            baseline_version + 1, detail, row["stored_sha256"], None,
        )
    return check_status, 1


def inspect_center(
    center_id: str,
    *,
    before_quarantine: Callable[[int, str], None] | None = None,
) -> dict:
    """Run a full integrity inspection for one center.

    ``before_quarantine(instance_id, check_status)`` is invoked after the
    read-only check, immediately before the object is isolated. Tests use it
    to interleave a repair and prove stale inspections cannot re-quarantine.
    """
    center_id = (center_id or "").strip()
    if not center_id:
        raise InspectionError("center_id is required", http_status=422)
    if len(center_id) > 64 or any(
        ch not in
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
        for ch in center_id
    ):
        raise InspectionError(
            "center_id must be 1-64 chars of letters, digits, '_' or '-'",
            http_status=422,
        )

    hook = before_quarantine if before_quarantine is not None else _before_quarantine_hook

    lock = _center_lock(center_id)
    if not lock.acquire(blocking=False):
        raise InspectionError(
            f"an inspection for center {center_id!r} is already running",
            http_status=409,
        )

    run_id = uuid.uuid4().hex
    try:
        config.ensure_dirs()
        # Create the run row up front (also 404s unknown centers clearly).
        with immediate_transaction() as conn:
            center = conn.execute(
                "SELECT center_id FROM centers WHERE center_id = ?", (center_id,)
            ).fetchone()
            if center is None:
                raise InspectionError(
                    f"unknown center {center_id!r}; nothing has been ingested "
                    "for it yet",
                    http_status=404,
                )
            conn.execute(
                "INSERT INTO inspection_runs (run_id, center_id, status) "
                "VALUES (?, ?, 'running')",
                (run_id, center_id),
            )

        counters = {
            CHECK_OK: 0,
            CHECK_NO_FINGERPRINT: 0,
            CHECK_MISSING: 0,
            CHECK_DIGEST_MISMATCH: 0,
            CHECK_QUARANTINE_FAILED: 0,
            CHECK_SKIPPED_REPAIRED: 0,
        }
        quarantined_count = 0

        # Read-only snapshot: hashing files never takes a writer lock.
        ro_conn = get_readonly_connection()
        try:
            rows = ro_conn.execute(
                """
                SELECT id, center_id, stored_path, stored_sha256,
                       quarantine_state, state_version
                FROM instances
                WHERE center_id = ?
                ORDER BY id
                """,
                (center_id,),
            ).fetchall()
            total = len(rows)

            for row in rows:
                check_status, expected, actual, detail = _check_one_file(row)

                if check_status in (CHECK_MISSING, CHECK_DIGEST_MISMATCH):
                    if hook is not None:
                        hook(row["id"], check_status)
                    final_status, did_quarantine = _quarantine(
                        run_id, row, check_status, detail
                    )
                    counters[final_status] += 1
                    quarantined_count += did_quarantine
                else:
                    counters[check_status] += 1
                    with immediate_transaction() as conn:
                        _record_finding(
                            conn, run_id, row["id"], center_id, check_status,
                            row["state_version"], detail, expected, actual,
                        )
        finally:
            ro_conn.close()

        with immediate_transaction() as conn:
            conn.execute(
                """
                UPDATE inspection_runs
                SET status = 'completed',
                    total_instances = ?,
                    ok_count = ?,
                    no_fingerprint_count = ?,
                    missing_count = ?,
                    digest_mismatch_count = ?,
                    quarantined_count = ?,
                    finished_at = ?
                WHERE run_id = ?
                """,
                (
                    total,
                    counters[CHECK_OK],
                    counters[CHECK_NO_FINGERPRINT],
                    counters[CHECK_MISSING],
                    counters[CHECK_DIGEST_MISMATCH],
                    quarantined_count,
                    _utcnow(),
                    run_id,
                ),
            )
    except InspectionError:
        _fail_run(run_id, "rejected before inspection started")
        raise
    except Exception as exc:
        _fail_run(run_id, f"inspection failed: {exc}")
        raise
    finally:
        lock.release()

    return get_run(run_id)


def _fail_run(run_id: str, reason: str) -> None:
    try:
        with immediate_transaction() as conn:
            conn.execute(
                "UPDATE inspection_runs SET status = 'failed', reason = ?, "
                "finished_at = ? WHERE run_id = ? AND status = 'running'",
                (reason, _utcnow(), run_id),
            )
    except Exception:
        pass


def get_run(run_id: str) -> dict:
    conn = get_connection()
    try:
        run = conn.execute(
            "SELECT * FROM inspection_runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        if run is None:
            raise InspectionError(f"inspection run {run_id!r} not found", 404)
        finding_rows = conn.execute(
            "SELECT instance_id, check_status, detail, expected_sha256, "
            "actual_sha256, state_version "
            "FROM inspection_findings WHERE run_id = ? ORDER BY instance_id",
            (run_id,),
        ).fetchall()
        result = dict(run)
        result["findings"] = [dict(r) for r in finding_rows]
        return result
    finally:
        conn.close()


def list_runs(center_id: str, limit: int, offset: int) -> list[dict]:
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM inspection_runs WHERE center_id = ? "
            "ORDER BY id DESC LIMIT ? OFFSET ?",
            (center_id, limit, offset),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()
