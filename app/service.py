"""Batch ingestion service: atomicity, idempotency, repair and fingerprints.

Ingestion remains one atomic batch. In addition to the original idempotent
retransmit behavior, the same upload entry point handles two integrity
workflows:

* **repair** - an instance previously quarantined by an inspection (missing
  file or digest mismatch) can be re-uploaded from the center's original
  object. Same center + same original SOP UID + same *original* SHA-256 is the
  eligibility rule. The instance id, every UID mapping and all references stay
  unchanged; only the on-disk rewritten file and its fingerprint are restored.
* **fingerprint establishment** - legacy objects (ingested before fingerprinting
  existed, ``stored_sha256 IS NULL``) can receive a trusted fingerprint through
  the exact same re-upload, again without changing identity rows.

Nothing is observable until the whole batch commits: files are staged as
unique ``.part`` files, verified (hash, DICOM re-read) and atomically renamed
inside the writer transaction; a rollback or a killed process leaves no
partial object downloadable and never releases a quarantine.
"""
from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass
from pathlib import Path

from . import config, dicom_io, storage
from .config import MAX_FILES_PER_BATCH
from .db import immediate_transaction
from .uid import remap_uid


class IngestionError(Exception):
    """Rejection of a whole batch; nothing is persisted or left to download.

    ``http_status`` distinguishes malformed input (422) from conflicts with
    already-stored state such as byte mismatches (409).
    """

    def __init__(self, message: str, http_status: int = 409) -> None:
        super().__init__(message)
        self.http_status = http_status


@dataclass
class UploadedFile:
    filename: str
    content: bytes


def _upsert_mapping(
    conn: sqlite3.Connection,
    center_id: str,
    original_uid: str,
    kind: str,
    batch_id: str,
) -> str:
    new_uid = remap_uid(center_id, original_uid)
    # The mapping value is deterministic, so an existing row is always equal.
    conn.execute(
        """
        INSERT INTO uid_mappings
            (center_id, original_uid, new_uid, uid_kind, first_seen_batch)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT (center_id, original_uid) DO NOTHING
        """,
        (center_id, original_uid, new_uid, kind, batch_id),
    )
    return new_uid


def _validate_center_id(center_id: str) -> str:
    center_id = (center_id or "").strip()
    if not center_id:
        raise IngestionError("center_id is required", http_status=422)
    if len(center_id) > 64 or any(ch not in
                                  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
                                  for ch in center_id):
        raise IngestionError(
            "center_id must be 1-64 chars of letters, digits, '_' or '-'",
            http_status=422,
        )
    return center_id


def ingest_batch(center_id: str, files: list[UploadedFile]) -> dict:
    """Ingest a batch atomically.

    Returns a summary dict on success; raises :class:`IngestionError` when the
    batch is rejected (in which case no row and no file is persisted).
    """

    center_id = _validate_center_id(center_id)
    if not files:
        raise IngestionError("at least one DICOM file is required", http_status=422)
    if len(files) > MAX_FILES_PER_BATCH:
        raise IngestionError(
            f"a batch may contain at most {MAX_FILES_PER_BATCH} files, "
            f"got {len(files)}",
            http_status=422,
        )

    batch_id = uuid.uuid4().hex

    # ---- Phase 1: parse and validate every file outside the DB transaction.
    parsed_objects: list[dicom_io.ParsedObject] = []
    seen_sop_in_batch: set[str] = set()
    for uploaded in files:
        try:
            parsed = dicom_io.parse_and_validate(uploaded.content)
        except dicom_io.DicomValidationError as exc:
            raise IngestionError(
                f"file {uploaded.filename!r} rejected: {exc}", http_status=422
            ) from exc
        if parsed.original_sop_uid in seen_sop_in_batch:
            raise IngestionError(
                f"file {uploaded.filename!r} duplicates SOP UID "
                f"{parsed.original_sop_uid} within the same batch",
                http_status=422,
            )
        seen_sop_in_batch.add(parsed.original_sop_uid)
        parsed_objects.append(parsed)

    config.ensure_dirs()
    prepared: list[dict] = []
    # Cleanup bookkeeping for failure paths.
    staged_parts: list = []          # temp files to unlink on any failure
    promoted: list[dict] = []        # replacements made (for rollback restore)
    quarantine_cleanups: list = []   # quarantine copies to delete post-commit

    # ---- Phase 2: one writer transaction covers the whole batch.
    try:
        with immediate_transaction() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO centers (center_id) VALUES (?)",
                (center_id,),
            )

            # Idempotent retransmit / repair / byte-conflict pre-check.
            for parsed in parsed_objects:
                row = conn.execute(
                    """
                    SELECT id, sha256, new_sop_uid, stored_path,
                           stored_sha256, quarantine_state, state_version
                    FROM instances
                    WHERE center_id = ? AND original_sop_uid = ?
                    """,
                    (center_id, parsed.original_sop_uid),
                ).fetchone()
                if row is not None and row["sha256"] != parsed.sha256:
                    # A different original object for the same SOP can never
                    # repair anything and would break the identity contract.
                    raise IngestionError(
                        f"SOP UID {parsed.original_sop_uid} already exists for "
                        f"center {center_id} with different bytes (original "
                        f"SHA-256 mismatch); the whole batch is rejected"
                    )

            for parsed in parsed_objects:
                existing = conn.execute(
                    """
                    SELECT id, new_sop_uid, stored_path, stored_sha256,
                           quarantine_state, quarantine_path, state_version
                    FROM instances
                    WHERE center_id = ? AND original_sop_uid = ? AND sha256 = ?
                    """,
                    (
                        center_id,
                        parsed.original_sop_uid,
                        parsed.sha256,
                    ),
                ).fetchone()

                # Rewrite all UIDs through the deterministic center mapping.
                def map_fn(original_uid: str, kind: str) -> str:
                    return _upsert_mapping(
                        conn, center_id, original_uid, kind, batch_id
                    )

                dicom_io.rewrite_uids(parsed.ds, map_fn)
                encoded = dicom_io.encode_and_verify(parsed)
                encoded_sha256 = storage.sha256_bytes(encoded)
                new_sop_uid = remap_uid(center_id, parsed.original_sop_uid)
                new_study_uid = remap_uid(center_id, parsed.original_study_uid)
                new_series_uid = remap_uid(center_id, parsed.original_series_uid)

                if existing is not None:
                    instance_id = existing["id"]
                    stored_path = existing["stored_path"]
                    live_path = config.STORAGE_DIR / existing["stored_path"]
                    live_file_missing = not live_path.is_file()
                    live_file_changed = False
                    if (
                        not live_file_missing
                        and existing["stored_sha256"] is not None
                    ):
                        # Cheap, read-only integrity probe: if the live file no
                        # longer matches its own fingerprint, an inspection has
                        # either already isolated it or is about to.
                        live_file_changed = (
                            storage.sha256_file(live_path)
                            != existing["stored_sha256"]
                        )
                    if existing["quarantine_state"] == "quarantined":
                        # Row already isolated by a committed inspection.
                        action = "repair"
                    elif live_file_missing and existing["stored_sha256"] is not None:
                        # An inspection may be in the middle of isolating this
                        # object (file moved/missing, row not yet updated). The
                        # center-original re-upload is a repair and the
                        # compare-and-swap below makes the two flows resolve
                        # safely.
                        action = "repair"
                    elif live_file_changed:
                        # Corrupt bytes still sitting in the live tree: treat
                        # the center-original re-upload as a repair rather than
                        # silently "reusing" untrusted bytes.
                        action = "repair"
                    elif existing["stored_sha256"] is None:
                        # Healthy legacy object: establish the fingerprint only.
                        action = "fingerprint"
                    else:
                        action = "reuse"
                    reused = action == "reuse"
                else:
                    instance_id = None
                    stored_path = ""
                    action = "insert"
                    reused = False

                # Record reference rows even for reused/repaired objects: the
                # same bytes may be retransmitted alongside new references.
                for original_ref in dict.fromkeys(parsed.referenced_sop_uids):
                    new_ref = _upsert_mapping(
                        conn, center_id, original_ref, "sop", batch_id
                    )
                    if instance_id is not None:
                        conn.execute(
                            """
                            INSERT OR IGNORE INTO instance_references
                                (center_id, source_instance_id,
                                 original_referenced_uid, new_referenced_uid)
                            VALUES (?, ?, ?, ?)
                            """,
                            (center_id, instance_id, original_ref, new_ref),
                        )

                prepared.append(
                    {
                        "parsed": parsed,
                        "encoded": encoded,
                        "encoded_sha256": encoded_sha256,
                        "new_sop_uid": new_sop_uid,
                        "new_study_uid": new_study_uid,
                        "new_series_uid": new_series_uid,
                        "instance_id": instance_id,
                        "stored_path": stored_path,
                        "reused": reused,
                        "action": action,
                        "existing": existing,
                    }
                )

            # Materialize / restore objects only after all DB checks passed.
            for item in prepared:
                action = item["action"]
                if action == "reuse":
                    continue

                parsed = item["parsed"]
                existing = item["existing"]

                if action == "insert":
                    relative = (
                        f"{center_id}/{item['new_sop_uid']}.{parsed.sha256}.dcm"
                    )
                    absolute = config.STORAGE_DIR / relative
                    final_name = absolute.name
                    directory = absolute.parent
                else:
                    # Repair / fingerprint: keep the exact same stored path so
                    # identity, mapping and references are untouched.
                    relative = existing["stored_path"]
                    absolute = config.STORAGE_DIR / relative
                    directory = absolute.parent
                    final_name = absolute.name

                temp_path, final_path = storage.atomic_write(
                    directory, final_name, item["encoded"]
                )
                staged_parts.append(temp_path)

                # The fingerprint we are about to trust must describe the exact
                # bytes staged for this path.
                actual_temp_hash = storage.sha256_file(temp_path)
                if actual_temp_hash != item["encoded_sha256"]:
                    raise IngestionError(
                        "internal error: staged file hash does not match its "
                        "fingerprint; batch aborted"
                    )
                item["temp_path"] = temp_path
                item["final_path"] = final_path

                if action == "insert":
                    # Promote immediately; an IntegrityError below rolls the DB
                    # back and the except handler deletes the orphan file.
                    storage.commit_atomic_write(temp_path, final_path)
                    staged_parts.remove(temp_path)
                    item["stored_path"] = relative
                    cur = conn.execute(
                        """
                        INSERT INTO instances (
                            center_id, batch_id, original_sop_uid, new_sop_uid,
                            original_study_uid, new_study_uid,
                            original_series_uid, new_series_uid, modality,
                            transfer_syntax_uid, sha256, byte_size, stored_path,
                            stored_sha256, quarantine_state, state_version
                        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,'active',0)
                        """,
                        (
                            center_id,
                            batch_id,
                            parsed.original_sop_uid,
                            item["new_sop_uid"],
                            parsed.original_study_uid,
                            item["new_study_uid"],
                            parsed.original_series_uid,
                            item["new_series_uid"],
                            parsed.modality,
                            parsed.transfer_syntax_uid,
                            parsed.sha256,
                            len(item["encoded"]),
                            relative,
                            item["encoded_sha256"],
                        ),
                    )
                    item["instance_id"] = cur.lastrowid

                    for original_ref in dict.fromkeys(parsed.referenced_sop_uids):
                        new_ref = remap_uid(center_id, original_ref)
                        conn.execute(
                            """
                            INSERT OR IGNORE INTO instance_references (
                                center_id, source_instance_id,
                                original_referenced_uid, new_referenced_uid
                            ) VALUES (?, ?, ?, ?)
                            """,
                            (
                                center_id,
                                cur.lastrowid,
                                original_ref,
                                new_ref,
                            ),
                        )
                else:
                    # Repair or fingerprint establishment on an existing row.
                    # Compare-and-swap against the inspected generation so a
                    # stale concurrent flow cannot clobber newer state.
                    established_fingerprint = existing["stored_sha256"] is None
                    cur = conn.execute(
                        """
                        UPDATE instances
                        SET stored_sha256 = ?,
                            byte_size = ?,
                            quarantine_state = 'active',
                            quarantine_path = NULL,
                            quarantine_reason = NULL,
                            quarantined_at = NULL,
                            state_version = state_version + 1,
                            fingerprint_established_at = COALESCE(
                                fingerprint_established_at, ?
                            )
                        WHERE id = ? AND state_version = ?
                        """,
                        (
                            item["encoded_sha256"],
                            len(item["encoded"]),
                            # First fingerprint for a legacy object: stamp now;
                            # subsequent repairs keep the original timestamp.
                            storage.utcnow() if established_fingerprint else None,
                            existing["id"],
                            existing["state_version"],
                        ),
                    )
                    if cur.rowcount != 1:
                        raise IngestionError(
                            f"instance {existing['id']} changed concurrently; "
                            "the whole batch is rejected"
                        )
                    if action == "repair" and existing["quarantine_path"]:
                        quarantine_cleanups.append(
                            config.DATA_DIR / existing["quarantine_path"]
                        )

                    # Move any pre-existing live file aside instead of
                    # overwriting it: if the DB transaction rolls back (or the
                    # process dies before commit) the original file is restored
                    # byte-for-byte and no residual new file is exposed.
                    backup_path: Path | None = None
                    if final_path.exists():
                        backup_path = final_path.with_name(
                            f".{final_path.name}.bak-{uuid.uuid4().hex}"
                        )
                        final_path.replace(backup_path)
                    storage.commit_atomic_write(temp_path, final_path)
                    staged_parts.remove(temp_path)
                    promoted.append(
                        {
                            "final_path": final_path,
                            "backup_path": backup_path,
                        }
                    )

            # SOP mappings carried by ingested objects are now present.
            conn.execute(
                """
                UPDATE uid_mappings SET present = 1
                WHERE center_id = ? AND uid_kind = 'sop' AND original_uid IN (
                    SELECT original_sop_uid FROM instances WHERE center_id = ?
                )
                """,
                (center_id, center_id),
            )
            # Recompute resolution for every reference of this center in one
            # shot; this also resolves references created by earlier batches.
            conn.execute(
                """
                UPDATE instance_references SET resolved = 1
                WHERE center_id = ? AND new_referenced_uid IN (
                    SELECT new_uid FROM uid_mappings
                    WHERE center_id = ? AND present = 1
                )
                """,
                (center_id, center_id),
            )

            reused_count = sum(1 for item in prepared if item["reused"])
            repair_count = sum(1 for item in prepared if item["action"] == "repair")
            fingerprint_count = sum(
                1 for item in prepared if item["action"] == "fingerprint"
            )
            conn.execute(
                """
                INSERT INTO batches
                    (batch_id, center_id, status, file_count, reason)
                VALUES (?, ?, 'committed', ?, NULL)
                """,
                (batch_id, center_id, len(prepared)),
            )
    except IngestionError:
        _rollback_files(staged_parts, promoted)
        raise
    except sqlite3.IntegrityError as exc:
        # The DB transaction rolls back. Remove any object files that were
        # already materialized so no half batch is ever downloadable.
        _rollback_files(staged_parts, promoted)
        raise IngestionError(f"batch conflicted with existing data: {exc}") from exc

    # Post-commit: old bytes kept aside during replacement are now obsolete,
    # and so are the quarantine copies of repaired objects. Deleting after
    # commit means a failure here only leaves extra files on disk; the
    # committed live objects and their fingerprints are unaffected.
    for entry in promoted:
        backup = entry["backup_path"]
        if backup is not None:
            try:
                backup.unlink()
            except FileNotFoundError:
                pass
    for stale in quarantine_cleanups:
        try:
            stale.unlink()
        except FileNotFoundError:
            pass

    return {
        "batch_id": batch_id,
        "center_id": center_id,
        "status": "committed",
        "file_count": len(prepared),
        "reused_count": reused_count,
        "repaired_count": repair_count,
        "fingerprinted_count": fingerprint_count,
        "files": [
            {
                "original_sop_uid": item["parsed"].original_sop_uid,
                "new_sop_uid": item["new_sop_uid"],
                "new_study_uid": item["new_study_uid"],
                "new_series_uid": item["new_series_uid"],
                "modality": item["parsed"].modality,
                "reused": item["reused"],
                "action": item["action"],
            }
            for item in prepared
        ],
    }


def _rollback_files(staged_parts: list, promoted: list[dict]) -> None:
    """Best-effort restoration of everything a rolled-back batch touched."""
    for part in staged_parts:
        try:
            part.unlink()
        except FileNotFoundError:
            pass
    # Repairs/fingerprint writes that were renamed before rollback. Remove the
    # new file and, when one existed, put the pre-batch bytes back so the
    # on-disk state matches the (unchanged) database row exactly.
    for entry in promoted:
        final_path = entry["final_path"]
        backup_path = entry["backup_path"]
        try:
            final_path.unlink()
        except FileNotFoundError:
            pass
        if backup_path is not None:
            try:
                backup_path.replace(final_path)
            except FileNotFoundError:
                pass
