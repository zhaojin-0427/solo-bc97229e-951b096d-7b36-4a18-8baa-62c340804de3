"""HTTP API for multi-center DICOM ingestion and integrity inspection.

Endpoints
---------
POST /api/v1/batches                        upload / retransmit / repair a batch
GET  /api/v1/batches/{batch_id}             batch status and per-file UID mapping
GET  /api/v1/batches                        list batches (filter by center)
GET  /api/v1/instances                      search instances / inspect UID mapping
GET  /api/v1/instances/{id}/download        download the rewritten DICOM object
                                            (refused with 423 while quarantined)
GET  /api/v1/references/pending             reference-first bookkeeping per center
POST /api/v1/inspections/centers/{center}   run a center integrity inspection
GET  /api/v1/inspections/runs/{run_id}      fetch one inspection run with findings
GET  /api/v1/inspections/runs               list inspection runs for a center
GET  /healthz                               liveness probe
GET  /docs                                  interactive Swagger UI
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, File, Form, HTTPException, Query, UploadFile, status
from fastapi.responses import FileResponse
from pydantic import BaseModel

from . import config, storage
from .config import MAX_FILE_BYTES, MAX_FILES_PER_BATCH
from .db import get_connection, init_db
from .inspection import InspectionError, inspect_center, get_run, list_runs
from .service import IngestionError, UploadedFile, ingest_batch


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Create / migrate the schema and clear crash leftovers before traffic.
    init_db()
    storage.sweep_parts()
    yield


app = FastAPI(
    title="Multi-Center DICOM Ingest & Integrity API",
    version="2.0.0",
    lifespan=lifespan,
    description=(
        "Ingests Explicit VR Little Endian DICOM objects from multiple source "
        "centers, deterministically remaps every instance/study/series UID "
        "(including nested references) per center, fingerprints every stored "
        "object with SHA-256, and supports per-center integrity inspections "
        "that quarantine missing/corrupt objects until a same-center original "
        "re-upload repairs them."
    ),
)


# --------------------------------------------------------------------------- #
# Response schemas
# --------------------------------------------------------------------------- #
class FileResult(BaseModel):
    original_sop_uid: str
    new_sop_uid: str
    new_study_uid: str
    new_series_uid: str
    modality: str | None
    reused: bool
    # insert | reuse | repair | fingerprint
    action: str


class BatchResult(BaseModel):
    batch_id: str
    center_id: str
    status: str
    file_count: int
    reused_count: int
    repaired_count: int = 0
    fingerprinted_count: int = 0
    files: list[FileResult]


class BatchSummary(BaseModel):
    batch_id: str
    center_id: str
    status: str
    file_count: int
    reason: str | None
    created_at: str


class InstanceRow(BaseModel):
    id: int
    center_id: str
    batch_id: str
    original_sop_uid: str
    new_sop_uid: str
    original_study_uid: str
    new_study_uid: str
    original_series_uid: str
    new_series_uid: str
    modality: str | None
    transfer_syntax_uid: str
    sha256: str
    byte_size: int
    stored_path: str
    # SHA-256 of the rewritten file on disk; None for legacy objects that have
    # not received a fingerprint yet.
    stored_sha256: str | None
    quarantine_state: str
    quarantine_path: str | None
    quarantine_reason: str | None
    quarantined_at: str | None
    state_version: int
    fingerprint_established_at: str | None
    created_at: str


class PendingReference(BaseModel):
    center_id: str
    original_referenced_uid: str
    new_referenced_uid: str
    source_instance_id: int
    resolved: bool


class InspectionFinding(BaseModel):
    instance_id: int
    check_status: str
    detail: str | None
    expected_sha256: str | None
    actual_sha256: str | None
    state_version: int


class InspectionRunResult(BaseModel):
    run_id: str
    center_id: str
    status: str
    total_instances: int
    ok_count: int
    no_fingerprint_count: int
    missing_count: int
    digest_mismatch_count: int
    quarantined_count: int
    repair_count: int
    reason: str | None
    started_at: str
    finished_at: str | None
    findings: list[InspectionFinding]


class InspectionRunSummary(BaseModel):
    run_id: str
    center_id: str
    status: str
    total_instances: int
    ok_count: int
    no_fingerprint_count: int
    missing_count: int
    digest_mismatch_count: int
    quarantined_count: int
    repair_count: int
    reason: str | None
    started_at: str
    finished_at: str | None


# --------------------------------------------------------------------------- #
# Ingestion / retransmit / repair
# --------------------------------------------------------------------------- #
@app.post(
    "/api/v1/batches",
    response_model=BatchResult,
    status_code=status.HTTP_201_CREATED,
    tags=["batches"],
    summary=(
        "Upload an atomic batch; also the entry point for repair and "
        "fingerprint establishment"
    ),
    description=(
        "Same center + same original SOP UID + identical original SHA-256 "
        "re-uploads are idempotent. If the target instance is quarantined the "
        "upload repairs it (instance id, UID mappings and references do not "
        "change); if it is a legacy object without a stored fingerprint the "
        "upload establishes one. Different original bytes for an existing SOP "
        "UID reject the whole batch with 409."
    ),
)
async def upload_batch(
    center_id: str = Form(
        ..., description="Source center identifier (letters, digits, _ or -)."
    ),
    files: list[UploadFile] = File(
        ...,
        description=(
            f"1-{MAX_FILES_PER_BATCH} DICOM files, Explicit VR Little Endian "
            "(transfer syntax 1.2.840.10008.1.2.1)."
        ),
    ),
) -> BatchResult:
    if len(files) > MAX_FILES_PER_BATCH:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            f"a batch may contain at most {MAX_FILES_PER_BATCH} files",
        )

    payload: list[UploadedFile] = []
    for upload in files:
        content = await upload.read()
        if len(content) > MAX_FILE_BYTES:
            raise HTTPException(
                status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                f"file {upload.filename!r} exceeds {MAX_FILE_BYTES} bytes",
            )
        payload.append(UploadedFile(filename=upload.filename or "unnamed",
                                    content=content))

    try:
        result = ingest_batch(center_id, payload)
    except IngestionError as exc:
        raise HTTPException(exc.http_status, str(exc)) from exc
    return BatchResult(**result)


# --------------------------------------------------------------------------- #
# Queries
# --------------------------------------------------------------------------- #
@app.get(
    "/api/v1/batches/{batch_id}",
    tags=["batches"],
    summary="Fetch a batch with per-file original/new UID mapping",
)
def get_batch(batch_id: str) -> dict:
    conn = get_connection()
    try:
        batch = conn.execute(
            "SELECT * FROM batches WHERE batch_id = ?", (batch_id,)
        ).fetchone()
        if batch is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "batch not found")
        rows = conn.execute(
            "SELECT * FROM instances WHERE batch_id = ? ORDER BY id", (batch_id,)
        ).fetchall()
        return {
            "batch_id": batch["batch_id"],
            "center_id": batch["center_id"],
            "status": batch["status"],
            "file_count": batch["file_count"],
            "reason": batch["reason"],
            "created_at": batch["created_at"],
            "files": [dict(r) for r in rows],
        }
    finally:
        conn.close()


@app.get(
    "/api/v1/batches",
    response_model=list[BatchSummary],
    tags=["batches"],
    summary="List batches, optionally filtered by center",
)
def list_batches(
    center_id: str | None = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> list[BatchSummary]:
    conn = get_connection()
    try:
        cols = "batch_id, center_id, status, file_count, reason, created_at"
        if center_id:
            rows = conn.execute(
                f"SELECT {cols} FROM batches WHERE center_id = ? "
                "ORDER BY created_at DESC, batch_id DESC LIMIT ? OFFSET ?",
                (center_id, limit, offset),
            ).fetchall()
        else:
            rows = conn.execute(
                f"SELECT {cols} FROM batches "
                "ORDER BY created_at DESC, batch_id DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [BatchSummary(**dict(r)) for r in rows]
    finally:
        conn.close()


@app.get(
    "/api/v1/instances",
    response_model=list[InstanceRow],
    tags=["instances"],
    summary="Search instances and inspect their UID mappings / integrity state",
)
def list_instances(
    center_id: str | None = Query(None),
    original_sop_uid: str | None = Query(
        None, description="Original SOP UID as supplied by the source center."
    ),
    new_sop_uid: str | None = Query(None),
    quarantine_state: str | None = Query(
        None,
        description="Filter by integrity lifecycle state: active | quarantined.",
    ),
    limit: int = Query(100, ge=1, le=500),
) -> list[InstanceRow]:
    if quarantine_state not in (None, "active", "quarantined"):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "quarantine_state must be one of: active, quarantined",
        )
    clauses, params = [], []
    if center_id:
        clauses.append("center_id = ?")
        params.append(center_id)
    if original_sop_uid:
        clauses.append("original_sop_uid = ?")
        params.append(original_sop_uid)
    if new_sop_uid:
        clauses.append("new_sop_uid = ?")
        params.append(new_sop_uid)
    if quarantine_state:
        clauses.append("quarantine_state = ?")
        params.append(quarantine_state)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.extend([limit])
    conn = get_connection()
    try:
        rows = conn.execute(
            f"SELECT * FROM instances {where} ORDER BY id DESC LIMIT ?", params
        ).fetchall()
        return [InstanceRow(**dict(r)) for r in rows]
    finally:
        conn.close()


@app.get(
    "/api/v1/instances/{instance_id}/download",
    tags=["instances"],
    summary="Download the rewritten DICOM object (refused while quarantined)",
    responses={
        200: {"description": "The stored rewritten DICOM object."},
        404: {"description": "Instance does not exist."},
        423: {
            "description": (
                "Locked: the instance is quarantined after a failed integrity "
                "check and must be repaired by re-uploading the center original."
            ),
        },
        500: {"description": "Storage/database divergence (missing active file)."},
    },
)
def download_instance(instance_id: int) -> FileResponse:
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT stored_path, new_sop_uid, transfer_syntax_uid, "
            "quarantine_state, quarantine_reason FROM instances WHERE id = ?",
            (instance_id,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "instance not found")

    if row["quarantine_state"] == "quarantined":
        # Download must be refused once isolation succeeded, regardless of
        # whether a file still happens to be reachable on disk.
        raise HTTPException(
            status.HTTP_423_LOCKED,
            (
                f"instance {instance_id} is quarantined"
                + (f" ({row['quarantine_reason']})" if row["quarantine_reason"] else "")
                + "; re-upload the center original to repair it"
            ),
        )

    path = config.STORAGE_DIR / row["stored_path"]
    if not path.is_file():
        # Storage and DB must never diverge; the next inspection will isolate
        # the row. Never hand back a partial file.
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "stored object missing; contact the platform operator",
        )
    return FileResponse(
        path,
        media_type="application/dicom",
        filename=f"{row['new_sop_uid']}.dcm",
        headers={
            "X-New-SOP-Instance-UID": row["new_sop_uid"],
            "X-Transfer-Syntax-UID": row["transfer_syntax_uid"],
        },
    )


@app.get(
    "/api/v1/references/pending",
    response_model=list[PendingReference],
    tags=["references"],
    summary="List references whose target image has not arrived yet",
)
def pending_references(
    center_id: str = Query(..., description="Center scope; references never cross centers."),
    resolved: bool | None = Query(None),
) -> list[PendingReference]:
    conn = get_connection()
    try:
        sql = (
            "SELECT center_id, original_referenced_uid, new_referenced_uid, "
            "source_instance_id, resolved FROM instance_references WHERE center_id = ?"
        )
        params: list = [center_id]
        if resolved is not None:
            sql += " AND resolved = ?"
            params.append(1 if resolved else 0)
        rows = conn.execute(sql, params).fetchall()
        return [PendingReference(**dict(r)) for r in rows]
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Integrity inspection
# --------------------------------------------------------------------------- #
@app.post(
    "/api/v1/inspections/centers/{center_id}",
    response_model=InspectionRunResult,
    status_code=status.HTTP_200_OK,
    tags=["inspection"],
    summary="Run an integrity inspection of every object of one center",
    description=(
        "Hashes each rewritten object on disk against its ingest-time SHA-256 "
        "fingerprint using read-only database access. Missing or mismatched "
        "objects are quarantined (their files are moved out of the live "
        "storage tree) and downloads are then refused. Legacy objects without "
        "a fingerprint are reported as `no_fingerprint` and never trusted from "
        "the current file. Overlapping inspections of the same center are "
        "rejected with 409."
    ),
)
def run_inspection(center_id: str) -> InspectionRunResult:
    try:
        result = inspect_center(center_id)
    except InspectionError as exc:
        raise HTTPException(exc.http_status, str(exc)) from exc
    return InspectionRunResult(**result)


@app.get(
    "/api/v1/inspections/runs/{run_id}",
    response_model=InspectionRunResult,
    tags=["inspection"],
    summary="Fetch one inspection run including per-instance findings",
)
def fetch_inspection_run(run_id: str) -> InspectionRunResult:
    try:
        result = get_run(run_id)
    except InspectionError as exc:
        raise HTTPException(exc.http_status, str(exc)) from exc
    return InspectionRunResult(**result)


@app.get(
    "/api/v1/inspections/runs",
    response_model=list[InspectionRunSummary],
    tags=["inspection"],
    summary="List inspection runs of a center, newest first",
)
def fetch_inspection_runs(
    center_id: str = Query(..., description="Center scope."),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> list[InspectionRunSummary]:
    rows = list_runs(center_id, limit, offset)
    return [InspectionRunSummary(**r) for r in rows]


@app.get("/healthz", tags=["system"], summary="Liveness/readiness probe")
def healthz() -> dict:
    conn = get_connection()
    try:
        conn.execute("SELECT 1")
    finally:
        conn.close()
    return {"status": "ok"}
