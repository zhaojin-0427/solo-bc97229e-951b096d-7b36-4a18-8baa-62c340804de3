"""Integrity inspection, quarantine and repair requirement tests."""
from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

import pytest

from app import config, inspection
from app.db import get_readonly_connection

from conftest import upload


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _ingest_one(client, center: str, image: Path) -> dict:
    resp = upload(client, center, [image])
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["files"][0]["action"] == "insert"
    return body


def _instance(client, center: str) -> dict:
    rows = client.get(
        "/api/v1/instances", params={"center_id": center}
    ).json()
    assert len(rows) == 1
    return rows[0]


def _stored_file(client, center: str) -> Path:
    inst = _instance(client, center)
    return config.STORAGE_DIR / inst["stored_path"]


def _inspect(client, center: str):
    resp = client.post(f"/api/v1/inspections/centers/{center}")
    assert resp.status_code == 200, resp.text
    return resp.json()


# --------------------------------------------------------------------------- #
# Fingerprints
# --------------------------------------------------------------------------- #
def test_new_ingest_stores_rewritten_file_fingerprint(client, samples_dir):
    image = samples_dir / "reference_first" / "image_001.dcm"
    _ingest_one(client, "fp-center", image)

    inst = _instance(client, "fp-center")
    assert inst["stored_sha256"] is not None
    assert len(inst["stored_sha256"]) == 64
    # Fingerprint is over the *rewritten* stored file, not the uploaded bytes.
    import hashlib

    stored = _stored_file(client, "fp-center")
    assert hashlib.sha256(stored.read_bytes()).hexdigest() == inst["stored_sha256"]
    # And it differs from the original-upload sha256 (UIDs were rewritten).
    assert inst["stored_sha256"] != inst["sha256"]
    assert inst["quarantine_state"] == "active"
    assert inst["state_version"] == 0


def test_healthy_center_inspection_reports_ok(client, samples_dir):
    image = samples_dir / "reference_first" / "image_001.dcm"
    _ingest_one(client, "ok-center", image)

    run = _inspect(client, "ok-center")
    assert run["status"] == "completed"
    assert run["total_instances"] == 1
    assert run["ok_count"] == 1
    assert run["quarantined_count"] == 0
    finding = run["findings"][0]
    assert finding["instance_id"] == _instance(client, "ok-center")["id"]
    assert finding["check_status"] == "ok"
    assert finding["expected_sha256"] == finding["actual_sha256"]


def test_legacy_object_is_no_fingerprint_and_current_file_not_trusted(
    client, samples_dir
):
    image = samples_dir / "reference_first" / "image_001.dcm"
    _ingest_one(client, "legacy-center", image)

    # Simulate a row written by the pre-fingerprint release.
    db_path = config.DB_PATH
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE instances SET stored_sha256 = NULL WHERE center_id = ?",
            ("legacy-center",),
        )

    run = _inspect(client, "legacy-center")
    assert run["no_fingerprint_count"] == 1
    finding = run["findings"][0]
    assert finding["check_status"] == "no_fingerprint"
    assert finding["expected_sha256"] is None
    assert finding["actual_sha256"] is None
    # The file is still active and downloadable; nothing was quarantined.
    inst = _instance(client, "legacy-center")
    assert inst["quarantine_state"] == "active"
    dl = client.get(f"/api/v1/instances/{inst['id']}/download")
    assert dl.status_code == 200


def test_legacy_object_corrupt_bytes_still_no_fingerprint_not_baseline(
    client, samples_dir
):
    image = samples_dir / "reference_first" / "image_001.dcm"
    _ingest_one(client, "legacy-corrupt", image)
    stored = _stored_file(client, "legacy-corrupt")
    with sqlite3.connect(config.DB_PATH) as conn:
        conn.execute(
            "UPDATE instances SET stored_sha256 = NULL WHERE center_id = ?",
            ("legacy-corrupt",)
        )
    # Tamper with the file on disk. Without a fingerprint this cannot be
    # proven corrupt, so it must remain no_fingerprint rather than trusted.
    raw = bytearray(stored.read_bytes())
    raw[200] ^= 0xFF
    stored.write_bytes(bytes(raw))

    run = _inspect(client, "legacy-corrupt")
    assert run["findings"][0]["check_status"] == "no_fingerprint"
    assert run["quarantined_count"] == 0


# --------------------------------------------------------------------------- #
# Missing / corrupt -> quarantine -> download refusal
# --------------------------------------------------------------------------- #
def test_missing_file_is_quarantined_and_download_refused(client, samples_dir):
    image = samples_dir / "reference_first" / "image_001.dcm"
    _ingest_one(client, "missing-center", image)
    inst = _instance(client, "missing-center")
    stored = _stored_file(client, "missing-center")
    stored.unlink()
    assert not stored.exists()

    run = _inspect(client, "missing-center")
    assert run["missing_count"] == 1
    assert run["quarantined_count"] == 1
    assert run["findings"][0]["check_status"] == "missing"

    inst = _instance(client, "missing-center")
    assert inst["quarantine_state"] == "quarantined"
    assert inst["quarantine_reason"] == "missing"
    assert inst["state_version"] == 1

    dl = client.get(f"/api/v1/instances/{inst['id']}/download")
    assert dl.status_code == 423
    assert "quarantined" in dl.text.lower()


def test_digest_mismatch_moves_file_to_quarantine_and_refuses_download(
    client, samples_dir
):
    image = samples_dir / "reference_first" / "image_001.dcm"
    _ingest_one(client, "corrupt-center", image)
    inst = _instance(client, "corrupt-center")
    stored = _stored_file(client, "corrupt-center")

    raw = bytearray(stored.read_bytes())
    raw[128] ^= 0x01
    stored.write_bytes(bytes(raw))

    run = _inspect(client, "corrupt-center")
    assert run["digest_mismatch_count"] == 1
    assert run["quarantined_count"] == 1
    assert run["findings"][0]["check_status"] == "digest_mismatch"

    # The corrupt file was physically moved out of the live storage tree.
    assert not stored.exists()
    quarantine_files = list(config.QUARANTINE_DIR.rglob("*.dcm"))
    assert len(quarantine_files) == 1

    inst = _instance(client, "corrupt-center")
    assert inst["quarantine_state"] == "quarantined"
    assert inst["quarantine_reason"] == "digest_mismatch"
    dl = client.get(f"/api/v1/instances/{inst['id']}/download")
    assert dl.status_code == 423


def test_quarantined_filter_lists_only_isolated_instances(client, samples_dir):
    image = samples_dir / "reference_first" / "image_001.dcm"
    _ingest_one(client, "filter-center", image)
    _stored_file(client, "filter-center").unlink()
    _inspect(client, "filter-center")

    q = client.get(
        "/api/v1/instances",
        params={"center_id": "filter-center", "quarantine_state": "quarantined"},
    ).json()
    assert len(q) == 1
    a = client.get(
        "/api/v1/instances",
        params={"center_id": "filter-center", "quarantine_state": "active"},
    ).json()
    assert a == []


# --------------------------------------------------------------------------- #
# Repair via the original upload entry point
# --------------------------------------------------------------------------- #
def test_repair_missing_object_restores_identity_and_clears_quarantine(
    client, samples_dir
):
    image = samples_dir / "reference_first" / "image_001.dcm"
    body = _ingest_one(client, "repair-center", image)
    original_instance = _instance(client, "repair-center")
    instance_id = original_instance["id"]
    new_sop_uid = original_instance["new_sop_uid"]
    stored = _stored_file(client, "repair-center")
    stored.unlink()
    _inspect(client, "repair-center")
    assert _instance(client, "repair-center")["quarantine_state"] == "quarantined"

    # Re-upload the center original through the SAME batch endpoint.
    repair = upload(client, "repair-center", [image])
    assert repair.status_code == 201, repair.text
    rbody = repair.json()
    assert rbody["files"][0]["action"] == "repair"
    assert rbody["repaired_count"] == 1

    repaired = _instance(client, "repair-center")
    # Identity, UID mapping and references are unchanged.
    assert repaired["id"] == instance_id
    assert repaired["new_sop_uid"] == new_sop_uid
    assert repaired["quarantine_state"] == "active"
    assert repaired["quarantine_reason"] is None
    assert repaired["state_version"] == 2
    # Fingerprint restored and matches the new file.
    import hashlib

    assert repaired["stored_sha256"] == hashlib.sha256(
        stored.read_bytes()
    ).hexdigest()

    # Download works again and returns the fully rewritten object.
    dl = client.get(f"/api/v1/instances/{instance_id}/download")
    assert dl.status_code == 200
    assert dl.headers["X-New-SOP-Instance-UID"] == new_sop_uid

    # Only one instance row exists; no duplicate was created by the repair.
    rows = client.get(
        "/api/v1/instances", params={"center_id": "repair-center"}
    ).json()
    assert len(rows) == 1
    # Quarantine copy was cleaned up.
    assert list(config.QUARANTINE_DIR.rglob("*.dcm")) == []
    # Original batch remains queryable and still points at the same instance.
    batch = client.get(f"/api/v1/batches/{body['batch_id']}").json()
    assert batch["files"][0]["id"] == instance_id


def test_repair_of_digest_mismatch_replaces_file_and_passes_reinspection(
    client, samples_dir
):
    image = samples_dir / "reference_first" / "image_001.dcm"
    _ingest_one(client, "repair-corrupt", image)
    stored = _stored_file(client, "repair-corrupt")
    raw = bytearray(stored.read_bytes())
    raw[128] ^= 0x01
    stored.write_bytes(bytes(raw))
    _inspect(client, "repair-corrupt")
    assert _instance(client, "repair-corrupt")["quarantine_state"] == "quarantined"

    resp = upload(client, "repair-corrupt", [image])
    assert resp.status_code == 201
    assert resp.json()["files"][0]["action"] == "repair"

    # A follow-up whole-center inspection must now pass cleanly.
    run = _inspect(client, "repair-corrupt")
    assert run["ok_count"] == 1
    assert run["quarantined_count"] == 0
    assert run["findings"][0]["check_status"] == "ok"


def test_legacy_object_gets_fingerprint_via_reupload_without_new_row(
    client, samples_dir
):
    image = samples_dir / "reference_first" / "image_001.dcm"
    _ingest_one(client, "fp-repair", image)
    inst_before = _instance(client, "fp-repair")
    with sqlite3.connect(config.DB_PATH) as conn:
        conn.execute(
            "UPDATE instances SET stored_sha256 = NULL WHERE center_id = ?",
            ("fp-repair",),
        )

    resp = upload(client, "fp-repair", [image])
    assert resp.status_code == 201
    body = resp.json()
    assert body["files"][0]["action"] == "fingerprint"
    assert body["fingerprinted_count"] == 1
    assert body["repaired_count"] == 0

    inst_after = _instance(client, "fp-repair")
    assert inst_after["id"] == inst_before["id"]
    assert inst_after["stored_sha256"] is not None
    assert inst_after["quarantine_state"] == "active"

    run = _inspect(client, "fp-repair")
    assert run["ok_count"] == 1


def test_repair_with_different_original_bytes_is_rejected(client, samples_dir, tmp_path):
    image = samples_dir / "reference_first" / "image_001.dcm"
    _ingest_one(client, "repair-deny", image)
    _stored_file(client, "repair-deny").unlink()
    _inspect(client, "repair-deny")

    mutated = tmp_path / "mutated.dcm"
    raw = bytearray(image.read_bytes())
    raw[-1] = (raw[-1] + 1) % 256
    mutated.write_bytes(bytes(raw))

    resp = upload(client, "repair-deny", [mutated])
    assert resp.status_code == 409
    assert "different bytes" in resp.text
    # Still quarantined; still refused.
    inst = _instance(client, "repair-deny")
    assert inst["quarantine_state"] == "quarantined"
    dl = client.get(f"/api/v1/instances/{inst['id']}/download")
    assert dl.status_code == 423


def test_identical_retransmit_after_repair_is_reused(client, samples_dir):
    image = samples_dir / "reference_first" / "image_001.dcm"
    _ingest_one(client, "reuse-after", image)
    _stored_file(client, "reuse-after").unlink()
    _inspect(client, "reuse-after")
    upload(client, "reuse-after", [image])  # repair

    again = upload(client, "reuse-after", [image])
    assert again.status_code == 201
    body = again.json()
    assert body["files"][0]["action"] == "reuse"
    assert body["reused_count"] == 1
    assert len(client.get(
        "/api/v1/instances", params={"center_id": "reuse-after"}
    ).json()) == 1


# --------------------------------------------------------------------------- #
# No partial files / atomicity
# --------------------------------------------------------------------------- #
def test_failed_repair_batch_leaves_no_partial_and_keeps_quarantine(
    client, samples_dir, tmp_path
):
    image = samples_dir / "reference_first" / "image_001.dcm"
    _ingest_one(client, "atomic-center", image)
    _stored_file(client, "atomic-center").unlink()
    _inspect(client, "atomic-center")

    # Repair image is valid, but the second file of the batch is invalid ->
    # the whole batch must fail and the repair must not take effect.
    bad = tmp_path / "bad.dcm"
    bad.write_bytes(b"not dicom at all\n")
    resp = upload(client, "atomic-center", [image, bad])
    assert resp.status_code == 422

    inst = _instance(client, "atomic-center")
    assert inst["quarantine_state"] == "quarantined"
    assert not list(config.STORAGE_DIR.rglob("*.part"))
    assert not list(config.STORAGE_DIR.rglob("*.bak-*"))
    # No live object got exposed.
    assert not _stored_file(client, "atomic-center").exists()


# --------------------------------------------------------------------------- #
# Concurrency: late stale inspection vs. repair
# --------------------------------------------------------------------------- #
def test_late_inspection_cannot_re_quarantine_repaired_object(
    client, samples_dir
):
    image = samples_dir / "reference_first" / "image_001.dcm"
    _ingest_one(client, "race-center", image)
    inst = _instance(client, "race-center")
    stored = _stored_file(client, "race-center")
    stored.unlink()

    # Pause the inspection right after its read-only check, repair from
    # another thread, then let the (now stale) quarantine proceed.
    reached = threading.Event()
    release = threading.Event()
    run_started = threading.Event()

    def before_quarantine(instance_id, check_status):
        reached.set()
        release.wait(timeout=10)

    inspection._before_quarantine_hook = before_quarantine
    try:
        worker = threading.Thread(
            target=lambda: inspection.inspect_center("race-center")
        )
        worker.start()
        assert reached.wait(timeout=10)

        # The inspection must have committed its run row (and snapshot) before
        # the repair starts, so the repair genuinely races the quarantine
        # rather than happening before the inspection opened any transaction.
        import time

        deadline = time.time() + 10
        while time.time() < deadline:
            runs = client.get(
                "/api/v1/inspections/runs",
                params={"center_id": "race-center"},
            ).json()
            if runs and runs[0]["status"] == "running":
                run_started.set()
                break
            time.sleep(0.02)
        assert run_started.is_set()

        # Concurrent repair through the normal service path.
        from app.service import UploadedFile, ingest_batch

        result = ingest_batch(
            "race-center",
            [UploadedFile(filename=image.name, content=image.read_bytes())],
        )
        assert result["files"][0]["action"] == "repair"
        assert stored.exists()

        release.set()
        worker.join(timeout=10)
        assert not worker.is_alive()
    finally:
        inspection._before_quarantine_hook = None

    inst_after = _instance(client, "race-center")
    assert inst_after["quarantine_state"] == "active"
    assert inst_after["state_version"] == 1  # only the repair bumped it

    run = client.get(
        "/api/v1/inspections/runs",
        params={"center_id": "race-center"},
    ).json()
    assert run[0]["status"] == "completed"
    detail = client.get(
        f"/api/v1/inspections/runs/{run[0]['run_id']}"
    ).json()
    assert detail["findings"][0]["check_status"] == "skipped_repaired"
    assert detail["quarantined_count"] == 0
    # The repaired file is intact and downloadable.
    dl = client.get(f"/api/v1/instances/{inst['id']}/download")
    assert dl.status_code == 200


def test_late_inspection_after_repair_of_corrupt_file_keeps_repair(
    client, samples_dir
):
    """Digest-mismatch variant: the on-disk file really was moved before the
    repair. The stale inspection must still not re-isolate the repaired file."""
    image = samples_dir / "reference_first" / "image_001.dcm"
    _ingest_one(client, "race-corrupt", image)
    inst = _instance(client, "race-corrupt")
    stored = _stored_file(client, "race-corrupt")

    # Corrupt the file so the inspection classifies digest_mismatch.
    raw = bytearray(stored.read_bytes())
    raw[128] ^= 0x01
    stored.write_bytes(bytes(raw))

    reached = threading.Event()
    release = threading.Event()

    def before_quarantine(instance_id, check_status):
        assert check_status == "digest_mismatch"
        reached.set()
        release.wait(timeout=10)

    inspection._before_quarantine_hook = before_quarantine
    try:
        worker = threading.Thread(
            target=lambda: inspection.inspect_center("race-corrupt")
        )
        worker.start()
        assert reached.wait(timeout=10)

        from app.service import UploadedFile, ingest_batch

        result = ingest_batch(
            "race-corrupt",
            [UploadedFile(filename=image.name, content=image.read_bytes())],
        )
        assert result["files"][0]["action"] == "repair"
        assert stored.exists()

        release.set()
        worker.join(timeout=10)
        assert not worker.is_alive()
    finally:
        inspection._before_quarantine_hook = None

    inst_after = _instance(client, "race-corrupt")
    assert inst_after["quarantine_state"] == "active"
    dl = client.get(f"/api/v1/instances/{inst['id']}/download")
    assert dl.status_code == 200

    runs = client.get(
        "/api/v1/inspections/runs", params={"center_id": "race-corrupt"}
    ).json()
    detail = client.get(
        f"/api/v1/inspections/runs/{runs[0]['run_id']}"
    ).json()
    assert detail["findings"][0]["check_status"] == "skipped_repaired"
    assert detail["quarantined_count"] == 0


def test_concurrent_repairs_and_inspections_converge_safely(
    client, samples_dir
):
    """Stress: many repairs and inspections racing on the same instances must
    never leave a quarantined row with a live healthy file (or vice versa) and
    must never lose the instance identity."""
    from concurrent.futures import ThreadPoolExecutor

    from app.service import UploadedFile, ingest_batch

    image = samples_dir / "reference_first" / "image_001.dcm"
    struct = samples_dir / "reference_first" / "struct_001.dcm"
    upload(client, "stress", [image, struct])
    instances = client.get(
        "/api/v1/instances", params={"center_id": "stress"}
    ).json()
    assert len(instances) == 2
    ids = {row["id"] for row in instances}

    payloads = {
        image.name: UploadedFile(filename=image.name, content=image.read_bytes()),
        struct.name: UploadedFile(filename=struct.name, content=struct.read_bytes()),
    }

    def repair():
        return ingest_batch(
            "stress", [payloads[image.name], payloads[struct.name]]
        )

    def inspect():
        return inspection.inspect_center("stress")

    outcomes: list = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = []
        for _ in range(4):
            futures.append(pool.submit(repair))
        for _ in range(4):
            futures.append(pool.submit(inspect))
        for fut in futures:
            try:
                outcomes.append(("ok", fut.result()))
            except Exception as exc:  # noqa: BLE001 - stress diagnostic
                outcomes.append(("err", type(exc).__name__))

    # Inspections may 409 against each other; repairs may 409 if a version
    # moved underneath them. Neither may corrupt the final state.
    assert any(kind == "ok" for kind, _ in outcomes)

    rows = client.get(
        "/api/v1/instances", params={"center_id": "stress"}
    ).json()
    assert {r["id"] for r in rows} == ids  # no rows created or destroyed
    for row in rows:
        stored = config.STORAGE_DIR / row["stored_path"]
        if row["quarantine_state"] == "active":
            assert stored.is_file()
            import hashlib

            assert (
                hashlib.sha256(stored.read_bytes()).hexdigest()
                == row["stored_sha256"]
            )
        else:
            # Quarantined rows must not expose a live object for download.
            dl = client.get(f"/api/v1/instances/{row['id']}/download")
            assert dl.status_code == 423
    assert not list(config.STORAGE_DIR.rglob("*.part"))
    assert not list(config.STORAGE_DIR.rglob("*.bak-*"))


def test_overlapping_inspections_of_same_center_are_rejected(
    client, samples_dir
):
    image = samples_dir / "reference_first" / "image_001.dcm"
    _ingest_one(client, "overlap-center", image)

    entered = threading.Event()
    release = threading.Event()

    def hook(instance_id, check_status):
        entered.set()
        release.wait(timeout=10)

    inspection._before_quarantine_hook = hook
    errors = []
    try:
        # Force a quarantine path so the hook actually fires.
        _stored_file(client, "overlap-center").unlink()
        first = threading.Thread(
            target=lambda: inspection.inspect_center("overlap-center")
        )
        first.start()
        assert entered.wait(timeout=10)

        def second():
            try:
                inspection.inspect_center("overlap-center")
            except inspection.InspectionError as exc:
                errors.append(exc)

        other = threading.Thread(target=second)
        other.start()
        other.join(timeout=10)
        release.set()
        first.join(timeout=10)
    finally:
        inspection._before_quarantine_hook = None

    assert len(errors) == 1
    assert errors[0].http_status == 409


# --------------------------------------------------------------------------- #
# Read-only inspection connection
# --------------------------------------------------------------------------- #
def test_inspection_uses_readonly_connection(client, samples_dir):
    image = samples_dir / "reference_first" / "image_001.dcm"
    _ingest_one(client, "ro-center", image)
    conn = get_readonly_connection()
    try:
        with pytest.raises(sqlite3.OperationalError):
            conn.execute(
                "UPDATE instances SET quarantine_state = 'quarantined'"
            )
    finally:
        conn.close()
    # And a normal inspection still works.
    run = _inspect(client, "ro-center")
    assert run["status"] == "completed"


# --------------------------------------------------------------------------- #
# Persistence across restart
# --------------------------------------------------------------------------- #
def test_quarantine_and_fingerprint_survive_restart(client, samples_dir):
    from fastapi.testclient import TestClient

    from app import main

    image = samples_dir / "reference_first" / "image_001.dcm"
    _ingest_one(client, "persist-center", image)
    _stored_file(client, "persist-center").unlink()
    _inspect(client, "persist-center")
    before = _instance(client, "persist-center")
    assert before["quarantine_state"] == "quarantined"

    # Brand-new app / connection pool simulates a process restart.
    with TestClient(main.app) as new_client:
        after = new_client.get(
            "/api/v1/instances", params={"center_id": "persist-center"}
        ).json()[0]
        assert after["quarantine_state"] == "quarantined"
        assert after["quarantine_reason"] == "missing"
        assert after["state_version"] == before["state_version"]
        dl = new_client.get(f"/api/v1/instances/{after['id']}/download")
        assert dl.status_code == 423

        # Repair after restart works and keeps the same instance identity.
        resp = upload(new_client, "persist-center", [image])
        assert resp.status_code == 201
        fixed = new_client.get(
            "/api/v1/instances", params={"center_id": "persist-center"}
        ).json()[0]
        assert fixed["id"] == before["id"]
        assert fixed["quarantine_state"] == "active"
        assert fixed["stored_sha256"] is not None


def test_startup_sweep_restores_interrupted_repair_backup(
    client, samples_dir, monkeypatch
):
    image = samples_dir / "reference_first" / "image_001.dcm"
    _ingest_one(client, "sweep-center", image)
    stored = _stored_file(client, "sweep-center")
    original_bytes = stored.read_bytes()

    # Simulate a crash between rename-aside and commit: backup exists, final
    # is missing, and a stray .part is left behind.
    backup = stored.with_name(f".{stored.name}.bak-deadbeef")
    stored.replace(backup)
    part = stored.with_name(f".{stored.name}.abc.part")
    part.write_bytes(b"partial")
    assert backup.exists() and part.exists() and not stored.exists()

    from app import storage

    storage.sweep_parts()
    assert stored.exists()
    assert stored.read_bytes() == original_bytes
    assert not backup.exists()
    assert not part.exists()


def test_inspection_unknown_center_404(client):
    resp = client.post("/api/v1/inspections/centers/never-seen")
    assert resp.status_code == 404
