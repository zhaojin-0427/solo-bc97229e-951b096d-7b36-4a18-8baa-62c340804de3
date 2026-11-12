#!/bin/sh
# Ensure the data volume layout exists and is writable by the unprivileged
# runtime user, then exec the given command (uvicorn by default).
#
# On a fresh named volume Docker copies the image's /data (owned by appuser),
# so mkdir is a no-op. On a pre-existing root-owned bind mount the mkdir calls
# may fail; they stay non-fatal because the application's own ensure_dirs()
# reports the real permission error clearly at first use.
set -e

for sub in objects quarantine; do
  mkdir -p "${DICOM_INGEST_DATA_DIR}/${sub}" 2>/dev/null || true
done

exec "$@"
