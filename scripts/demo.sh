#!/usr/bin/env bash
# End-to-end demo against a running ingest API (default: http://localhost:8000).
#
# Part 1 (legacy scenarios):
#   1. cross-center UID collision  (same original UID, two centers)
#   2. reference-first, then the referenced image arrives (same center)
#   3. reference must NOT resolve across centers
#   4. idempotent retransmit (same bytes) vs. byte conflict (whole-batch reject)
#   5. batch query + object download, verifying pixels / transfer syntax
#
# Part 2 (integrity inspection, quarantine and repair):
#   6. per-center inspection: healthy objects report ok with a SHA-256
#      fingerprint; legacy objects without one report no_fingerprint
#   7. corrupt an object on disk -> inspection quarantines it (file moved out
#      of the live tree) -> download is refused with HTTP 423
#   8. re-upload the center original through the SAME batch endpoint -> repair
#      keeps instance id / UID mapping, restores the file and fingerprint
#   9. a follow-up inspection passes and the object is downloadable again
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8000}"
SAMPLES="$(cd "$(dirname "$0")/../samples/generated" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

say() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
post_batch() { # center file...
  local center="$1"; shift
  curl -sS -X POST "$BASE_URL/api/v1/batches" \
    -F "center_id=$center" \
    $(printf -- '-F files=@%s ' "$@")
}

say "0. health check"
curl -sS "$BASE_URL/healthz"; echo

say "1. CROSS-CENTER UID COLLISION: both centers reuse the same original SOP UID"
post_batch center-a "$SAMPLES/cross_center_uid_collision/center-a/image_001.dcm" | tee "$WORK/a.json"; echo
post_batch center-b "$SAMPLES/cross_center_uid_collision/center-b/image_001.dcm" | tee "$WORK/b.json"; echo
UID_A=$(python3 -c 'import json;print(json.load(open("'$WORK/a.json'"))["files"][0]["new_sop_uid"])')
UID_B=$(python3 -c 'import json;print(json.load(open("'$WORK/b.json'"))["files"][0]["new_sop_uid"])')
[ "$UID_A" != "$UID_B" ] && echo "OK: same original UID -> distinct remapped UIDs per center"

say "2. REFERENCE-FIRST: upload the SR that points at an image not yet present"
post_batch center-x "$SAMPLES/reference_first/struct_001.dcm" | tee "$WORK/struct.json"; echo
echo "-- pending references for center-x (expect one unresolved):"
curl -sS "$BASE_URL/api/v1/references/pending?center_id=center-x&resolved=false"; echo

say "3. The SAME original target SOP uploaded by center-y must NOT resolve center-x's ref"
post_batch center-y "$SAMPLES/reference_first/image_001.dcm" > /dev/null
curl -sS "$BASE_URL/api/v1/references/pending?center_id=center-x&resolved=false"; echo
echo "  (still one pending row above: references never cross centers)"

say "4. Now center-x uploads its own image -> pending reference resolves"
post_batch center-x "$SAMPLES/reference_first/image_001.dcm" > /dev/null
curl -sS "$BASE_URL/api/v1/references/pending?center_id=center-x&resolved=false"; echo
echo "  (empty list above: reference resolved by same-center image)"

say "5. IDEMPOTENT RETRANSMIT: identical bytes reuse the stored object"
post_batch center-x "$SAMPLES/reference_first/image_001.dcm" | python3 -m json.tool

say "6. BYTE CONFLICT: same original SOP, changed bytes -> whole batch rejected (409)"
cp "$SAMPLES/reference_first/image_001.dcm" "$WORK/mutated.dcm"
printf '\001' | dd of="$WORK/mutated.dcm" bs=1 seek=$(( $(stat -c%s "$WORK/mutated.dcm") - 1 )) count=1 conv=notrunc 2>/dev/null
post_batch center-x "$WORK/mutated.dcm" "$SAMPLES/reference_first/struct_001.dcm"; echo

say "7. BATCH QUERY + DOWNLOAD: verify rewritten object keeps TS and pixel bytes"
BATCH=$(python3 -c 'import json;print(json.load(open("'$WORK/a.json'"))["batch_id"])')
curl -sS "$BASE_URL/api/v1/batches/$BATCH" | python3 -m json.tool
INSTANCE=$(curl -sS "$BASE_URL/api/v1/instances?center_id=center-a" | python3 -c 'import json,sys;print(json.load(sys.stdin)[0]["id"])')
curl -sS -D "$WORK/headers" "$BASE_URL/api/v1/instances/$INSTANCE/download" -o "$WORK/down.dcm"
grep -iE "content-type|x-new-sop|x-transfer" "$WORK/headers"
python3 - "$SAMPLES/cross_center_uid_collision/center-a/image_001.dcm" "$WORK/down.dcm" <<'PY'
import sys, pydicom
src, out = (pydicom.dcmread(p) for p in sys.argv[1:])
assert src.PixelData == out.PixelData, "pixel bytes changed!"
assert str(out.file_meta.TransferSyntaxUID) == "1.2.840.10008.1.2.1"
assert out.is_implicit_VR is False and out.is_little_endian is True
print("OK: pixel bytes identical; transfer syntax still Explicit VR Little Endian")
print("rewritten SOP:", out.SOPInstanceUID)
PY

say "8. INVALID OBJECT: whole batch rejected (422), nothing stored"
curl -sS -o "$WORK/inv.json" -w "HTTP %{http_code}\n" -X POST "$BASE_URL/api/v1/batches" \
  -F "center_id=center-z" \
  -F "files=@$SAMPLES/reference_first/image_001.dcm" \
  -F "files=@$SAMPLES/invalid/not_a_dicom.dcm"
cat "$WORK/inv.json"; echo
curl -sS "$BASE_URL/api/v1/batches?center_id=center-z"; echo "  (empty list above)"

# --------------------------------------------------------------------------- #
# Integrity inspection / quarantine / repair
# --------------------------------------------------------------------------- #
say "9. CENTER INSPECTION (healthy): fingerprint + ok status per instance"
post_batch insp-center "$SAMPLES/reference_first/image_001.dcm" > "$WORK/insp.json"
INSP_INSTANCE=$(python3 -c 'import json;print(json.load(open("'$WORK/insp.json'"))["files"][0]["new_sop_uid"])')
curl -sS -X POST "$BASE_URL/api/v1/inspections/centers/insp-center" | python3 -m json.tool

say "10. CORRUPT THE STORED FILE ON DISK, THEN INSPECT AGAIN"
STORED=$(curl -sS "$BASE_URL/api/v1/instances?center_id=insp-center" \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)[0]["stored_path"])')
echo "stored relative path: $STORED"
# The object lives in the container volume at /data/objects/<stored_path>.
# docker compose exec flips one byte there. When running against a non-Docker
# server, set LOCAL_DATA_DIR to the same path as DICOM_INGEST_DATA_DIR instead.
if [ -n "${LOCAL_DATA_DIR:-}" ]; then
  f="$LOCAL_DATA_DIR/objects/$STORED"
  cp "$f" /tmp/good.dcm
  printf '\001' | dd of="$f" bs=1 seek=200 count=1 conv=notrunc 2>/dev/null
  echo "corrupted (local): $f"
else
  docker compose exec -T dicom-ingest sh -lc '
    f="/data/objects/'"$STORED"'"
    printf "\001" | dd of="$f" bs=1 seek=200 count=1 conv=notrunc 2>/dev/null
    echo "corrupted (container): $f"
  '
fi

say "11. INSPECTION DETECTS THE DIGEST MISMATCH AND QUARANTINES THE OBJECT"
RUN=$(curl -sS -X POST "$BASE_URL/api/v1/inspections/centers/insp-center")
echo "$RUN" | python3 -m json.tool
RUN_ID=$(echo "$RUN" | python3 -c 'import json,sys;print(json.load(sys.stdin)["run_id"])')
echo "-- run history (newest first):"
curl -sS "$BASE_URL/api/v1/inspections/runs?center_id=insp-center" | python3 -m json.tool
echo "-- instance state now quarantined:"
curl -sS "$BASE_URL/api/v1/instances?center_id=insp-center" | python3 -m json.tool

say "12. DOWNLOAD IS REFUSED AFTER QUARANTINE (expect HTTP 423 Locked)"
QID=$(curl -sS "$BASE_URL/api/v1/instances?center_id=insp-center" \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)[0]["id"])')
curl -sS -o "$WORK/refused.json" -w "HTTP %{http_code}\n" \
  "$BASE_URL/api/v1/instances/$QID/download"
cat "$WORK/refused.json"; echo

say "13. REPAIR: re-upload the center original via the SAME /batches entry point"
REPAIR=$(post_batch insp-center "$SAMPLES/reference_first/image_001.dcm")
echo "$REPAIR" | python3 -m json.tool
echo "$REPAIR" | python3 -c 'import json,sys;b=json.load(sys.stdin);assert b["files"][0]["action"]=="repair";print("OK: action=repair, instance id and UID mapping unchanged")'

say "14. RE-INSPECTION PASSES AND DOWNLOAD WORKS AGAIN"
curl -sS -X POST "$BASE_URL/api/v1/inspections/centers/insp-center" | python3 -m json.tool
curl -sS -o "$WORK/restored.dcm" -w "download HTTP %{http_code}\n" \
  "$BASE_URL/api/v1/instances/$QID/download"
python3 - "$WORK/restored.dcm" "$INSP_INSTANCE" <<'PY'
import sys, pydicom
path, expected_sop = sys.argv[1], sys.argv[2]
ds = pydicom.dcmread(path)
assert str(ds.SOPInstanceUID) == expected_sop, "UID mapping changed after repair!"
assert str(ds.file_meta.TransferSyntaxUID) == "1.2.840.10008.1.2.1"
print("OK: repaired object downloadable, same SOP UID", expected_sop)
PY

echo
echo "Interactive docs: open $BASE_URL/docs in a browser."
echo "Try POST /api/v1/inspections/centers/{center_id}, the 423 on"
echo "GET /api/v1/instances/{id}/download, and the repair POST /api/v1/batches."
