#!/usr/bin/env bash
# Build the SIGIL image from a clean checkout and smoke-test it.
#
# The wheel is built inside the image (see deploy/Dockerfile), so this works on
# a fresh clone: no dist/ artefact is required. The smoke test runs the gate the
# way deploy/docker-compose.prod.yml does — read-only root filesystem, non-root
# uid 65534, all capabilities dropped — and waits for /health.
#
# Usage:
#   bash deploy/build.sh                 # build sigil:local + smoke test
#   SIGIL_IMAGE=sigil:0.22 bash deploy/build.sh
#   SIGIL_SMOKE_PORT=18800 bash deploy/build.sh
#
# SIGIL_DOCKER_BUILD_ARGS lets an air-gapped/mirrored environment pass extra
# `docker build` flags (e.g. "--add-host pypi.org:1.2.3.4" when the daemon's DNS
# is broken).
set -euo pipefail

cd "$(dirname "$0")/.."

IMAGE="${SIGIL_IMAGE:-sigil:local}"
PORT="${SIGIL_SMOKE_PORT:-18800}"
CONTAINER="sigil-smoke-$$"

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> docker build -f deploy/Dockerfile -t $IMAGE ."
# shellcheck disable=SC2086
docker build ${SIGIL_DOCKER_BUILD_ARGS:-} -f deploy/Dockerfile -t "$IMAGE" .

echo "==> smoke: import + version + non-root uid"
uid="$(docker run --rm --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  "$IMAGE" python -c 'import os, sigil; print(sigil.__version__, os.getuid())')"
version="${uid%% *}"
run_uid="${uid##* }"
echo "    sigil $version, uid $run_uid"
if [ "$run_uid" != "65534" ]; then
  echo "FAIL: expected uid 65534, got $run_uid" >&2
  exit 1
fi

echo "==> smoke: gate /health (read-only, non-root, cap-drop ALL) on 127.0.0.1:$PORT"
docker run -d --name "$CONTAINER" \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --tmpfs /data:rw,size=64m,mode=1777 \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --user 65534:65534 \
  -p "127.0.0.1:$PORT:18100" \
  "$IMAGE" python -m sigil.gate >/dev/null

health=""
for _ in $(seq 1 30); do
  if health="$(curl -fsS --max-time 2 "http://127.0.0.1:$PORT/health" 2>/dev/null)"; then
    break
  fi
  health=""
  sleep 1
done

if [ -z "$health" ]; then
  echo "FAIL: /health did not answer within 30s" >&2
  docker logs "$CONTAINER" >&2 || true
  exit 1
fi

echo "    $health"
echo "OK: $IMAGE built and smoke-tested"
