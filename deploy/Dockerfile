# syntax=docker/dockerfile:1
#
# SIGIL runtime image.
#
# The wheel is built inside the image from the checked-out sources. A fresh
# clone has no dist/ (it is gitignored and CI never produces one), so the build
# must never read a prebuilt artefact. No version appears in this file: bumping
# pyproject.toml / sigil.__version__ does not require touching the Dockerfile.
#
# Base image is pinned by digest for reproducibility. To move to a newer
# python:3.12-slim, resolve the new digest and update PYTHON_IMAGE below:
#   docker buildx imagetools inspect python:3.12-slim
ARG PYTHON_IMAGE=python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

# ---- build stage: source -> wheel -------------------------------------------
FROM ${PYTHON_IMAGE} AS wheel

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /src
COPY pyproject.toml ./
COPY sigil ./sigil

RUN python -m pip install --no-cache-dir --upgrade pip build \
 && python -m build --wheel --outdir /dist

# ---- runtime stage: wheel -> minimal image ----------------------------------
FROM ${PYTHON_IMAGE} AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY --from=wheel /dist/*.whl /tmp/wheels/
RUN python -m pip install --no-cache-dir /tmp/wheels/*.whl \
 && rm -rf /tmp/wheels

# Service ports (compose publishes them as 191xx on the host).
EXPOSE 18100 18101 18102 18103 18120

# Non-root, no writable path inside the image: works under --read-only with
# tmpfs/bind mounts for /data, /effects, /pub, /kms, as in deploy/compose.
USER 65534:65534
