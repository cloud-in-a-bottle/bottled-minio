# OpenHost MinIO container.
#
# Layers an OpenHost-SSO auth-proxy sidecar on top of the upstream
# MinIO server binary.  The S3 API (port 9000) is exposed publicly
# via OpenHost's [[ports]] mapping — its own access-key auth model
# is what gates that endpoint.  The web console (default port 9001)
# is bound to loopback only and only reachable via the auth-proxy
# at port 9090, which verifies the visitor's zone_auth JWT and
# forwards only requests from the zone owner.
#
# We could base on minio/minio:latest, but that image is a heavily-
# stripped RHEL UBI 9 with NO package manager, no grep, no python,
# essentially just coreutils + the minio binary.  Adding our auth-
# proxy sidecar to that image would require building Python from
# source.  Instead we use a multi-stage build: pull the minio + mc
# binaries from the upstream image (they're statically linked Go
# binaries — they don't need RHEL libraries to run), and put them
# on a python:3.13-slim base that has the rest of the toolchain we
# need for the sidecar.  The result is a slightly bigger image
# (~300 MiB vs ~250 MiB for the upstream alone) but a vastly more
# maintainable one, and the minio binary itself is identical to
# what upstream ships.

# Stage 1: pull the official MinIO binaries.
FROM minio/minio:latest AS minio-source

# Stage 2: build the runtime image on python:3.13-slim, which has
# Python + apt + libc6 already.  Copy the minio + mc binaries in
# from stage 1.
FROM python:3.13-slim

# -- system deps ------------------------------------------------
# curl for the health check inside the container, ca-certificates
# so MinIO can talk to the JWKS endpoint over TLS.
RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

# -- minio + mc -------------------------------------------------
# Copy the upstream binaries into the standard /usr/bin location.
# These are statically-linked Go binaries; they do not depend on
# any libraries from the upstream RHEL image.
COPY --from=minio-source /usr/bin/minio /usr/bin/minio
COPY --from=minio-source /usr/bin/mc /usr/bin/mc

# -- python deps for the auth-proxy ------------------------------
# A real venv at /opt/auth-venv so start.sh's
# /opt/auth-venv/bin/python3 invocation pattern (matching
# openhost-syncthing) works.  PyJWT[crypto] pulls in cryptography
# for RS256 verification; requests for the JWKS fetch.
RUN python3 -m venv /opt/auth-venv \
 && /opt/auth-venv/bin/pip install --no-cache-dir \
        'PyJWT[crypto]==2.10.1' \
        'requests==2.32.3'

# -- application -----------------------------------------------
COPY auth_proxy.py /opt/openhost-minio/auth_proxy.py
COPY start.sh /opt/openhost-minio/start.sh
RUN chmod +x /opt/openhost-minio/start.sh

# -- runtime ---------------------------------------------------
EXPOSE 9090
EXPOSE 9000

ENTRYPOINT ["/opt/openhost-minio/start.sh"]
