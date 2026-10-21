# OpenHost MinIO container.
#
# Layers an OpenHost auto-login auth-proxy on top of the upstream
# MinIO server.  The S3 API (port 9000) is exposed publicly via the
# [[ports]] mapping in openhost.toml — that surface uses MinIO's
# native access-key auth and is unaffected by this proxy.  The web
# console (default port 9001) binds on container loopback, with
# the auth-proxy on container port 9090 acting as the public-facing
# OpenHost-routed entry point.
#
# Auth flow:
#
#   1. Browser hits https://minio.<zone>/.  The OpenHost router
#      verifies the visitor's zone_auth JWT and stamps
#      X-OpenHost-Is-Owner: true onto the request before forwarding
#      to the auth-proxy on container port 9090.
#   2. Auth-proxy: if owner AND no MinIO `token` cookie yet, POSTs
#      the on-disk root creds to MinIO's /api/v1/login, captures
#      the resulting Set-Cookie, and 302's the browser back to
#      the same path with the cookie attached.
#   3. Browser follows the redirect, now carrying the MinIO token
#      cookie; auth-proxy forwards normally and the SPA loads
#      logged-in.
#
# This mirrors the openhost-plane.so pattern: trust the OpenHost
# router's X-OpenHost-Is-Owner header (it's restamped fresh every
# request after JWT verification) and use it as the trigger to
# mint an in-app session.
#
# The official release binaries are archived on GitHub. Each architecture
# uses immutable checksums, and ADD preserves executable modes without RUN.
ARG TARGETARCH

FROM scratch AS minio-amd64
ADD --checksum=sha256:7c5bd8512c6e966455b1d198209358b2d191c77a83ab377c4073281065fb855f --chmod=755 https://github.com/minio/minio/releases/download/RELEASE.2025-09-07T16-13-09Z/minio.linux-amd64.RELEASE.2025-09-07T16-13-09Z /usr/bin/minio
ADD --checksum=sha256:01f866e9c5f9b87c2b09116fa5d7c06695b106242d829a8bb32990c00312e891 --chmod=755 https://github.com/minio/mc/releases/download/RELEASE.2025-08-13T08-35-41Z/mc.linux-amd64.RELEASE.2025-08-13T08-35-41Z /usr/bin/mc

FROM scratch AS minio-arm64
ADD --checksum=sha256:5c83cd2cf151717ba0243f73e1c7802ff36e272b67144bdd7f1f7d684fd6f03d --chmod=755 https://github.com/minio/minio/releases/download/RELEASE.2025-09-07T16-13-09Z/minio.linux-arm64.RELEASE.2025-09-07T16-13-09Z /usr/bin/minio
ADD --checksum=sha256:14c8c9616cfce4636add161304353244e8de383b2e2752c0e9dad01d4c27c12c --chmod=755 https://github.com/minio/mc/releases/download/RELEASE.2025-08-13T08-35-41Z/mc.linux-arm64.RELEASE.2025-08-13T08-35-41Z /usr/bin/mc

FROM minio-${TARGETARCH} AS minio-source

# Stage 2: build the runtime image.
#
# python:3.13-slim has Python (for the auth-proxy), bash + coreutils
# (for start.sh's first-boot credential generator), and ca-certs
# (so MinIO can talk over TLS to anything it federates with).
# Avoiding `RUN apt-get install` keeps the build portable across
# operator hosts whose podman+crun trips on newer base images
# (the system crun on some hosts rejects the OCI metadata of any
# RUN step with "unknown version specified").
FROM python:3.13-slim

# -- minio + mc -------------------------------------------------
# Statically-linked Go binaries.
COPY --from=minio-source /usr/bin/minio /usr/bin/minio
COPY --from=minio-source /usr/bin/mc /usr/bin/mc

# -- auth-proxy + start.sh -------------------------------------
# Both files are committed to the repo with mode 0755 (verify with
# `git ls-files --stage`).  Buildah/podman preserves the git index
# mode through COPY, so no `RUN chmod +x` is needed — important
# for the same crun-portability reason.
COPY auth_proxy.py     /opt/openhost-minio/auth_proxy.py
COPY start.sh          /opt/openhost-minio/start.sh
COPY fetch_secrets.py  /opt/openhost-minio/fetch_secrets.py

# -- runtime ---------------------------------------------------
# 9090 = auth-proxy (the openhost.toml `port`, gated by the
#        OpenHost router upstream of us, owner-stamped).
# 9000 = S3 API (the [[ports]] published port, gated by MinIO's
#        own access-key auth model).
EXPOSE 9090
EXPOSE 9000

ENTRYPOINT ["/opt/openhost-minio/start.sh"]
