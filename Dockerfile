# OpenHost MinIO container.
#
# Layers an OpenHost-SSO auth-proxy sidecar on top of the upstream
# MinIO server image.  The S3 API (port 9000) is exposed publicly
# via OpenHost's [[ports]] mapping — its own access-key auth model
# is what gates that endpoint.  The web console (default port 9001)
# is bound to loopback only and only reachable via the auth-proxy
# at port 9090, which verifies the visitor's zone_auth JWT and
# forwards only requests from the zone owner.
#
# We base on minio/minio:latest rather than building from scratch
# because the upstream image is a stable, reproducible artifact
# that already ships the right MinIO version, and re-deriving it
# inside our Dockerfile would just be reproducing upstream's work
# while making it harder to audit "we ship the same MinIO binary
# everyone else does."
FROM minio/minio:latest

# -- Python + auth-proxy deps ------------------------------------
# The upstream image is RHEL UBI Micro; install Python and pip via
# microdnf.  We need PyJWT for RS256 verification and `requests`
# for the JWKS fetch + the proxy itself.
USER root
RUN microdnf install -y python3 python3-pip ca-certificates \
 && microdnf clean all

# Use a venv so we don't fight the system Python's package manager
# semantics (RHEL micro has no pip lockfile machinery).  The venv
# lives at /opt/auth-venv.
RUN python3 -m venv /opt/auth-venv \
 && /opt/auth-venv/bin/pip install --no-cache-dir \
        'PyJWT[crypto]==2.10.1' \
        'requests==2.32.3'

# -- Application ------------------------------------------------
# auth_proxy.py is the SSO-verifying sidecar.  start.sh launches
# minio (with its console bound to 127.0.0.1:9001) plus the
# auth-proxy (bound to 0.0.0.0:9090, the port OpenHost routes to).
COPY auth_proxy.py /opt/openhost-minio/auth_proxy.py
COPY start.sh /opt/openhost-minio/start.sh
RUN chmod +x /opt/openhost-minio/start.sh

# -- Runtime ----------------------------------------------------
# Both ports declared so an `oh app inspect` and a docker-compat
# tool both see the right surface.  9090: SSO-gated console.
# 9000: public S3 API (gated by MinIO's own auth).
EXPOSE 9090
EXPOSE 9000

# OpenHost mounts the persistent app-data dir at
# /data/app_data/minio (host-side: same path under the persistent
# data root).  start.sh resolves OPENHOST_APP_DATA_DIR and writes
# the buckets/, config/, certs/ subdirs there.

ENTRYPOINT ["/opt/openhost-minio/start.sh"]
