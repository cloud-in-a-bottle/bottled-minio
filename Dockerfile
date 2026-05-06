# OpenHost MinIO container.
#
# Plain MinIO server with an OpenHost-aware start.sh that derives
# the right MINIO_BROWSER_REDIRECT_URL / MINIO_SERVER_URL from
# OPENHOST_ZONE_DOMAIN and bootstraps strong root credentials on
# first boot.
#
# Auth: the OpenHost router gates the console on /minio/ (every
# request needs a valid zone_auth cookie or the router 302's the
# visitor to /login on the parent zone).  We don't ship an
# auth-proxy sidecar — see the openhost.toml comment for why this
# differs from openhost-syncthing / openhost-nextcloud /
# openhost-peertube.
#
# We could base on minio/minio:latest, but that image is a heavily-
# stripped RHEL UBI 9 with NO package manager and only the minio +
# mc binaries.  Our start.sh needs bash + coreutils for first-boot
# credential generation.  Use a multi-stage build: pull the minio +
# mc binaries (statically-linked Go) from the upstream image, run
# them on debian:bookworm-slim which has the rest of the toolchain
# we need.  The result is ~250 MiB and the minio binary is bit-
# identical to what upstream ships.

# Stage 1: pull the official MinIO binaries.
FROM minio/minio:latest AS minio-source

# Stage 2: build the runtime image.
FROM debian:bookworm-slim

# -- system deps ------------------------------------------------
# bash for start.sh, coreutils + curl for the first-boot
# credential generator and operator inspection.  ca-certificates
# so MinIO can talk over TLS to anything it federates with.
RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends \
      bash coreutils curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# -- minio + mc -------------------------------------------------
# Statically-linked Go binaries; they don't depend on RHEL libs.
COPY --from=minio-source /usr/bin/minio /usr/bin/minio
COPY --from=minio-source /usr/bin/mc /usr/bin/mc

# -- application -----------------------------------------------
COPY start.sh /opt/openhost-minio/start.sh
RUN chmod +x /opt/openhost-minio/start.sh

# -- runtime ---------------------------------------------------
# 9001 = MinIO console (the openhost.toml `port`).
# 9000 = S3 API (the [[ports]] published port).
EXPOSE 9001
EXPOSE 9000

ENTRYPOINT ["/opt/openhost-minio/start.sh"]
