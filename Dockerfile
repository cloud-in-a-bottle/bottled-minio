# OpenHost MinIO container.
#
# We base directly on the upstream minio/minio:latest image and only
# COPY a start.sh on top of it.  No RUN steps at all — some operator
# hosts have a podman+crun combo that fails any RUN-during-build with
# "unknown version specified" (the host's crun rejects newer OCI
# metadata), so keeping the build to pure file copies is the most
# portable shape.  The upstream minio/minio image already ships
# bash + all the coreutils start.sh needs (head, base64, tr, cat,
# mkdir, chown, dd, etc.) — they're hardlinked into a single
# busybox-style multi-call binary.
#
# Auth: the OpenHost router gates the console on /minio/ — every
# request needs a valid zone_auth cookie or the router 302's the
# visitor to /login on the parent zone.  No auth-proxy sidecar is
# needed; see the openhost.toml comment for why this differs from
# openhost-syncthing / openhost-nextcloud / openhost-peertube.

FROM minio/minio:latest

# start.sh is committed to the repo with mode 0755 (verify with
# `git ls-files --stage start.sh`).  Buildah/podman preserves the
# git index mode through COPY, so no `RUN chmod +x` is needed.
COPY start.sh /opt/openhost-minio/start.sh

# 9001 = MinIO console (the openhost.toml `port`, gated by the
#        OpenHost router upstream of us).
# 9000 = S3 API (the [[ports]] published port, gated by MinIO's
#        own access-key auth model).
EXPOSE 9001
EXPOSE 9000

ENTRYPOINT ["/opt/openhost-minio/start.sh"]
