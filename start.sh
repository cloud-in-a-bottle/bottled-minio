#!/bin/bash
# Launch MinIO on OpenHost.
#
# Topology:
#
#   browser → OpenHost outer Caddy (TLS termination)
#          → OpenHost router (path-prefix /minio/, auth-gates here)
#          → container :9001  (MinIO console)
#
#   S3 client (aws-cli, rclone, mc, etc.) →
#          host_port 9106 (from openhost.toml [[ports]])
#          → container :9000  (MinIO S3 API)
#
# The console is private (router redirects unauthenticated visitors
# to /login on the parent zone).  The S3 API is gated by MinIO's
# native access-key auth, which is the right primitive for non-
# browser clients — `aws s3 cp` cannot do an SSO redirect dance.
#
# We use bash specifically (not /bin/sh) because we want associative
# arrays and the `[[ ... ]]` test syntax for cleaner first-boot
# credential generation.
set -euo pipefail

# -----------------------------------------------------------------
# Persistence
# -----------------------------------------------------------------

# OpenHost mounts the persistent app-data dir at
# OPENHOST_APP_DATA_DIR.  In a real deploy this resolves to
# /data/app_data/minio inside the container; the same files show
# up on the OpenHost host under the persistent app_data dir.  We
# split the data, config, and cert dirs out so MinIO's object
# data is cleanly separated from the per-deploy bootstrap files
# (root credentials, future TLS material).
PERSIST="${OPENHOST_APP_DATA_DIR:-/data/app_data/minio}"
DATA_DIR="$PERSIST/data"
CONFIG_DIR="$PERSIST/config"
CERTS_DIR="$PERSIST/certs"
mkdir -p "$DATA_DIR" "$CONFIG_DIR" "$CERTS_DIR"

# -----------------------------------------------------------------
# Bootstrap root credentials
# -----------------------------------------------------------------
#
# MinIO requires the MINIO_ROOT_USER / MINIO_ROOT_PASSWORD env vars
# to start.  On first boot we generate strong defaults and persist
# them to disk under $CONFIG_DIR/root-credentials.txt — operators
# read them via e.g.
#   podman exec openhost-minio cat /data/app_data/minio/config/root-credentials.txt
# Subsequent boots read the same file so the credentials stay
# stable across restarts; rotating means deleting the file (and
# updating MinIO's IAM separately if you cared about the old key
# lingering in any user-created policies).
#
# We fall back to operator-supplied env vars if they're set —
# operators who want to manage the root credentials themselves
# can override and the on-disk file is ignored.
CRED_FILE="$CONFIG_DIR/root-credentials.txt"

if [[ -z "${MINIO_ROOT_USER:-}" || -z "${MINIO_ROOT_PASSWORD:-}" ]]; then
    if [[ -f "$CRED_FILE" ]]; then
        # shellcheck disable=SC1090
        source "$CRED_FILE"
    else
        echo "[start.sh] First boot: generating MinIO root credentials"
        # MinIO requires the username to be at least 3 chars and
        # the password at least 8.  We generate a 16-char username
        # (alphanumeric only — no special chars MinIO might reject)
        # and a 32-char password from /dev/urandom.
        MINIO_ROOT_USER="openhost-$(head -c 8 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 8)"
        MINIO_ROOT_PASSWORD="$(head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 32)"
        umask 077
        cat > "$CRED_FILE" <<EOF
# MinIO root credentials, auto-generated on first boot.
# Anyone with these credentials has full admin access to the
# console and the S3 API.  Treat as you would a root password.
#
# To rotate: delete this file AND update MinIO's IAM (the file
# alone won't take effect because MinIO already wrote them to
# its on-disk DB at first start).
export MINIO_ROOT_USER='$MINIO_ROOT_USER'
export MINIO_ROOT_PASSWORD='$MINIO_ROOT_PASSWORD'
EOF
        umask 022
    fi
fi
export MINIO_ROOT_USER MINIO_ROOT_PASSWORD

# -----------------------------------------------------------------
# Console + API URL hints
# -----------------------------------------------------------------
#
# These two env vars tell MinIO what URLs to report to clients.
# Without them, the console emits redirect-back URLs based on
# whatever Host the proxy forwarded, which loops badly behind a
# path-prefix router.  Setting them explicitly pins the console's
# self-referential URLs to the public hostname.
ZONE_DOMAIN="${OPENHOST_ZONE_DOMAIN:-localhost}"
APP_BASE_PATH="${OPENHOST_APP_BASE_PATH:-/minio}"
S3_API_HOST_PORT="${MINIO_S3_API_HOST_PORT:-9106}"

# Console URL: where the browser thinks the console lives.  The
# OpenHost router forwards /minio/* on the zone domain to this
# container's port 9001, so the public URL is
# https://<zone>/minio.
export MINIO_BROWSER_REDIRECT_URL="https://${ZONE_DOMAIN}${APP_BASE_PATH}"

# S3 API URL: the public endpoint clients use for `aws s3 cp`,
# rclone, mc, etc.  Reaches MinIO via the [[ports]] mapping
# (host_port 9106 → container 9000).  Note: HTTP, not HTTPS — the
# zone's outer Caddy does NOT TLS-terminate this port.  For a
# production setup that needs TLS on the S3 endpoint, drop a cert
# pair into $CERTS_DIR/public.crt and $CERTS_DIR/private.key;
# MinIO will pick them up at startup.
export MINIO_SERVER_URL="http://${ZONE_DOMAIN}:${S3_API_HOST_PORT}"

# -----------------------------------------------------------------
# Launch MinIO
# -----------------------------------------------------------------
#
# --address ":9000"           — S3 API on container port 9000.
# --console-address ":9001"   — web console on container port
#                               9001.  Both bind 0.0.0.0; the S3
#                               API is intentionally public via
#                               the [[ports]] mapping, and the
#                               console is gated by the OpenHost
#                               router upstream of us.
# --config-dir / --certs-dir  — operator-controlled persistent
#                               state per the dirs above.

echo "[start.sh] Starting MinIO server (data=$DATA_DIR, console=:9001, api=:9000)"
exec minio server "$DATA_DIR" \
    --config-dir "$CONFIG_DIR" \
    --certs-dir "$CERTS_DIR" \
    --address ":9000" \
    --console-address ":9001"
