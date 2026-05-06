#!/bin/bash
# Launch MinIO + the OpenHost auth-proxy sidecar in a single
# container.  Modelled on openhost-syncthing/start.sh — same
# wait-n-on-two-children pattern, same sentinel-gated first-boot
# initialization, same layering of "OpenHost SSO front-door for the
# console" on top of an unmodified upstream daemon.
#
# Topology:
#
#   OpenHost router  →  127.0.0.1:9090   (auth-proxy sidecar)
#                   →  127.0.0.1:9001   (MinIO console)
#                                      [SSO-gated, owner-only]
#
#   Public S3 client →  <zone>:9106     (host port from openhost.toml)
#                   →  container :9000  (MinIO S3 API)
#                                      [access-key gated by MinIO]
#
# We use bash specifically (not /bin/sh) for `wait -n`.
set -euo pipefail

# -----------------------------------------------------------------
# Persistence
# -----------------------------------------------------------------

# OpenHost mounts the persistent app-data dir at
# OPENHOST_APP_DATA_DIR (typically /data/app_data/minio inside the
# container; the host-side path is the persistent app_data dir
# under the OpenHost data root).  We split it into:
#   data/    — MinIO object data (every bucket lives here).  This
#              is where MinIO writes blobs.  The `minio server`
#              argument below points at this directory.
#   config/  — MinIO's configuration directory (--config-dir).
#              Holds .minio.sys/, IAM policies, encryption keys, etc.
#   certs/   — TLS material (currently unused — the zone's outer
#              Caddy terminates TLS for us — but reserved for
#              future use if we want MinIO itself to serve HTTPS
#              on the published S3 port).
PERSIST="${OPENHOST_APP_DATA_DIR:-/data/app_data/minio}"
DATA_DIR="$PERSIST/data"
CONFIG_DIR="$PERSIST/config"
CERTS_DIR="$PERSIST/certs"
# In a real OpenHost deploy compute_space sets
# OPENHOST_APP_DATA_DIR=/data/app_data/minio inside the container,
# so DATA_DIR resolves to /data/app_data/minio/data, CONFIG_DIR
# to /data/app_data/minio/config, etc.  The same paths show up
# on the OpenHost host under
# /home/host/.openhost/.../persistent_data/app_data/minio/.
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
# and wire them into the console at first login.  Subsequent boots
# read the same file so the credentials stay stable across
# container restarts; rotating means deleting the file (and
# updating MinIO's IAM separately if you cared about the old key
# lingering in any user-created policies).
#
# We fall back to operator-supplied env vars if they're set —
# operators who want to manage the root credentials themselves
# (e.g. via OPENHOST_APP_TEMPLATE) can override and the on-disk
# file is ignored.
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
# Without them the console ends up generating "browser redirect"
# loops back to whatever Host the auth-proxy reported; setting
# them explicitly avoids that.
#
# OPENHOST_ZONE_DOMAIN is injected by compute_space at container
# start; OPENHOST_APP_BASE_PATH is the path-prefix the OpenHost
# router routes to this app under (e.g. /minio).  Combined they
# tell MinIO where its console is publicly reachable.
ZONE_DOMAIN="${OPENHOST_ZONE_DOMAIN:-localhost}"
APP_BASE_PATH="${OPENHOST_APP_BASE_PATH:-/minio}"
S3_API_HOST_PORT="${MINIO_S3_API_HOST_PORT:-9106}"

# Console: the URL the operator's browser hits.  Path-prefixed
# under the zone's outer Caddy.
export MINIO_BROWSER_REDIRECT_URL="https://${ZONE_DOMAIN}${APP_BASE_PATH}"

# S3 API: the URL clients use for `aws s3 cp`, rclone, mc, etc.
# Reaches MinIO via the published [[ports]] entry on the zone's
# host (port 9106 by default).  Note: the zone's outer Caddy
# does NOT TLS-terminate this port — it goes straight to the
# container.  Operators who want TLS on the S3 endpoint should
# either front it themselves with their own reverse proxy or
# drop a cert into $CERTS_DIR and set MINIO_OPTS to enable it.
export MINIO_SERVER_URL="http://${ZONE_DOMAIN}:${S3_API_HOST_PORT}"

# Loopback bind for the console.  Auth-proxy is the only thing
# allowed to reach it.  MinIO's own auth (the root user / per-
# user IAM logins) still applies — the proxy only adds the
# zone-owner gate ON TOP of MinIO's auth, it doesn't replace it.
# So a successfully-SSO'd visitor still has to log into MinIO
# with the root credentials (or any user account they've
# created) to do anything in the console.
MINIO_CONSOLE_BIND="${MINIO_CONSOLE_BIND:-127.0.0.1:9001}"

# -----------------------------------------------------------------
# Launch MinIO
# -----------------------------------------------------------------

echo "[start.sh] Starting MinIO server (data=$DATA_DIR, console=$MINIO_CONSOLE_BIND)"
minio server "$DATA_DIR" \
    --config-dir "$CONFIG_DIR" \
    --certs-dir "$CERTS_DIR" \
    --address ":9000" \
    --console-address "$MINIO_CONSOLE_BIND" &
MINIO_PID=$!

# Wait for MinIO to bind both ports before launching the proxy,
# so the proxy's first probe doesn't get connection-refused.
# We poll the console port (the one the proxy actually talks to)
# rather than the S3 port — they come up together but checking
# the console one is more relevant.
CONSOLE_PORT="${MINIO_CONSOLE_BIND##*:}"
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    if python3 -c "
import socket, sys
s = socket.socket()
s.settimeout(0.5)
sys.exit(0 if s.connect_ex(('127.0.0.1', $CONSOLE_PORT)) == 0 else 1)
" 2>/dev/null; then
        break
    fi
    if ! kill -0 "$MINIO_PID" 2>/dev/null; then
        wait "$MINIO_PID" || true
        echo "[start.sh] MinIO exited before binding"
        exit 1
    fi
    sleep 1
done

# -----------------------------------------------------------------
# Launch auth-proxy sidecar
# -----------------------------------------------------------------

echo "[start.sh] Starting auth-proxy on 0.0.0.0:${AUTH_PROXY_LISTEN_PORT:-9090}"
export AUTH_PROXY_UPSTREAM_HOST="127.0.0.1"
export AUTH_PROXY_UPSTREAM_PORT="$CONSOLE_PORT"
export AUTH_PROXY_LISTEN_PORT="${AUTH_PROXY_LISTEN_PORT:-9090}"
/opt/auth-venv/bin/python3 /opt/openhost-minio/auth_proxy.py &
PROXY_PID=$!

# -----------------------------------------------------------------
# Supervision
# -----------------------------------------------------------------

# Forward signals so a stop request reaches MinIO cleanly (it
# flushes in-memory metadata to disk on SIGTERM).
trap 'kill -TERM "$MINIO_PID" "$PROXY_PID" 2>/dev/null; wait' TERM INT

# Block until either child exits, then tear down the survivor.
# `wait -n` is bash-only; see openhost-syncthing's start.sh for
# the same pattern + reasoning.
set +e
wait -n "$MINIO_PID" "$PROXY_PID"
EXIT_CODE=$?
set -e

echo "[start.sh] Child exited (code=$EXIT_CODE); shutting down"
kill -TERM "$MINIO_PID" "$PROXY_PID" 2>/dev/null || true
wait || true
exit "$EXIT_CODE"
