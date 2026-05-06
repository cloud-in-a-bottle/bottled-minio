#!/bin/bash
# Launch MinIO on OpenHost.
#
# Topology:
#
#   browser → OpenHost outer Caddy (TLS termination)
#          → OpenHost router (subdomain minio.<zone>, JWT-verifies
#                              and stamps X-OpenHost-Is-Owner)
#          → container :9090   (auth_proxy.py — auto-login sidecar)
#          → 127.0.0.1:9001    (MinIO console)
#
#   S3 client (aws-cli, rclone, mc, etc.) →
#          host_port 9106 (from openhost.toml [[ports]])
#          → container :9000   (MinIO S3 API)
#
# The console flow has THREE auth gates layered:
#
#   1. OpenHost router: anonymous visitors get 302'd to /login,
#      so we never see them.  Owners arrive with the
#      X-OpenHost-Is-Owner: true header stamped.
#   2. auth_proxy.py: if owner has no MinIO session yet, calls
#      MinIO's /api/v1/login with the root creds and sets the
#      session cookie via 302.
#   3. MinIO itself: authenticates every request via the session
#      cookie.  We never disable this — even if the auth-proxy
#      is bypassed somehow, MinIO still requires its own session.
#
# The S3 API is gated by MinIO's native access-key auth, which is
# the right primitive for non-browser clients — `aws s3 cp` cannot
# do an SSO redirect dance.  Per-client access keys are generated
# from inside the console after the operator signs in.
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

# The upstream minio/minio:latest image sets several `MINIO_..._FILE`
# env vars (MINIO_ROOT_USER_FILE, MINIO_ROOT_PASSWORD_FILE,
# MINIO_ACCESS_KEY_FILE, MINIO_SECRET_KEY_FILE, MINIO_KMS_SECRET_KEY_FILE,
# MINIO_CONFIG_ENV_FILE) intended for Docker-secret-style mount-a-file
# auth.  When BOTH the env var (e.g. MINIO_ROOT_USER) and its _FILE
# variant are set, MinIO behaves inconsistently and the console's
# /api/v1/login endpoint returns 503 "unable to login due to network
# error" — because the server-internal auth path picks up unresolved
# file paths while the env-var path is set.  We're providing the
# values directly via env vars (above), so unset the _FILE variants
# to avoid the conflict.
unset MINIO_ROOT_USER_FILE MINIO_ROOT_PASSWORD_FILE
unset MINIO_ACCESS_KEY_FILE MINIO_SECRET_KEY_FILE
unset MINIO_KMS_SECRET_KEY_FILE MINIO_CONFIG_ENV_FILE

# -----------------------------------------------------------------
# Console + API URL hints
# -----------------------------------------------------------------
#
# These two env vars tell MinIO what URLs to report to clients.
# Without them, the console emits redirect-back URLs based on
# whatever Host the proxy forwarded, which causes redirect loops
# and broken assets when the SPA's self-references don't match
# the URL the browser is on.  Setting them explicitly pins the
# console's self-referential URLs to the public hostname.
#
# OpenHost serves apps on a subdomain by default
# (``<app>.<zone-domain>``).  A path-prefixed form
# (``<zone-domain>/<app>``) is also routable but isn't the
# canonical URL, and pinning the console at the path-prefixed
# form caused exactly this kind of breakage when browsers
# loaded the SPA from the subdomain: manifest.json / API calls
# / OAuth redirects all targeted the wrong origin.
ZONE_DOMAIN="${OPENHOST_ZONE_DOMAIN:-localhost}"
APP_NAME="${OPENHOST_APP_NAME:-minio}"

# Console URL: where the browser hits the console.  Subdomain
# form (``minio.<zone-domain>``) is the canonical OpenHost URL
# for an app; the OpenHost router accepts both subdomain and
# path-prefix routes for the same app, but the subdomain is the
# one the dashboard links to.
export MINIO_BROWSER_REDIRECT_URL="https://${APP_NAME}.${ZONE_DOMAIN}"

# NOTE: we deliberately do NOT set MINIO_SERVER_URL.
#
# That env var has a dual role: (a) it advertises the public S3
# URL to the browser SPA for display, and (b) it's used by the
# console's internal auth path to call back to the server for
# credential validation.  The two roles want different values:
# (a) wants the public URL (http://<zone>:9106 in our setup), but
# (b) wants a loopback URL the container can actually reach
# (http://127.0.0.1:9000).  When set to the public URL, login
# returns 503 "unable to login due to network error" because
# rootless podman's network namespacing means the container
# cannot reach its own host's public-port binding.
#
# Leaving MINIO_SERVER_URL unset makes the console fall back to
# loopback for (b) and use the request's Host header for (a),
# which works cleanly.  The S3 API URL the operator should
# actually use (http://<zone>:9106) is documented in the README
# instead of being shown in the console.

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

echo "[start.sh] Starting MinIO server (data=$DATA_DIR, console=127.0.0.1:9001, api=:9000)"
minio server "$DATA_DIR" \
    --config-dir "$CONFIG_DIR" \
    --certs-dir "$CERTS_DIR" \
    --address ":9000" \
    --console-address "127.0.0.1:9001" &
MINIO_PID=$!

# Wait for the console port to bind before starting the
# auth-proxy.  The proxy will fail its first auto-login attempt
# if MinIO isn't accepting yet, and the failure surfaces as a
# bad-UX manual login form even though everything is otherwise
# healthy.  Polling the port is more reliable than a fixed
# sleep — under load the initial scan can take a few seconds.
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    if python3 -c "
import socket, sys
s = socket.socket()
s.settimeout(0.5)
sys.exit(0 if s.connect_ex(('127.0.0.1', 9001)) == 0 else 1)
" 2>/dev/null; then
        break
    fi
    if ! kill -0 "$MINIO_PID" 2>/dev/null; then
        wait "$MINIO_PID" || true
        echo "[start.sh] MinIO exited before binding the console port"
        exit 1
    fi
    sleep 1
done

# -----------------------------------------------------------------
# Launch auth-proxy sidecar
# -----------------------------------------------------------------

echo "[start.sh] Starting auth-proxy on 0.0.0.0:9090 -> 127.0.0.1:9001"
export AUTH_PROXY_LISTEN_PORT="${AUTH_PROXY_LISTEN_PORT:-9090}"
export AUTH_PROXY_UPSTREAM_HOST="127.0.0.1"
export AUTH_PROXY_UPSTREAM_PORT="9001"
export AUTH_PROXY_CRED_FILE="$CRED_FILE"
python3 /opt/openhost-minio/auth_proxy.py &
PROXY_PID=$!

# -----------------------------------------------------------------
# Supervision
# -----------------------------------------------------------------
#
# Forward signals so a stop request reaches MinIO cleanly (it
# flushes in-memory metadata to disk on SIGTERM).
trap 'kill -TERM "$MINIO_PID" "$PROXY_PID" 2>/dev/null; wait' TERM INT

# Block until either child exits, then tear down the survivor.
# `wait -n` is bash-only; same pattern as openhost-syncthing's
# start.sh.
set +e
wait -n "$MINIO_PID" "$PROXY_PID"
EXIT_CODE=$?
set -e

echo "[start.sh] Child exited (code=$EXIT_CODE); shutting down"
kill -TERM "$MINIO_PID" "$PROXY_PID" 2>/dev/null || true
wait || true
exit "$EXIT_CODE"
