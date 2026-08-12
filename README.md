# bottled-minio

[MinIO](https://min.io) — S3-compatible object storage — packaged for Cloud in a Bottle.

Use this when you want a generic blob backend on your zone that any S3 client (`aws-cli`, `rclone`, `mc`, `s3cmd`, language SDKs) can push to and pull from. Cryfs / borg / restic / kopia / git-annex backups, photo dumps, build artifacts, machine-learning checkpoints — anything you'd put in S3.

## What you get when you deploy this

- **Web console** at `https://minio.<your-zone>/`. Gated by Cloud in a Bottle zone-owner SSO. Beyond the SSO gate you log into MinIO with the auto-generated root credentials (recoverable from inside the container — see "First-boot credentials" below).
- **S3 API** at `<your-zone>:9106` (the `[[ports]]` published port from `openhost.toml`). Authenticated with MinIO access keys you generate yourself in the console. Anyone with a valid access key + secret can use the API; the SSO gate is NOT in this path.
- **Persistent storage** under `$OPENHOST_APP_DATA_DIR/` (in-container: `/data/app_data/minio/`). Object data, IAM policies, and root credentials all live here. The same files show up on the Cloud in a Bottle host under the persistent app_data dir.

## Quick start

After the app is deployed:

```sh
# 1. Sign into the console.
open https://minio.<your-zone>/
# OpenHost SSO gates you first.  After SSO, the auth-proxy
# auto-logs you into MinIO as root using the on-disk credentials —
# you should land in the console with no second password prompt.

# 2. Create an access key + secret for your laptop.
# In the console: Identity → Access Keys → Create access key. Copy
# both halves; the secret is only shown once.

# 3. Point an S3 client at the API.  No TLS by default on the
#    published port — the outer zone Caddy doesn't front this port.
mc alias set zone http://<your-zone>:9106 <access-key> <secret>
mc mb zone/backup
mc cp -r /local/cryfs/ zone/backup/cryfs/
```

If for some reason auto-login doesn't fire (auth-proxy down, credentials file missing, etc.), the worst-case UX is that you see MinIO's own login form. Recover the root credentials from the container:

```sh
podman exec bottled-minio cat /data/app_data/minio/config/root-credentials.txt
```

Then sign in manually. Once that succeeds, the cookie is set and subsequent visits work whether or not the auth-proxy auto-login path runs.

The S3 API host port (`9106`) is set in `openhost.toml`'s `[[ports]]` block; if a different port is needed (e.g. it conflicts with another app on the host) the operator can override the `host_port` value before deploy.

## How auto-login works

When you visit `https://minio.<zone>/` after signing into Cloud in a Bottle, you don't see MinIO's login form — you're dropped straight into the console as `root`. This works in three layers:

1. **Cloud in a Bottle router** verifies your `zone_auth` cookie. If valid (`sub == "owner"`), it stamps `X-OpenHost-Is-Owner: true` on the request and forwards to the auth-proxy. If absent or invalid, it 302's you to Cloud in a Bottle's `/login`.
2. **`auth_proxy.py` sidecar** (container port 9090) reads `X-OpenHost-Is-Owner`. If true AND your browser doesn't yet have a MinIO `token` cookie, the proxy POSTs the on-disk root credentials to MinIO's `/api/v1/login` endpoint, captures the resulting `Set-Cookie`, and sends a 302 back to your original URL with the cookie attached. Subsequent requests carry the cookie and proxy through normally.
3. **MinIO console** authenticates every request via its `token` cookie. We never disable MinIO's own auth — it's a defense-in-depth layer below the Cloud in a Bottle gate.

This mirrors the pattern used in `bottled-plane.so`'s `openhost_auth.py`: the Cloud in a Bottle router stamps a per-request owner-trust header, and the app's sidecar uses it as the trigger to mint an in-app session. The difference is that MinIO has a documented `/api/v1/login` endpoint that mints sessions for us, so we don't need to forge anything by hand.

**Anyone other than the zone owner who tries to reach the console gets 302'd to Cloud in a Bottle login at the router layer; they never reach the auth-proxy.** The sidecar additionally strips any client-supplied `X-OpenHost-Is-Owner` / `X-OpenHost-User` headers as defense-in-depth, in case a future router bug or path misconfiguration ever lets an unverified value through.

The S3 API on container port `9000` (host port `9106`) is reachable directly without going through the auth-proxy. It uses MinIO's own access-key auth — the right primitive for non-browser clients, since `aws s3 cp` cannot do an SSO redirect dance.

## First-boot credentials

The first time the container starts, `start.sh` notices there are no MinIO root credentials and generates a fresh pair:

- `MINIO_ROOT_USER`: `openhost-` plus 8 random alphanumeric characters.
- `MINIO_ROOT_PASSWORD`: 32 random alphanumeric characters.

Both are written to `$OPENHOST_APP_DATA_DIR/config/root-credentials.txt` with mode `0600`. Subsequent boots read this file and re-export the same values, so the root credentials are stable across restarts.

To rotate: stop the app, delete `root-credentials.txt`, start again. New credentials are generated; you'll need to update any scripts holding the old root password (per-user access keys you generated through the console are unaffected).

You can also override at deploy time via env vars: if `MINIO_ROOT_USER` / `MINIO_ROOT_PASSWORD` are present in the container's environment, `start.sh` uses those and never writes the on-disk file.

## Configuration

| Env var                   | Purpose                                                      | Default                                       |
| ------------------------- | ------------------------------------------------------------ | --------------------------------------------- |
| `OPENHOST_APP_DATA_DIR`     | Persistent data dir; injected by compute_space at boot.      | `/data/app_data/minio`                        |
| `OPENHOST_ZONE_DOMAIN`      | Zone domain; injected. Used to derive `MINIO_BROWSER_REDIRECT_URL`. | `localhost`                                   |
| `OPENHOST_APP_NAME`         | App name; injected. Forms the canonical console URL `https://<app-name>.<zone-domain>/`. | `minio`                                       |
| `MINIO_ROOT_USER`           | Override the auto-generated root user.                       | auto                                          |
| `MINIO_ROOT_PASSWORD`       | Override the auto-generated root password.                   | auto                                          |
| `AUTH_PROXY_LISTEN_PORT`    | Port the auth-proxy sidecar listens on.                      | `9090`                                        |
| `AUTH_PROXY_UPSTREAM_PORT`  | Port MinIO's console binds (loopback inside container).      | `9001`                                        |
| `AUTH_PROXY_CRED_FILE`      | Path to start.sh's persisted root credentials file.          | `$OPENHOST_APP_DATA_DIR/config/root-credentials.txt` |

In a default deploy you don't have to set any of these; sensible values come out of `start.sh` and `openhost.toml`.

## What this app is not

- **It is not a CDN.** MinIO can serve objects publicly via bucket policy, but the default deploy is private; objects are reachable only with an access key. If you want public buckets, configure them yourself in the console.
- **It is not multi-tenant.** The Cloud in a Bottle SSO gate sees one principal (the zone owner). Any number of S3 access keys can exist for non-browser clients, but the console is single-operator.
- **It is not a sync daemon.** Use `rclone` or similar to push changes; this is a request/response object store, not a continuous-sync system. (See `bottled-syncthing` if you want continuous file sync.)
- **It is not high-availability.** Single-instance MinIO. Sufficient for personal/zone-scale workloads; not appropriate as the primary S3 backend for a customer-facing service.

## Troubleshooting

- **You see MinIO's login form instead of being auto-logged in**: the auth-proxy didn't manage to mint a session. Check `podman logs bottled-minio` for `auto-login:` lines. Common causes: credentials file missing or unreadable (`/data/app_data/minio/config/root-credentials.txt` inside the container), MinIO not yet ready when the visit landed (wait ten seconds and retry), or upstream MinIO returning a non-2xx to `/api/v1/login` (which would indicate an internal MinIO problem). The fall-through behavior is intentional — manual login from the form using the on-disk credentials always works as a backup.
- **Auto-login redirect loop**: the browser keeps following 302's back to `/`. Almost always means MinIO's `/api/v1/login` returned a 2xx but the cookie didn't get set on the browser (cookie-domain mismatch, `Secure` flag while accessed over HTTP, etc.). Inspect the `Set-Cookie` header on the redirect response in dev tools.
- **`mc` / `aws s3` connection refused on the API port**: confirm the `[[ports]]` entry in `openhost.toml` actually published the host port. `oh app status minio` from the operator side should show the mapping. The S3 API URL is `http://<zone>:9106` (no TLS by default).
- **403 on `/manifest.json` or other SPA self-fetches**: this used to be caused by `MINIO_BROWSER_REDIRECT_URL` being set to a different URL than the browser was on. `start.sh` now derives it from `OPENHOST_APP_NAME` + `OPENHOST_ZONE_DOMAIN` to match the canonical subdomain — if you override either env var, make sure both still produce the URL the browser will actually be on.

## Updating

Standard Cloud in a Bottle reload-with-update flow rebuilds the image (which pulls the latest `minio/minio` from upstream) and restarts the container. Object data on disk is preserved across rebuilds.
