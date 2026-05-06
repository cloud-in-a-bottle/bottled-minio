# openhost-minio

[MinIO](https://min.io) — S3-compatible object storage — packaged for OpenHost.

Use this when you want a generic blob backend on your zone that any S3 client (`aws-cli`, `rclone`, `mc`, `s3cmd`, language SDKs) can push to and pull from. Cryfs / borg / restic / kopia / git-annex backups, photo dumps, build artifacts, machine-learning checkpoints — anything you'd put in S3.

## What you get when you deploy this

- **Web console** at `https://<your-zone>/minio`. Gated by OpenHost zone-owner SSO. Beyond the SSO gate you log into MinIO with the auto-generated root credentials (recoverable from inside the container — see "First-boot credentials" below).
- **S3 API** at `<your-zone>:9106` (the `[[ports]]` published port from `openhost.toml`). Authenticated with MinIO access keys you generate yourself in the console. Anyone with a valid access key + secret can use the API; the SSO gate is NOT in this path.
- **Persistent storage** under `$OPENHOST_APP_DATA_DIR/data/` (host-side: `/data/app_data/minio/data/`). Object data, IAM policies, and root credentials all live here.

## Quick start

After the app is deployed:

```sh
# 1. Recover the root password from inside the container.
oh app shell minio cat /data/config/root-credentials.txt

# Output:
# export MINIO_ROOT_USER='openhost-XXXXXXXX'
# export MINIO_ROOT_PASSWORD='YYYY...'

# 2. Sign into the console.
open https://<your-zone>/minio
# OpenHost SSO will gate you first; once through, log in with the
# user/password from step 1.

# 3. Create an access key + secret for your laptop.
# In the console: Identity → Access Keys → Create access key. Copy
# both halves; the secret is only shown once.

# 4. Point an S3 client at the API.
mc alias set zone https://<your-zone>:9106 <access-key> <secret>
mc mb zone/backup
mc cp -r /local/cryfs/ zone/backup/cryfs/
```

The S3 API host port (`9106`) is set in `openhost.toml`'s `[[ports]]` block; if a different port is needed (e.g. it conflicts with another app on the host) the operator can override the `host_port` value before deploy.

## How the SSO gate works

The console binds on loopback (`127.0.0.1:9001`) inside the container, where only the auth-proxy sidecar can reach it. The sidecar (`auth_proxy.py`) listens on `0.0.0.0:9090` — the OpenHost router routes browser traffic from `https://<zone>/minio` to that port. On every request the sidecar:

1. Whitelists `/minio/health/live` and `/minio/health/ready` for the OpenHost router's liveness probes.
2. For everything else, parses the `zone_auth` cookie, verifies it as an RS256 JWT against the OpenHost router's JWKS, and only forwards the request if `sub == "owner"`.
3. Failed verification → 403. Verified → request forwarded to MinIO with the original `Host` header preserved (so MinIO's redirect URLs come out right).

This is an exact copy of the `openhost-syncthing` auth-proxy pattern; the diff is the upstream port (9001 vs 8385) and the health-path whitelist.

The S3 API on port `9000` (host port `9106`) does NOT go through the auth-proxy. It uses MinIO's own access-key auth, which is the right primitive for non-browser clients — `aws s3 cp` cannot do an OpenHost SSO redirect dance.

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
| `OPENHOST_APP_DATA_DIR`   | Persistent data dir; injected by compute_space at boot.      | `/data/app_data/minio`                        |
| `OPENHOST_ZONE_DOMAIN`    | Zone domain; injected. Used to derive `MINIO_BROWSER_REDIRECT_URL` and `MINIO_SERVER_URL`. | `localhost`                                   |
| `OPENHOST_APP_BASE_PATH`  | Path-prefix the OpenHost router uses for this app.           | `/minio`                                      |
| `OPENHOST_ROUTER_URL`     | Internal URL used by the auth-proxy to fetch the JWKS.       | injected                                      |
| `MINIO_ROOT_USER`         | Override the auto-generated root user.                       | auto                                          |
| `MINIO_ROOT_PASSWORD`     | Override the auto-generated root password.                   | auto                                          |
| `MINIO_S3_API_HOST_PORT`  | Used to compose `MINIO_SERVER_URL`. Should match the host port mapped to container 9000 in `openhost.toml`. | `9106`                                        |
| `MINIO_CONSOLE_BIND`      | Loopback bind for the console (where the auth-proxy talks).  | `127.0.0.1:9001`                              |
| `AUTH_PROXY_LISTEN_PORT`  | Public port the auth-proxy listens on; this is the `port` in `openhost.toml`. | `9090`                                        |
| `AUTH_PROXY_UPSTREAM_PORT`| Where the auth-proxy forwards verified requests.             | `9001`                                        |

In a default deploy you don't have to set any of these; sensible values come out of `start.sh` and `openhost.toml`.

## What this app is not

- **It is not a CDN.** MinIO can serve objects publicly via bucket policy, but the default deploy is private; objects are reachable only with an access key. If you want public buckets, configure them yourself in the console.
- **It is not multi-tenant.** The OpenHost SSO gate sees one principal (the zone owner). Any number of S3 access keys can exist for non-browser clients, but the console is single-operator.
- **It is not a sync daemon.** Use `rclone` or similar to push changes; this is a request/response object store, not a continuous-sync system. (See `openhost-syncthing` if you want continuous file sync.)
- **It is not high-availability.** Single-instance MinIO. Sufficient for personal/zone-scale workloads; not appropriate as the primary S3 backend for a customer-facing service.

## Troubleshooting

- **Console redirects to `http://127.0.0.1` and breaks**: `MINIO_BROWSER_REDIRECT_URL` did not get set correctly. Check that `OPENHOST_ZONE_DOMAIN` is in the container's environment and that `start.sh` set the export.
- **`mc` / `aws s3` connection refused on the API port**: confirm the `[[ports]]` entry in `openhost.toml` actually published the host port. `oh app status minio` from the operator side should show the mapping. The S3 API URL is `http://<zone>:9106` (no TLS by default).
- **403 on every console request**: zone_auth cookie is not landing. Sign out of the OpenHost dashboard and back in, then revisit `https://<zone>/minio`.
- **`auth-proxy not initialised` 503**: the sidecar's first JWKS fetch failed and it has nothing cached. Usually means the OpenHost router is unreachable from the container; check `OPENHOST_ROUTER_URL` and confirm the router is up.

## Updating

Standard OpenHost reload-with-update flow rebuilds the image (which pulls the latest `minio/minio` from upstream) and restarts the container. Object data on disk is preserved across rebuilds.
