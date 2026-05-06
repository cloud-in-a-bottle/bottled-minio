# openhost-minio

[MinIO](https://min.io) — S3-compatible object storage — packaged for OpenHost.

Use this when you want a generic blob backend on your zone that any S3 client (`aws-cli`, `rclone`, `mc`, `s3cmd`, language SDKs) can push to and pull from. Cryfs / borg / restic / kopia / git-annex backups, photo dumps, build artifacts, machine-learning checkpoints — anything you'd put in S3.

## What you get when you deploy this

- **Web console** at `https://minio.<your-zone>/`. Gated by OpenHost zone-owner SSO. Beyond the SSO gate you log into MinIO with the auto-generated root credentials (recoverable from inside the container — see "First-boot credentials" below).
- **S3 API** at `<your-zone>:9106` (the `[[ports]]` published port from `openhost.toml`). Authenticated with MinIO access keys you generate yourself in the console. Anyone with a valid access key + secret can use the API; the SSO gate is NOT in this path.
- **Persistent storage** under `$OPENHOST_APP_DATA_DIR/` (in-container: `/data/app_data/minio/`). Object data, IAM policies, and root credentials all live here. The same files show up on the OpenHost host under the persistent app_data dir.

## Quick start

After the app is deployed:

```sh
# 1. Recover the root password from inside the container (run on the
#    OpenHost host that's running this app):
podman exec openhost-minio cat /data/app_data/minio/config/root-credentials.txt

# Output (substitute your own zone path / instance prefix as needed):
# export MINIO_ROOT_USER='openhost-XXXXXXXX'
# export MINIO_ROOT_PASSWORD='YYYY...'

# 2. Sign into the console.
open https://minio.<your-zone>/
# OpenHost SSO will gate you first; once through, log in with the
# user/password from step 1.

# 3. Create an access key + secret for your laptop.
# In the console: Identity → Access Keys → Create access key. Copy
# both halves; the secret is only shown once.

# 4. Point an S3 client at the API.  No TLS by default on the
#    published port — the outer zone Caddy doesn't front this port.
mc alias set zone http://<your-zone>:9106 <access-key> <secret>
mc mb zone/backup
mc cp -r /local/cryfs/ zone/backup/cryfs/
```

The S3 API host port (`9106`) is set in `openhost.toml`'s `[[ports]]` block; if a different port is needed (e.g. it conflicts with another app on the host) the operator can override the `host_port` value before deploy.

## How the SSO gate works

There is **no auth-proxy sidecar in this app**. Authentication is enforced one layer up by the OpenHost router itself: every request to `https://minio.<zone>/...` (the canonical subdomain form OpenHost uses for app URLs) is checked against the visitor's `zone_auth` cookie before the router decides whether to forward it to the container.

- **No cookie / invalid cookie** → router 302-redirects to `https://<zone>/login`. After SSO completes the cookie is set on `Domain=<zone>` (valid for subdomains too); revisiting `https://minio.<zone>/` then routes through to MinIO's own login form.
- **Valid owner cookie** → router forwards the request straight to MinIO's console on container port 9001.

This pattern is simpler than what `openhost-syncthing` / `openhost-nextcloud` / `openhost-peertube` use, all of which run an auth-proxy sidecar. The sidecar is unnecessary here because:

- MinIO has its own login UI (so a 403 on missing cookie would be a worse UX than letting the OpenHost router do its standard login redirect).
- MinIO's S3 API lives on a different port (the `[[ports]]` mapping below), so we don't have nextcloud's "native sync clients sharing the browser port" problem.
- MinIO doesn't federate, so we don't have peertube's "anonymous viewers must reach the browser port" problem.

The S3 API on container port `9000` (host port `9106`) is reachable directly without going through the OpenHost router. It uses MinIO's own access-key auth, which is the right primitive for non-browser clients — `aws s3 cp` cannot do an OpenHost SSO redirect dance.

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
| `OPENHOST_APP_NAME`       | App name; injected. Forms the canonical console URL `https://<app-name>.<zone-domain>/`. | `minio`                                       |
| `MINIO_ROOT_USER`         | Override the auto-generated root user.                       | auto                                          |
| `MINIO_ROOT_PASSWORD`     | Override the auto-generated root password.                   | auto                                          |
| `MINIO_S3_API_HOST_PORT`  | Used to compose `MINIO_SERVER_URL`. Should match the host port mapped to container 9000 in `openhost.toml`. | `9106`                                        |

In a default deploy you don't have to set any of these; sensible values come out of `start.sh` and `openhost.toml`.

## What this app is not

- **It is not a CDN.** MinIO can serve objects publicly via bucket policy, but the default deploy is private; objects are reachable only with an access key. If you want public buckets, configure them yourself in the console.
- **It is not multi-tenant.** The OpenHost SSO gate sees one principal (the zone owner). Any number of S3 access keys can exist for non-browser clients, but the console is single-operator.
- **It is not a sync daemon.** Use `rclone` or similar to push changes; this is a request/response object store, not a continuous-sync system. (See `openhost-syncthing` if you want continuous file sync.)
- **It is not high-availability.** Single-instance MinIO. Sufficient for personal/zone-scale workloads; not appropriate as the primary S3 backend for a customer-facing service.

## Troubleshooting

- **Console redirects to `http://127.0.0.1` and breaks**: `MINIO_BROWSER_REDIRECT_URL` did not get set correctly. Check that `OPENHOST_ZONE_DOMAIN` is in the container's environment and that `start.sh` set the export.
- **`mc` / `aws s3` connection refused on the API port**: confirm the `[[ports]]` entry in `openhost.toml` actually published the host port. `oh app status minio` from the operator side should show the mapping. The S3 API URL is `http://<zone>:9106` (no TLS by default).
- **Stuck at the OpenHost login page when visiting `https://minio.<zone>/`**: sign in to OpenHost first, then revisit. The router 302's unauthenticated visitors to `/login`; coming back to `https://minio.<zone>/` after the cookie is set should land you at MinIO's own login form.
- **403 on `/manifest.json` or other SPA self-fetches**: confirms `MINIO_BROWSER_REDIRECT_URL` is set to the wrong URL. The SPA loads from the URL the operator's browser is on (e.g. `https://minio.<zone>/`), and emits self-fetch URLs based on what `MINIO_BROWSER_REDIRECT_URL` was set to at startup. They must match. `start.sh` derives the correct URL from `OPENHOST_APP_NAME` + `OPENHOST_ZONE_DOMAIN`; if you've overridden either env var, make sure both still produce the canonical subdomain.

## Updating

Standard OpenHost reload-with-update flow rebuilds the image (which pulls the latest `minio/minio` from upstream) and restarts the container. Object data on disk is preserved across rebuilds.
