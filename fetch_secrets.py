#!/usr/bin/env python3
"""Fetch MinIO root credentials from the OpenHost secrets service at boot.

OpenHost injects OPENHOST_APP_TOKEN (this app's identity) and OPENHOST_ROUTER_URL
(the router's service proxy) into every app container.  We call the secrets
service through the router's v2 proxy:

    POST $OPENHOST_ROUTER_URL/api/services/v2/call/secrets/get
        Authorization: Bearer $OPENHOST_APP_TOKEN
        {"keys": ["MINIO_ROOT_USER", "MINIO_ROOT_PASSWORD"]}
    -> {"secrets": {"MINIO_ROOT_USER": "...", "MINIO_ROOT_PASSWORD": "..."}}

The router authenticates us by our app token and stamps the permissions granted
by the ``[[services.v2.consumes]]`` block in openhost.toml; the secrets provider
returns only the keys we were granted.

On success we print shell-quoted ``export`` lines for start.sh to ``eval`` and
exit 0.  On any failure (service absent, no grant, keys unset, network error) we
exit non-zero and print nothing, so start.sh falls back to the on-disk file or
first-boot generation and MinIO still boots.
"""

from __future__ import annotations

import json
import os
import shlex
import sys
import time
import urllib.request

KEYS = ["MINIO_ROOT_USER", "MINIO_ROOT_PASSWORD"]
TIMEOUT_S = 5
# The secrets app is a builtin and usually already running, but it may be mid
# (re)start on a fresh zone; a few short retries smooth over that window without
# meaningfully delaying boot when the service is simply absent.
RETRIES = 3
RETRY_SLEEP_S = 1.0


def _fetch() -> dict[str, str]:
    token = os.environ["OPENHOST_APP_TOKEN"]
    base = os.environ["OPENHOST_ROUTER_URL"].rstrip("/")
    req = urllib.request.Request(
        f"{base}/api/services/v2/call/secrets/get",
        data=json.dumps({"keys": KEYS}).encode(),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
        body = json.load(resp)
    secrets = body.get("secrets") or {}
    return {k: secrets[k] for k in KEYS if secrets.get(k)}


def main() -> int:
    if not os.environ.get("OPENHOST_APP_TOKEN") or not os.environ.get("OPENHOST_ROUTER_URL"):
        return 3  # not running under OpenHost (or no service wiring) — use fallback
    creds: dict[str, str] = {}
    for attempt in range(RETRIES):
        try:
            creds = _fetch()
            break
        except Exception:  # noqa: BLE001 - any failure means "fall back", never fatal
            if attempt < RETRIES - 1:
                time.sleep(RETRY_SLEEP_S)
    if not all(creds.get(k) for k in KEYS):
        return 5  # secrets not set (or not granted, or unreachable) — use fallback
    for k in KEYS:
        print(f"export {k}={shlex.quote(creds[k])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
