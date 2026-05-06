"""OpenHost auth proxy sidecar for the MinIO web console.

Sits between the OpenHost router and MinIO's console. Verifies the
visitor's `zone_auth` JWT cookie (signed by the OpenHost router with
RS256, published at /.well-known/jwks.json on the router) and only
forwards requests when the claim `sub == "owner"`.

Why a hard gate instead of a stamped header (forgejo/miniflux pattern)?
MinIO's web console operates against a self-contained user/IAM model
that is fully owned by whoever has the root credentials.  There is no
per-user mapping to do here — once the operator gets through the
SSO gate, they still need to log into MinIO with the root
credentials (or whatever IAM user they have created).  This proxy
therefore answers exactly one question: "is this the OpenHost zone
owner?"  Anyone else gets 403 before MinIO ever sees the request.

Critically, this proxy does NOT gate the S3 API.  The S3 API binds
on a separate port (9000 inside the container, published as a host
[[ports]] entry in openhost.toml) and is reachable directly without
going through this proxy.  S3 clients authenticate with access keys
the operator generates inside the console — i.e. the data plane has
its own auth that lives entirely inside MinIO and is unaffected by
the SSO gate on the console.

Two paths bypass the JWT check:

  * /minio/health/live   — MinIO's liveness probe (always 200 once
    the server is up).  The OpenHost router uses this for its own
    health_check and we let it through unauthenticated so a not-
    yet-logged-in zone reports healthy.
  * /minio/health/ready  — the "ready to serve traffic" probe; same
    rationale.

Every other path requires a valid owner JWT.

We strip any inbound `X-Openhost-User` header on every request as
defence-in-depth against future bugs / misconfigurations where a
public_paths setting + a downstream consumer of that header
combine into header injection.

Implementation is adapted from openhost-syncthing/auth_proxy.py
verbatim except for the upstream port (configurable via
AUTH_PROXY_UPSTREAM_PORT, defaulted to 9001 — MinIO's console
port) and the health-path whitelist.
"""

from __future__ import annotations

import http.client
import logging
import os
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import AbstractSet, Iterable

import jwt
import requests

AUTH_HEADER_NAME = "X-Openhost-User"
ZONE_COOKIE = "zone_auth"
JWKS_PATH = "/.well-known/jwks.json"
JWKS_REFRESH_INTERVAL_SEC = 600  # 10 minutes
# Paths that are forwarded without a JWT check.  We match strictly
# with `==` (or `==` followed by a `?...` query string) — never
# prefix-match — to avoid an attacker hiding a sensitive endpoint
# behind a benign-looking prefix (e.g. /minio/health/live/../admin).
# These are the only two MinIO console paths intentionally exposed
# without auth; both return tiny static JSON status documents.
HEALTH_PATHS = ("/minio/health/live", "/minio/health/ready")

# Headers that must not be forwarded hop-by-hop (RFC 7230 §6.1).
HOP_BY_HOP_HEADERS = frozenset(
    h.lower()
    for h in (
        "Connection",
        "Keep-Alive",
        "Proxy-Authenticate",
        "Proxy-Authorization",
        "TE",
        "Trailer",
        "Transfer-Encoding",
        "Upgrade",
        # Host is dropped from the inbound request; _proxy() rewrites
        # it explicitly from X-Forwarded-Host below.
        "Host",
    )
)

logging.basicConfig(
    level=os.environ.get("AUTH_PROXY_LOG_LEVEL", "INFO"),
    format="[auth-proxy] %(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("auth_proxy")


class JwksCache:
    """Fetches the OpenHost router's JWKS and caches it with stale fallback.

    On a successful fetch the keys are cached for JWKS_REFRESH_INTERVAL_SEC;
    on a failed refresh we keep serving previously-cached keys so a
    transient router outage doesn't lock the owner out. Same shape as
    openhost-miniflux's cache (see that file for reasoning on the
    two-lock pattern).
    """

    def __init__(self, router_url: str) -> None:
        self._router_url = router_url.rstrip("/")
        self._keys: list = []
        self._fetched_at: float = 0.0
        self._cache_lock = threading.Lock()
        self._fetch_lock = threading.Lock()

    def _fetch(self) -> list:
        url = f"{self._router_url}{JWKS_PATH}"
        with requests.get(url, timeout=5) as resp:
            resp.raise_for_status()
            jwks = resp.json()
        keys = []
        skipped = 0
        for jwk in jwks.get("keys", []):
            try:
                key = jwt.algorithms.RSAAlgorithm.from_jwk(jwk)
            except Exception as exc:  # noqa: BLE001
                skipped += 1
                kid = jwk.get("kid") if isinstance(jwk, dict) else None
                log.warning("skipping malformed JWK (kid=%s): %s", kid, exc)
                continue
            keys.append(key)
        if not keys:
            raise RuntimeError(
                f"router JWKS contains no usable keys (skipped {skipped})"
            )
        return keys

    def get(self) -> list:
        with self._cache_lock:
            cached_keys = self._keys
            cached_at = self._fetched_at
        if cached_keys and (time.time() - cached_at) < JWKS_REFRESH_INTERVAL_SEC:
            return cached_keys

        with self._fetch_lock:
            with self._cache_lock:
                cached_keys = self._keys
                cached_at = self._fetched_at
            if cached_keys and (time.time() - cached_at) < JWKS_REFRESH_INTERVAL_SEC:
                return cached_keys

            try:
                keys = self._fetch()
            except Exception as exc:  # noqa: BLE001 - log+fallback
                if cached_keys:
                    log.warning(
                        "JWKS refresh failed, using cached keys: %s", exc
                    )
                    return cached_keys
                log.warning("JWKS fetch failed and no cache: %s", exc)
                raise

            with self._cache_lock:
                self._keys = keys
                self._fetched_at = time.time()
            log.info("refreshed JWKS (%d key(s))", len(keys))
            return keys

    def prefetch(self) -> None:
        try:
            self.get()
        except Exception as exc:  # noqa: BLE001
            log.warning("initial JWKS prefetch failed (will retry on demand): %s", exc)


def _parse_cookie_header(cookie_header: str | None) -> dict[str, str]:
    """Parse an RFC6265 Cookie header into a {name: value} dict.

    Uses first-value-wins semantics for duplicate cookie names. See
    openhost-miniflux's auth_proxy.py for the full rationale (TL;DR:
    matches browser ordering and prevents trivial duplicate-cookie DoS).
    """
    if not cookie_header:
        return {}
    result: dict[str, str] = {}
    for part in cookie_header.split(";"):
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        result.setdefault(name.strip(), value.strip())
    return result


def _verify_owner(token: str, jwks: JwksCache) -> bool:
    """Return True if the JWT is a valid router-signed owner token."""
    if not token:
        return False
    try:
        keys = jwks.get()
    except Exception as exc:  # noqa: BLE001
        log.warning("JWKS unavailable; denying owner check: %s", exc)
        return False

    for key in keys:
        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                options={
                    "require": ["exp"],
                    "verify_aud": False,
                },
            )
        except jwt.PyJWTError:
            continue
        if claims.get("sub") == "owner":
            return True
    return False


def _strip_headers(
    headers: Iterable[tuple[str, str]], drop: AbstractSet[str]
) -> list[tuple[str, str]]:
    drop_lower = {h.lower() for h in drop}
    return [(k, v) for k, v in headers if k.lower() not in drop_lower]


def _is_health_path(path: str) -> bool:
    """Return True iff the request path is a router health probe.

    We accept either an exact match on the canonical path, or the
    canonical path followed by a `?` query string. We deliberately
    do NOT accept prefix matches (e.g. /minio/health/live/foo or
    /minio/health/livecheck) — accepting prefixes here would be a
    footgun if a future MinIO release adds an authenticated
    endpoint at a sibling path like /minio/health/live-detailed.
    """
    for canonical in HEALTH_PATHS:
        if path == canonical or path.startswith(canonical + "?"):
            return True
    return False


class AuthProxyHandler(BaseHTTPRequestHandler):
    # Set by main() before the server starts.
    jwks: JwksCache | None = None
    upstream_host: str = "127.0.0.1"
    upstream_port: int = 9001

    def log_message(self, format: str, *args) -> None:  # noqa: A002, N802
        # Suppress logs for health-check probes — at OpenHost's ~1
        # probe/sec rate they'd otherwise drown the actual request log.
        path = getattr(self, "path", "")
        if _is_health_path(path):
            return
        log.info("%s - " + format, self.address_string(), *args)

    def do_GET(self) -> None:  # noqa: N802
        self._proxy()

    def do_HEAD(self) -> None:  # noqa: N802
        self._proxy()

    def do_POST(self) -> None:  # noqa: N802
        self._proxy()

    def do_PUT(self) -> None:  # noqa: N802
        self._proxy()

    def do_DELETE(self) -> None:  # noqa: N802
        self._proxy()

    def do_PATCH(self) -> None:  # noqa: N802
        self._proxy()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._proxy()

    # 64 MiB body cap. The MinIO console's biggest legitimate POST is
    # an IAM policy upload, which is a small JSON document well under
    # a MiB. The cap mainly bounds RAM exposure if a buggy/hostile
    # client sends `Content-Length: 2147483647`. Note: this proxy is
    # ONLY in front of the console; bulk object uploads go through the
    # S3 API on a separate port and don't traverse this code path.
    MAX_BODY_BYTES = 64 * 1024 * 1024

    # Read timeout on the inbound socket so a slow-loris client can't
    # hold a thread forever.
    CLIENT_READ_TIMEOUT_SECONDS = 60

    def _safe_send_error(self, code: int, message: str) -> None:
        try:
            self.send_error(code, message)
        except OSError as exc:
            log.debug("client disconnected before error response: %s", exc)

    def _proxy(self) -> None:
        try:
            self.connection.settimeout(self.CLIENT_READ_TIMEOUT_SECONDS)
        except OSError:
            pass

        # Strip the auth header (never trust client-supplied), hop-by-hop
        # headers, and Content-Length (we rebuild it from the buffered body).
        cleaned_headers = _strip_headers(
            self.headers.items(),
            HOP_BY_HOP_HEADERS | {AUTH_HEADER_NAME.lower(), "content-length"},
        )

        # Rewrite Host from X-Forwarded-Host. The OpenHost router
        # strips the original Host and puts the user's real hostname
        # into X-Forwarded-Host. MinIO's console reads the Host header
        # to compose redirect URLs and to validate browser callbacks,
        # so passing the real public hostname through is essential —
        # without this, the console redirects browsers to the proxy's
        # 127.0.0.1 and the page breaks.
        forwarded_host = self.headers.get("X-Forwarded-Host")
        explicit_host_set = False
        if forwarded_host:
            cleaned_headers.append(("Host", forwarded_host))
            explicit_host_set = True

        # Auth gate. A request is allowed through if either:
        #   1. The path is a router liveness probe (the only JWT
        #      bypass — see HEALTH_PATHS), or
        #   2. The cookie verifies as a valid owner JWT.
        # Anything else → 403.
        path_for_check = self.path or ""
        is_health = _is_health_path(path_for_check)

        if not is_health:
            if self.jwks is None:
                log.error("auth-proxy JWKS not initialised; refusing request")
                self._safe_send_error(503, "auth-proxy not initialised")
                return
            cookies = _parse_cookie_header(self.headers.get("Cookie"))
            token = cookies.get(ZONE_COOKIE, "")
            if not _verify_owner(token, self.jwks):
                # 403 not 401: a 401 invites the browser to pop a basic-
                # auth dialog, but our auth flow is the OpenHost
                # zone_auth cookie, not basic auth. Returning 403 is
                # consistent with the router's own behaviour for
                # unauthenticated requests on protected paths.
                self._safe_send_error(403, "Forbidden")
                return

        # Reject chunked / non-identity transfer encoding. The OpenHost
        # router (httpx) already de-chunks before reaching us; receiving
        # a chunked body here would mean either the router did not
        # de-chunk (bug) or someone is bypassing it.
        transfer_encoding = self.headers.get("Transfer-Encoding", "").lower().strip()
        if transfer_encoding and transfer_encoding != "identity":
            self._safe_send_error(501, "Transfer-Encoding not supported")
            return

        body: bytes | None = None
        content_length_header = self.headers.get("Content-Length")
        if content_length_header:
            try:
                length = int(content_length_header)
            except ValueError:
                self._safe_send_error(400, "invalid Content-Length")
                return
            if length < 0:
                self._safe_send_error(400, "negative Content-Length")
                return
            if length > self.MAX_BODY_BYTES:
                self._safe_send_error(413, "request body too large")
                return
            if length > 0:
                try:
                    body = self.rfile.read(length)
                except (OSError, TimeoutError) as exc:
                    log.info("client read error: %s", exc)
                    self._safe_send_error(400, "request body read failed")
                    return
                if len(body) != length:
                    log.info(
                        "short read: expected %d bytes, got %d",
                        length,
                        len(body),
                    )
                    self._safe_send_error(400, "incomplete request body")
                    return
            else:
                body = b""
        elif self.command in ("POST", "PUT", "PATCH", "DELETE"):
            # Body method with no Content-Length / Transfer-Encoding —
            # treat as empty body rather than blocking on EOF.
            body = b""

        conn = http.client.HTTPConnection(
            self.upstream_host, self.upstream_port, timeout=60
        )
        try:
            try:
                conn.putrequest(
                    self.command,
                    self.path,
                    skip_host=explicit_host_set,
                    skip_accept_encoding=True,
                )
                for key, value in cleaned_headers:
                    conn.putheader(key, value)
                if body is not None:
                    conn.putheader("Content-Length", str(len(body)))
                conn.endheaders(message_body=body)
                upstream = conn.getresponse()
            except (OSError, http.client.HTTPException) as exc:
                log.warning("upstream error: %s", exc)
                self._safe_send_error(502, "Bad Gateway")
                return

            try:
                payload = upstream.read(self.MAX_BODY_BYTES + 1)
            except (OSError, http.client.HTTPException) as exc:
                log.warning("upstream read error: %s", exc)
                self._safe_send_error(502, "Bad Gateway")
                try:
                    upstream.close()
                except Exception as close_exc:  # noqa: BLE001 - best effort
                    log.debug("upstream.close() after read error raised: %s", close_exc)
                return
            try:
                upstream.close()
            except Exception as exc:  # noqa: BLE001 - best effort only
                log.debug("upstream.close() raised (ignored): %s", exc)
            if len(payload) > self.MAX_BODY_BYTES:
                log.warning(
                    "upstream response exceeded %d bytes; returning 502",
                    self.MAX_BODY_BYTES,
                )
                self._safe_send_error(502, "upstream response too large")
                return

            reason = upstream.reason or ""
            try:
                self.send_response(upstream.status, reason)
                for key, value in upstream.getheaders():
                    if key.lower() in HOP_BY_HOP_HEADERS:
                        continue
                    self.send_header(key, value)
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(payload)
            except OSError as exc:
                log.debug("client disconnected mid-response: %s", exc)
        finally:
            conn.close()


class IPv4ThreadingServer(ThreadingHTTPServer):
    address_family = socket.AF_INET
    allow_reuse_address = True
    daemon_threads = True


def _port_from_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        port = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name}={raw!r} is not an integer: {exc}") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"{name}={raw!r} is out of range (1-65535)")
    return port


def main() -> int:
    router_url = os.environ.get("OPENHOST_ROUTER_URL", "").strip()
    if not router_url:
        log.error("OPENHOST_ROUTER_URL is not set; refusing to start")
        return 1

    try:
        listen_port = _port_from_env("AUTH_PROXY_LISTEN_PORT", 9090)
        upstream_port = _port_from_env("AUTH_PROXY_UPSTREAM_PORT", 9001)
    except ValueError as exc:
        log.error("invalid port configuration: %s", exc)
        return 1

    upstream_host = os.environ.get("AUTH_PROXY_UPSTREAM_HOST", "127.0.0.1").strip()

    jwks = JwksCache(router_url)
    jwks.prefetch()

    AuthProxyHandler.jwks = jwks
    AuthProxyHandler.upstream_host = upstream_host
    AuthProxyHandler.upstream_port = upstream_port

    try:
        server = IPv4ThreadingServer(("0.0.0.0", listen_port), AuthProxyHandler)
    except OSError as exc:
        log.error(
            "failed to bind auth-proxy listener on 0.0.0.0:%d: %s",
            listen_port,
            exc,
        )
        return 1
    log.info(
        "listening on 0.0.0.0:%d -> %s:%d (router=%s)",
        listen_port,
        upstream_host,
        upstream_port,
        router_url,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

