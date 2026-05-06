"""OpenHost auto-login auth-proxy for MinIO.

Sits between the OpenHost router and MinIO's web console.  When an
authenticated zone owner visits the console for the first time on a
device, this proxy logs them in to MinIO automatically using the
on-disk root credentials and sets the resulting ``token`` cookie on
the browser.  After the cookie is set, the proxy is a near-pass-
through; subsequent requests carry the cookie and reach MinIO with
no further auth-proxy involvement.

This mirrors the openhost-plane.so pattern (see plane's
``openhost_auth.py``): the OpenHost router stamps
``X-OpenHost-Is-Owner: true`` on requests where the visitor's
``zone_auth`` JWT has been verified, and we use that header as the
trigger to mint an in-app session.  The difference is that MinIO
exposes a documented ``/api/v1/login`` endpoint that returns a
ready-made session cookie, so we don't have to forge a session by
direct DB writes the way plane does — we just call MinIO's own
login API on the user's behalf.

Auth model summary:

  * Anonymous (no zone_auth)        → OpenHost router 302's to /login
                                       BEFORE the request reaches us.
                                       We never see anonymous traffic.
  * Owner, has MinIO token cookie   → forward unchanged.
  * Owner, no MinIO token cookie    → call MinIO's /api/v1/login
                                       with root creds, capture the
                                       Set-Cookie, send a 302 to the
                                       same path with the cookie set.

Defense in depth: ALWAYS strip any client-supplied
``X-OpenHost-Is-Owner`` / ``X-OpenHost-User`` / etc. before
forwarding upstream.  The OpenHost router stamps the real value
fresh on every request, so any pre-existing instance of those
headers came from the client and is not to be trusted.

Implementation is adapted from openhost-syncthing/auth_proxy.py
(JWKS-style verification we don't actually need here since the
router already verified) and openhost-plane.so/openhost_auth.py
(the auto-login pattern).
"""

from __future__ import annotations

import http.client
import json
import logging
import os
import re
import selectors
import socket
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import AbstractSet, Iterable

# We deliberately do NOT verify the zone_auth JWT in this sidecar
# even though the syncthing pattern does.  Reasoning:
#
#   * The OpenHost router already verified it upstream of us
#     before stamping X-OpenHost-Is-Owner; re-verifying here
#     would duplicate the work and require us to ship PyJWT +
#     a JWKS cache for no incremental benefit.
#   * The router strips any client-supplied X-OpenHost-Is-Owner
#     before stamping its own, so we can trust the header at
#     face value.  We also strip it ourselves before forwarding
#     upstream, which closes the loop.
#
# This keeps the image dependency-free (no pip install) and
# matches plane's openhost_auth.py shape, which is also
# X-OpenHost-Is-Owner-trusting and JWT-blind.
OWNER_HEADER_NAME = "X-OpenHost-Is-Owner"
USER_HEADER_NAME = "X-OpenHost-User"
MINIO_TOKEN_COOKIE = "token"

# Hop-by-hop headers (RFC 9110 §7.6.1) plus a few entries we
# rewrite ourselves at the proxy seam.  Same list the syncthing
# sidecar uses; kept verbatim so the two stay in lockstep.
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
        "Host",
        "Content-Length",
    )
)

# Trust headers that a hostile client could try to forge.  ALWAYS
# stripped from inbound requests, even though the OpenHost router
# also strips client-supplied versions before stamping its own.
# Defense in depth: if the router ever has a bug or is bypassed,
# this layer catches forged identity injection too.
ALWAYS_STRIP_HEADERS = frozenset(
    h.lower() for h in (
        OWNER_HEADER_NAME,
        OWNER_HEADER_NAME.lower(),
        USER_HEADER_NAME,
        USER_HEADER_NAME.lower(),
    )
)

# Read timeout on the inbound socket so a slow-loris client can't
# hold a thread forever.
CLIENT_READ_TIMEOUT_SECONDS = 60

# 64 MiB body cap.  The MinIO console's biggest legitimate POST is
# an IAM policy upload, which is a small JSON document well under
# a MiB.  The cap mainly bounds RAM exposure if a buggy/hostile
# client sends Content-Length: 2147483647.  Bulk object uploads
# go through the S3 API on a separate port and don't traverse
# this code path.
MAX_BODY_BYTES = 64 * 1024 * 1024

# WebSocket bidirectional-forwarding constants.  MinIO's console
# uses a /ws/objectManager WebSocket for live object listing
# updates inside the bucket browser; without WS support the SPA
# spins forever trying to upgrade.  These constants are sized for
# WS traffic specifically (small chunks, long total session
# lifetime).
STREAM_CHUNK_BYTES = 64 * 1024
STREAM_TIMEOUT_SECONDS = 30 * 60
HEADER_LINE_CAP = 64 * 1024

# Path the MinIO console uses for credential exchange.  Empirically
# verified: POST {accessKey, secretKey} JSON returns 204 + a
# Set-Cookie: token=... that the SPA then uses for every subsequent
# call.  We hit this path on the auto-login codepath; see
# _maybe_auto_login.
MINIO_LOGIN_PATH = "/api/v1/login"

logging.basicConfig(
    level=os.environ.get("AUTH_PROXY_LOG_LEVEL", "INFO"),
    format="[auth-proxy] %(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("auth_proxy")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_cookie_header(cookie_header: str | None) -> dict[str, str]:
    """Parse an RFC6265 Cookie header into a {name: value} dict.

    Uses first-value-wins semantics for duplicate cookie names.  See
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


def _strip_headers(
    headers: Iterable[tuple[str, str]], drop: AbstractSet[str]
) -> list[tuple[str, str]]:
    drop_lower = {h.lower() for h in drop}
    return [(k, v) for k, v in headers if k.lower() not in drop_lower]


def _read_root_creds(cred_file: str) -> tuple[str, str] | None:
    """Read MINIO_ROOT_USER / MINIO_ROOT_PASSWORD from start.sh's
    on-disk credentials file.

    Format is two lines of ``export NAME='VALUE'`` written by start.sh
    on first boot.  We re-parse the file on every auto-login attempt
    so that an operator who rotates the credentials (delete the file,
    let start.sh regenerate) doesn't need to restart the sidecar.
    """
    try:
        with open(cred_file, encoding="utf-8") as fh:
            content = fh.read()
    except FileNotFoundError:
        return None
    user = password = None
    # Match `export NAME='VALUE'` and `export NAME="VALUE"` and bare
    # `NAME=VALUE`.  start.sh always writes single-quoted values, but
    # be permissive in case an operator hand-edits the file.
    for line in content.splitlines():
        m = re.match(r"^\s*(?:export\s+)?(MINIO_ROOT_USER|MINIO_ROOT_PASSWORD)\s*=\s*(.*?)\s*$", line)
        if not m:
            continue
        key, val = m.group(1), m.group(2)
        # Strip matching outer quotes if present.
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
            val = val[1:-1]
        if key == "MINIO_ROOT_USER":
            user = val
        elif key == "MINIO_ROOT_PASSWORD":
            password = val
    if user and password:
        return user, password
    return None


def _login_to_minio(
    upstream_host: str,
    upstream_port: int,
    user: str,
    password: str,
) -> str | None:
    """POST credentials to MinIO's /api/v1/login and return the
    Set-Cookie header value (the entire ``token=...; ...`` string,
    suitable for echoing on a 302 response back to the browser).

    Returns None on any failure — the auto-login attempt is
    best-effort; if it fails the proxy falls through to a normal
    request forward and the user sees MinIO's own login form.  This
    preserves the worst-case UX (manual login) when something is
    misconfigured upstream, rather than locking the operator out.
    """
    payload = json.dumps({"accessKey": user, "secretKey": password}).encode("utf-8")
    try:
        conn = http.client.HTTPConnection(upstream_host, upstream_port, timeout=10)
        conn.request(
            "POST",
            MINIO_LOGIN_PATH,
            body=payload,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(payload)),
            },
        )
        resp = conn.getresponse()
        # Consume the body so the connection is reusable / cleanly
        # closed; we don't need the contents.
        resp.read()
    except (OSError, http.client.HTTPException) as exc:
        log.warning("auto-login: upstream POST %s failed: %s", MINIO_LOGIN_PATH, exc)
        return None
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001 - best effort
            pass

    if resp.status >= 400:
        log.warning("auto-login: MinIO returned %d to login attempt", resp.status)
        return None

    # MinIO returns Set-Cookie on success.  We capture it verbatim
    # and echo it on our 302 — the cookie carries Path=/, HttpOnly,
    # SameSite=Lax, Max-Age, etc., all of which we want preserved.
    set_cookie = resp.getheader("Set-Cookie")
    if not set_cookie:
        log.warning("auto-login: MinIO 2xx response had no Set-Cookie")
        return None
    return set_cookie


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------


class AuthProxyHandler(BaseHTTPRequestHandler):
    # Set by main() before the server starts.
    upstream_host: str = "127.0.0.1"
    upstream_port: int = 9001
    cred_file: str = "/data/app_data/minio/config/root-credentials.txt"

    def log_message(self, format: str, *args) -> None:  # noqa: A002, N802
        log.info("%s - " + format, self.address_string(), *args)

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch()

    def do_HEAD(self) -> None:  # noqa: N802
        self._dispatch()

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PUT(self) -> None:  # noqa: N802
        self._dispatch()

    def do_DELETE(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PATCH(self) -> None:  # noqa: N802
        self._dispatch()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._dispatch()

    def _safe_send_error(self, code: int, message: str) -> None:
        try:
            self.send_error(code, message)
        except OSError as exc:
            log.debug("client disconnected before error response: %s", exc)

    def _dispatch(self) -> None:
        try:
            self.connection.settimeout(CLIENT_READ_TIMEOUT_SECONDS)
        except OSError:
            pass

        # WebSocket upgrade requests bypass the auto-login + body-
        # buffering paths entirely.  MinIO's bucket-browser SPA
        # opens a /ws/objectManager WebSocket for live object
        # listings; without this branch the proxy returns 400 to
        # the upgrade and the SPA gets stuck in a retry loop.
        # Treat the upgrade like any other proxy hop: forward the
        # handshake to upstream and switch to bidirectional byte
        # forwarding.  The cookie that authenticates the WS to
        # MinIO is already present (the SPA has the token cookie
        # by the time it opens the WS), so no auto-login dance
        # is needed here.
        if self._is_websocket_upgrade():
            self._proxy_websocket()
            return

        is_owner = self.headers.get(OWNER_HEADER_NAME, "").lower() == "true"
        cookies = _parse_cookie_header(self.headers.get("Cookie"))
        has_minio_session = MINIO_TOKEN_COOKIE in cookies

        # Owner-bounce check: if the visitor is an authenticated
        # owner and has no MinIO session yet, mint one and 302 them
        # back to the same URL with the cookie set.  We only run
        # this on top-level navigations (Accept: text/html in the
        # request) so that asset fetches and XHR calls don't get
        # caught in a redirect loop while the MinIO session is
        # being established.
        accept = self.headers.get("Accept", "")
        is_html_navigation = (
            self.command == "GET"
            and "text/html" in accept.lower()
        )

        if is_owner and not has_minio_session and is_html_navigation:
            if self._maybe_auto_login():
                return

        # Pass through.
        self._proxy()

    # ----------------------------------------------------------------
    # WebSocket upgrade handling
    # ----------------------------------------------------------------

    def _is_websocket_upgrade(self) -> bool:
        """True if the request is a WebSocket upgrade per RFC 6455 §4.1."""
        upgrade = self.headers.get("Upgrade", "").lower().strip()
        connection = self.headers.get("Connection", "").lower()
        # ``Connection`` is comma-separated; check for ``upgrade``
        # as one of the tokens.
        connection_tokens = {t.strip() for t in connection.split(",")}
        return upgrade == "websocket" and "upgrade" in connection_tokens

    def _proxy_websocket(self) -> None:
        """Forward a WebSocket upgrade request bidirectionally.

        Open a TCP connection to upstream, send the request
        verbatim (preserving Upgrade + Connection: Upgrade and the
        Sec-WebSocket-* trio), forward the upstream's 101 response
        head to the client, then shuffle bytes both directions
        until either side closes.

        The HTTP path's hop-by-hop header stripping and Content-
        Length rebuilding are deliberately bypassed for this code
        path because they would break the handshake.  We DO strip
        the SSO trust headers (X-OpenHost-Is-Owner / X-OpenHost-
        User) before forwarding, same as the HTTP path, so a
        hostile client can't forge owner identity through a
        WebSocket request.

        The implementation is adapted from openhost-peertube's
        auth_proxy.py — the body-streaming model used there
        applies cleanly here.
        """
        # Headers to forward to upstream: drop only the trust
        # headers and Host (we'll re-write Host below).  Keep
        # Upgrade, Connection, and Sec-WebSocket-* intact —
        # those are part of the handshake.
        ws_drop = ALWAYS_STRIP_HEADERS | frozenset({"host"})
        cleaned = _strip_headers(self.headers.items(), ws_drop)

        try:
            upstream_sock = socket.create_connection(
                (self.upstream_host, self.upstream_port),
                timeout=STREAM_TIMEOUT_SECONDS,
            )
        except OSError as exc:
            log.warning("upstream connect failed (websocket): %s", exc)
            self._safe_send_error(502, "Bad Gateway")
            return

        try:
            upstream_sock.settimeout(STREAM_TIMEOUT_SECONDS)
            # Build the request as raw bytes.  We avoid
            # http.client here because its framing model doesn't
            # cleanly expose the post-101 socket for byte-level
            # forwarding.
            request_bytes = bytearray()
            request_bytes.extend(
                self._encode_header_bytes(
                    f"{self.command} {self.path} HTTP/1.1\r\n"
                )
            )
            request_bytes.extend(
                self._encode_header_bytes(
                    f"Host: {self.upstream_host}:{self.upstream_port}\r\n"
                )
            )
            for k, v in cleaned:
                request_bytes.extend(
                    self._encode_header_bytes(f"{k}: {v}\r\n")
                )
            request_bytes.extend(b"\r\n")
            try:
                upstream_sock.sendall(bytes(request_bytes))
            except OSError as exc:
                log.warning("websocket request send failed: %s", exc)
                self._safe_send_error(502, "Bad Gateway")
                return

            # Read upstream response head (and any leftover bytes
            # pipelined into the same recv) and forward verbatim.
            response_buf = self._read_until_double_crlf(
                upstream_sock, max_bytes=HEADER_LINE_CAP
            )
            if response_buf is None:
                self._safe_send_error(502, "Bad Gateway")
                return
            head_bytes, tail_bytes = response_buf

            try:
                self.wfile.write(head_bytes)
                if tail_bytes:
                    self.wfile.write(tail_bytes)
                self.wfile.flush()
            except OSError as exc:
                log.debug("client disconnected during ws handshake: %s", exc)
                return

            # If upstream rejected the upgrade, no bidirectional
            # phase needed; the client already has the rejection.
            if not head_bytes.startswith(b"HTTP/1.1 101"):
                log.info("upstream rejected websocket upgrade")
                return

            self._websocket_pump(self.connection, upstream_sock)
        finally:
            try:
                upstream_sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                upstream_sock.close()
            except OSError:
                pass

    @staticmethod
    def _read_until_double_crlf(
        sock: socket.socket, max_bytes: int
    ) -> tuple[bytes, bytes] | None:
        """Read bytes from ``sock`` until ``\\r\\n\\r\\n``.

        Returns ``(head_including_terminator, leftover_bytes)`` or
        ``None`` on EOF / overflow / socket error.  ``leftover_bytes``
        is whatever bytes were read past the header terminator in
        the same recv() — typically empty for a WebSocket handshake.
        """
        buf = bytearray()
        while True:
            try:
                chunk = sock.recv(4096)
            except OSError as exc:
                log.info("websocket handshake recv failed: %s", exc)
                return None
            if not chunk:
                return None
            buf.extend(chunk)
            idx = buf.find(b"\r\n\r\n")
            if idx >= 0:
                head = bytes(buf[: idx + 4])
                tail = bytes(buf[idx + 4 :])
                return head, tail
            if len(buf) >= max_bytes:
                log.warning(
                    "websocket response head exceeds %d bytes; aborting",
                    max_bytes,
                )
                return None

    @staticmethod
    def _websocket_pump(
        client_sock: socket.socket, upstream_sock: socket.socket
    ) -> None:
        """Bidirectionally forward bytes between two sockets.

        Returns when either socket closes.  Uses ``selectors`` so a
        single thread can wait on both directions; matches the
        pattern Caddy / nginx use for WebSocket reverse-proxying.
        """
        for s in (client_sock, upstream_sock):
            try:
                s.settimeout(None)
            except OSError:
                pass

        sel = selectors.DefaultSelector()
        try:
            sel.register(client_sock, selectors.EVENT_READ, "client")
            sel.register(upstream_sock, selectors.EVENT_READ, "upstream")
            while True:
                events = sel.select(timeout=STREAM_TIMEOUT_SECONDS)
                if not events:
                    log.info("websocket idle timeout; closing")
                    return
                for key, _ in events:
                    if key.data == "client":
                        src, dst = client_sock, upstream_sock
                        direction = "client→upstream"
                    else:
                        src, dst = upstream_sock, client_sock
                        direction = "upstream→client"
                    try:
                        chunk = src.recv(STREAM_CHUNK_BYTES)
                    except OSError as exc:
                        log.info(
                            "websocket %s recv failed: %s",
                            direction, exc,
                        )
                        return
                    if not chunk:
                        log.debug("websocket %s EOF; closing", direction)
                        return
                    try:
                        dst.sendall(chunk)
                    except OSError as exc:
                        log.info(
                            "websocket %s sendall failed: %s",
                            direction, exc,
                        )
                        return
        finally:
            try:
                sel.close()
            except Exception as exc:  # noqa: BLE001
                log.debug("websocket selector close failed: %s", exc)

    @staticmethod
    def _encode_header_bytes(value: str) -> bytes:
        try:
            return value.encode("latin-1")
        except UnicodeEncodeError:
            log.warning("non-latin-1 header value, replacing offending bytes")
            return value.encode("latin-1", errors="replace")

    def _maybe_auto_login(self) -> bool:
        """Attempt to auto-login to MinIO and 302 with the cookie set.

        Returns True on success (a 302 was sent), False otherwise.
        On False the caller falls through to a normal request
        forward, which means the user sees MinIO's own login form
        — the worst-case UX, not an error page.
        """
        creds = _read_root_creds(self.cred_file)
        if creds is None:
            log.warning(
                "auto-login: credentials file missing or unreadable at %s; "
                "falling through to manual login",
                self.cred_file,
            )
            return False

        user, password = creds
        set_cookie = _login_to_minio(
            self.upstream_host, self.upstream_port, user, password
        )
        if set_cookie is None:
            return False

        # Mint a 302 back to the same URL.  The browser follows the
        # redirect and re-issues the request with the new MinIO
        # token cookie attached, this time hitting the proxy's
        # pass-through path.
        target_path = self.path or "/"
        # Defensive: confine the redirect to a relative path so we
        # cannot be tricked into open-redirecting to an external
        # URL.  self.path comes from the request line and is
        # already same-origin, but parsing through urllib normalises
        # any weird forms and rejects scheme/netloc components.
        parsed = urllib.parse.urlparse(target_path)
        if parsed.scheme or parsed.netloc:
            target_path = "/"

        try:
            self.send_response(302)
            self.send_header("Location", target_path)
            self.send_header("Set-Cookie", set_cookie)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
        except OSError as exc:
            log.debug("client disconnected during auto-login redirect: %s", exc)
            return False

        log.info(
            "auto-login: minted MinIO session for owner; redirected to %s",
            target_path,
        )
        return True

    def _proxy(self) -> None:
        """Forward the request to MinIO without modification (apart
        from stripping trust headers and the standard hop-by-hop set).
        """
        cleaned_headers = _strip_headers(
            self.headers.items(),
            HOP_BY_HOP_HEADERS | ALWAYS_STRIP_HEADERS,
        )

        # Read the request body if any.
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
            if length > MAX_BODY_BYTES:
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
            body = b""

        conn = http.client.HTTPConnection(
            self.upstream_host, self.upstream_port, timeout=60
        )
        try:
            try:
                conn.putrequest(
                    self.command,
                    self.path,
                    skip_host=False,
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
                payload = upstream.read(MAX_BODY_BYTES + 1)
            except (OSError, http.client.HTTPException) as exc:
                log.warning("upstream read error: %s", exc)
                self._safe_send_error(502, "Bad Gateway")
                try:
                    upstream.close()
                except Exception as close_exc:  # noqa: BLE001 - best effort
                    log.debug("upstream.close() raised: %s", close_exc)
                return
            try:
                upstream.close()
            except Exception as exc:  # noqa: BLE001 - best effort only
                log.debug("upstream.close() raised (ignored): %s", exc)
            if len(payload) > MAX_BODY_BYTES:
                log.warning(
                    "upstream response exceeded %d bytes; returning 502",
                    MAX_BODY_BYTES,
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
    try:
        listen_port = _port_from_env("AUTH_PROXY_LISTEN_PORT", 9090)
        upstream_port = _port_from_env("AUTH_PROXY_UPSTREAM_PORT", 9001)
    except ValueError as exc:
        log.error("invalid port configuration: %s", exc)
        return 1

    upstream_host = os.environ.get("AUTH_PROXY_UPSTREAM_HOST", "127.0.0.1").strip()
    cred_file = os.environ.get(
        "AUTH_PROXY_CRED_FILE",
        "/data/app_data/minio/config/root-credentials.txt",
    )

    AuthProxyHandler.upstream_host = upstream_host
    AuthProxyHandler.upstream_port = upstream_port
    AuthProxyHandler.cred_file = cred_file

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
        "listening on 0.0.0.0:%d -> %s:%d (creds=%s)",
        listen_port,
        upstream_host,
        upstream_port,
        cred_file,
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
