"""
Automated Test Suite for Network Resilience and SSRF Probing Engine.
"""

import asyncio
import contextlib
import os
import socket
import ssl
import time
from unittest.mock import patch

import httpx
from app.enums import PingOutcome
from app.net import (
    perform_http_probe,
    redact_url_credentials,
    robust_ping,
)


# =========================================================================
# 1. Status Code Classification Tests
# =========================================================================
def test_status_code_classification() -> None:
    """Verify 2xx/3xx -> UP, 4xx -> DEGRADED, 5xx -> DOWN."""

    def mock_handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/200":
            return httpx.Response(200, text="OK")
        elif path == "/301":
            return httpx.Response(301, headers={"Location": "https://example.com/200"})
        elif path == "/404":
            return httpx.Response(404, text="Not Found")
        elif path == "/403":
            return httpx.Response(403, text="Forbidden")
        elif path == "/500":
            return httpx.Response(500, text="Internal Server Error")
        elif path == "/503":
            return httpx.Response(503, text="Service Unavailable")
        return httpx.Response(200)

    transport = httpx.MockTransport(mock_handler)

    # 200 OK -> UP
    r200 = robust_ping("https://example.com/200", allow_loopback=True, transport=transport)
    assert r200.outcome == PingOutcome.UP
    assert r200.status_code == 200
    assert r200.error_detail is None

    # 404 Not Found -> DEGRADED (server responded!)
    r404 = robust_ping("https://example.com/404", allow_loopback=True, transport=transport)
    assert r404.outcome == PingOutcome.DEGRADED
    assert r404.status_code == 404
    assert r404.error_detail is None

    # 403 Forbidden -> DEGRADED
    r403 = robust_ping("https://example.com/403", allow_loopback=True, transport=transport)
    assert r403.outcome == PingOutcome.DEGRADED
    assert r403.status_code == 403

    # 500 Internal Server Error -> DOWN
    r500 = robust_ping("https://example.com/500", allow_loopback=True, transport=transport)
    assert r500.outcome == PingOutcome.DOWN
    assert r500.status_code == 500

    # 503 Service Unavailable -> DOWN
    r503 = robust_ping("https://example.com/503", allow_loopback=True, transport=transport)
    assert r503.outcome == PingOutcome.DOWN
    assert r503.status_code == 503


# =========================================================================
# 2. Timeout Model Tests
# =========================================================================
def test_connect_timeout_classification() -> None:
    """Verify connect timeout maps to connect_timeout and outcome=UNREACHABLE."""

    def timeout_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("Connection timed out in connect phase", request=request)

    transport = httpx.MockTransport(timeout_handler)
    result = robust_ping(
        "https://example.com/slow-connect", allow_loopback=True, transport=transport
    )
    assert result.outcome == PingOutcome.UNREACHABLE
    assert result.status_code is None
    assert result.error_detail == "connect_timeout"
    assert result.latency_ms is not None


def test_read_timeout_classification() -> None:
    """Verify read timeout maps to read_timeout and outcome=UNREACHABLE."""

    def timeout_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("Server connected but took too long to send data", request=request)

    transport = httpx.MockTransport(timeout_handler)
    result = robust_ping("https://example.com/slow-read", allow_loopback=True, transport=transport)
    assert result.outcome == PingOutcome.UNREACHABLE
    assert result.status_code is None
    assert result.error_detail == "read_timeout"
    assert result.latency_ms is not None


# =========================================================================
# 3. SSRF Defense: Private, Loopback, & Cloud Metadata Blocking
# =========================================================================
def test_ssrf_blocked_ip_literals() -> None:
    """Verify private and reserved IP literals are blocked before outbound requests."""
    blocked_targets = [
        "http://127.0.0.1",
        "http://127.0.0.1:8080/metrics",
        "http://localhost",
        "http://localhost:3000",
        "http://10.0.0.1",
        "http://10.254.1.1/internal",
        "http://172.16.0.1",
        "http://172.31.255.255",
        "http://192.168.1.1",
        "http://192.168.0.254",
        "http://169.254.169.254",  # AWS/GCP/Azure Cloud Metadata
        "http://169.254.1.1",  # IPv4 Link-local
        "http://[::1]",  # IPv6 Loopback
        "http://[fe80::1]",  # IPv6 Link-local
        "http://0.0.0.0",
    ]

    for target in blocked_targets:
        result = robust_ping(target, allow_loopback=False)
        assert result.outcome == PingOutcome.UNREACHABLE, f"Expected {target} to be UNREACHABLE"
        assert result.status_code is None
        assert result.error_detail == "ssrf_blocked", (
            f"Expected {target} to have error_detail ssrf_blocked"
        )


def test_dns_rebinding_defense() -> None:
    """
    Verify that a domain name resolving to a private/loopback IP is blocked.
    Simulates DNS rebinding where an external domain resolves to 127.0.0.1 or 169.254.169.254.
    """

    def mock_rebind_resolver(host: str, port: int, type: int = 0):
        # Simulate DNS returning a malicious private IP for a public-looking domain
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

    result = robust_ping(
        "https://evil-rebind-domain.com/secret",
        allow_loopback=False,
        dns_resolver=mock_rebind_resolver,
    )
    assert result.outcome == PingOutcome.UNREACHABLE
    assert result.error_detail == "ssrf_blocked"


def test_dns_resolution_failure() -> None:
    """Verify non-existent hostnames map to dns_error."""

    def mock_failing_resolver(host: str, port: int, type: int = 0):
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    result = robust_ping(
        "https://completely-fake-unresolvable-domain-999.org",
        dns_resolver=mock_failing_resolver,
    )
    assert result.outcome == PingOutcome.UNREACHABLE
    assert result.error_detail == "dns_error"
    assert result.latency_ms is not None


# =========================================================================
# 4. Redirect SSRF Defense
# =========================================================================
def test_redirect_ssrf_intercepted() -> None:
    """
    Verify that a public endpoint redirecting (302) to an internal/metadata IP
    is intercepted and blocked before connection.
    """

    def redirect_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/entry":
            # Attempts redirect to cloud metadata service
            return httpx.Response(
                302, headers={"Location": "http://169.254.169.254/latest/meta-data"}
            )
        return httpx.Response(200)

    transport = httpx.MockTransport(redirect_handler)
    result = robust_ping(
        "https://example.com/entry",
        allow_loopback=False,
        transport=transport,
    )
    assert result.outcome == PingOutcome.UNREACHABLE
    assert result.error_detail == "ssrf_blocked"


# =========================================================================
# 5. Response Size Protection (Bounded Streaming)
# =========================================================================
def test_response_size_bounding() -> None:
    """Verify large streaming response bodies stop reading once limit is reached."""
    huge_content = b"X" * (500 * 1024)  # 500 KB

    def huge_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=huge_content)

    transport = httpx.MockTransport(huge_handler)

    from app.config import get_settings

    with patch.dict(os.environ, {"HTTP_MAX_RESPONSE_BYTES": str(10 * 1024)}):
        get_settings.cache_clear()
        try:
            result = robust_ping(
                "https://example.com/huge", allow_loopback=True, transport=transport
            )
            assert result.outcome == PingOutcome.UP
            assert result.status_code == 200
        finally:
            get_settings.cache_clear()


# =========================================================================
# 6. TLS / SSL Error Classification
# =========================================================================
def test_tls_error_classification() -> None:
    """Verify TLS/SSL certificate handshake errors map to tls_error."""

    def tls_fail_handler(request: httpx.Request) -> httpx.Response:
        ssl_err = ssl.SSLCertVerificationError("Certificate verify failed: certificate has expired")
        connect_err = httpx.ConnectError(
            f"[SSL: CERTIFICATE_VERIFY_FAILED] {ssl_err}", request=request
        )
        connect_err.__cause__ = ssl_err
        raise connect_err

    transport = httpx.MockTransport(tls_fail_handler)

    def mock_resolver(host, port, type=0):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    result = robust_ping(
        "https://expired-cert.example.com",
        allow_loopback=True,
        transport=transport,
        dns_resolver=mock_resolver,
    )
    assert result.outcome == PingOutcome.UNREACHABLE
    assert result.error_detail == "tls_error"


# =========================================================================
# 7. URL Security: Schemes & Credential Redaction
# =========================================================================
def test_unsupported_schemes_blocked() -> None:
    """Verify non-HTTP/HTTPS schemes are blocked."""
    forbidden_urls = [
        "ftp://files.example.com/file.txt",
        "file:///etc/passwd",
        "gopher://gopher.floodgap.com",
        "ws://socket.example.com",
    ]
    for bad_url in forbidden_urls:
        result = robust_ping(bad_url)
        assert result.outcome == PingOutcome.UNREACHABLE, f"Expected {bad_url} to be UNREACHABLE"
        assert result.error_detail == "ssrf_blocked", (
            f"Expected {bad_url} to have error_detail ssrf_blocked"
        )


def test_credential_redaction() -> None:
    """Verify embedded credentials in URLs are redacted in logs and helper."""
    raw_url = "https://admin:SuperSecretPassword123@api.example.com/v1/health"
    redacted = redact_url_credentials(raw_url)
    assert "SuperSecretPassword123" not in redacted
    assert "***:***" in redacted
    assert redacted == "https://***:***@api.example.com/v1/health"


def test_nat64_translation_validation() -> None:
    """Verify NAT64 IPv6 addresses (64:ff9b::/96) allow public IPv4 while blocking private IPv4."""
    import ipaddress

    from app.net import is_ip_blocked

    # 64:ff9b::d818:3910 embeds 216.24.57.16 (public Render IP) -> allowed
    assert not is_ip_blocked(ipaddress.ip_address("64:ff9b::d818:3910"))
    # 64:ff9b::7f00:1 embeds 127.0.0.1 (loopback) -> blocked
    assert is_ip_blocked(ipaddress.ip_address("64:ff9b::7f00:1"))
    # 64:ff9b::0a00:1 embeds 10.0.0.1 (RFC 1918) -> blocked
    assert is_ip_blocked(ipaddress.ip_address("64:ff9b::0a00:1"))


# =========================================================================
# Task A8: Total Deadline (Slow-Drip) Test
# =========================================================================
def test_slow_drip_total_timeout_enforced() -> None:
    """
    Verify that a server dripping chunks slowly (1 byte every 0.5s for 20s)
    is aborted by total_timeout within < 2.5s with error_detail='total_timeout'.
    """

    async def _run_test():
        async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            with contextlib.suppress(Exception):
                line = await reader.readline()
                while line and line != b"\r\n":
                    line = await reader.readline()

                writer.write(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Transfer-Encoding: chunked\r\n"
                    b"Content-Type: text/plain\r\n\r\n"
                )
                await writer.drain()

                for _ in range(40):
                    writer.write(b"1\r\nX\r\n")
                    await writer.drain()
                    await asyncio.sleep(0.5)

                writer.write(b"0\r\n\r\n")
                await writer.drain()
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
        host, port = server.sockets[0].getsockname()
        url = f"http://127.0.0.1:{port}/"

        async with server:
            server_task = asyncio.create_task(server.serve_forever())
            try:
                t0 = time.monotonic()
                res = await perform_http_probe(
                    url=url,
                    read_timeout=2.0,
                    allow_loopback=True,
                    total_timeout=1.0,
                )
                elapsed = time.monotonic() - t0
                return res, elapsed
            finally:
                server_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await server_task

    res, elapsed = asyncio.run(_run_test())
    assert res.outcome == PingOutcome.UNREACHABLE
    assert res.error_detail == "total_timeout"
    assert elapsed < 2.5


def test_latency_excludes_body_streaming_time() -> None:
    """
    Verify latency_ms measures time-to-response-headers only.
    Server sends headers immediately, then sleeps for 1.0s before sending body.
    Assert latency_ms < 500 while total elapsed >= 1.0s.
    """

    async def _run_test():
        async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            with contextlib.suppress(Exception):
                await reader.read(1024)
                headers = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"Content-Length: 5\r\n"
                    b"Connection: close\r\n\r\n"
                )
                writer.write(headers)
                await writer.drain()

                await asyncio.sleep(1.0)
                writer.write(b"hello")
                await writer.drain()

            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
        host, port = server.sockets[0].getsockname()
        url = f"http://127.0.0.1:{port}/"

        async with server:
            server_task = asyncio.create_task(server.serve_forever())
            try:
                t0 = time.monotonic()
                res = await perform_http_probe(
                    url=url,
                    read_timeout=3.0,
                    allow_loopback=True,
                    total_timeout=5.0,
                )
                elapsed = time.monotonic() - t0
                return res, elapsed
            finally:
                server_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await server_task

    res, elapsed = asyncio.run(_run_test())
    assert res.outcome == PingOutcome.UP
    assert res.status_code == 200
    assert res.latency_ms is not None
    assert res.latency_ms < 500
    assert elapsed >= 1.0


# =========================================================================
# Task A9: DNS-Rebinding & IP Pinning Tests
# =========================================================================
def test_dns_rebinding_pinned_ip_used() -> None:
    """
    Test (a) Rebinding: injected resolver returns public IP on call 1 and 127.0.0.1 on call 2.
    Assert resolver called once and outgoing URL host equals FIRST (validated) IP,
    with Host header equal to the original hostname.
    """
    call_count = 0

    def rebinding_resolver(host: str, port: int, type: int = 0):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

    captured_request: httpx.Request | None = None

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal captured_request
        captured_request = request
        return httpx.Response(200, text="OK")

    transport = httpx.MockTransport(mock_handler)
    result = robust_ping(
        "https://rebinding-victim.example.com/resource",
        allow_loopback=False,
        transport=transport,
        dns_resolver=rebinding_resolver,
    )

    assert result.outcome == PingOutcome.UP
    assert call_count == 1
    assert captured_request is not None
    assert captured_request.url.host == "93.184.216.34"
    assert captured_request.headers.get("host") == "rebinding-victim.example.com"


def test_redirect_to_blocked_ip_or_private_host_blocked() -> None:
    """
    Test (b): Redirect to a blocked IP literal and redirect to a hostname resolving
    to a private IP both end with ssrf_blocked and no request is sent to the blocked target.
    """
    # Case 1: Redirect to blocked IP literal
    received_requests_1: list[httpx.Request] = []

    def handler_literal(request: httpx.Request) -> httpx.Response:
        received_requests_1.append(request)
        return httpx.Response(302, headers={"Location": "http://127.0.0.1/admin"})

    def mock_pub_resolver(h, p, t=0):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", p))]

    transport_1 = httpx.MockTransport(handler_literal)
    res_literal = robust_ping(
        "https://public-site.com/step1",
        allow_loopback=False,
        transport=transport_1,
        dns_resolver=mock_pub_resolver,
    )
    assert res_literal.outcome == PingOutcome.UNREACHABLE
    assert res_literal.error_detail == "ssrf_blocked"
    assert len(received_requests_1) == 1  # Only initial hop sent; blocked target was NOT requested

    # Case 2: Redirect to hostname resolving to private IP
    received_requests_2: list[httpx.Request] = []

    def handler_host(request: httpx.Request) -> httpx.Response:
        received_requests_2.append(request)
        return httpx.Response(302, headers={"Location": "http://internal-db.local/secret"})

    def multi_resolver(host: str, port: int, type: int = 0):
        if "public" in host:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", port))]

    transport_2 = httpx.MockTransport(handler_host)
    res_host = robust_ping(
        "https://public-site.com/step1",
        allow_loopback=False,
        transport=transport_2,
        dns_resolver=multi_resolver,
    )
    assert res_host.outcome == PingOutcome.UNREACHABLE
    assert res_host.error_detail == "ssrf_blocked"
    assert len(received_requests_2) == 1  # Internal host was NOT requested


def test_redirect_relative_and_loop_exhaustion() -> None:
    """
    Test (c): Relative Location redirects are followed correctly;
    redirect loops stop at max_redirects.
    """

    def mock_resolver(h, p, t=0):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", p))]

    # Relative Location redirect followed correctly
    def relative_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/start":
            return httpx.Response(302, headers={"Location": "/finish"})
        elif request.url.path == "/finish":
            return httpx.Response(200, text="Final Destination")
        return httpx.Response(404)

    transport_rel = httpx.MockTransport(relative_handler)
    res_rel = robust_ping(
        "https://public-site.com/start",
        allow_loopback=False,
        transport=transport_rel,
        dns_resolver=mock_resolver,
    )
    assert res_rel.outcome == PingOutcome.UP
    assert res_rel.status_code == 200
    assert res_rel.final_url == "https://public-site.com/finish"

    # Redirect loop stops at max_redirects
    def loop_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "/loop"})

    transport_loop = httpx.MockTransport(loop_handler)
    res_loop = robust_ping(
        "https://public-site.com/loop",
        allow_loopback=False,
        transport=transport_loop,
        dns_resolver=mock_resolver,
    )
    assert res_loop.outcome == PingOutcome.UNREACHABLE
    assert res_loop.error_detail == "redirect_error"


def test_https_request_carries_sni_hostname() -> None:
    """
    Test (d): https request carries extensions sni_hostname == original hostname.
    """

    def mock_resolver(h, p, t=0):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", p))]

    captured_req: httpx.Request | None = None

    def sni_handler(request: httpx.Request) -> httpx.Response:
        nonlocal captured_req
        captured_req = request
        return httpx.Response(200, text="OK")

    transport = httpx.MockTransport(sni_handler)
    res = robust_ping(
        "https://secure-service.example.org/health",
        allow_loopback=False,
        transport=transport,
        dns_resolver=mock_resolver,
    )
    assert res.outcome == PingOutcome.UP
    assert captured_req is not None
    assert captured_req.extensions.get("sni_hostname") == "secure-service.example.org"


def test_characterisation_httpx_exception_mapping() -> None:
    """
    Characterisation tests pinning current behaviour for all handled httpx exceptions.
    Maps each exception raised by MockTransport to expected outcome and error_detail.
    """

    def mock_resolver(h, p, t=0):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", p))]

    ssl_err = ssl.SSLCertVerificationError("cert expired")
    tls_connect_err = httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] cert expired")
    tls_connect_err.__cause__ = ssl_err

    cases = [
        (httpx.ConnectTimeout("connection timed out"), "connect_timeout"),
        (httpx.ReadTimeout("read timed out"), "read_timeout"),
        (httpx.WriteTimeout("write timed out"), "write_timeout"),
        (httpx.PoolTimeout("pool timed out"), "pool_timeout"),
        (httpx.TooManyRedirects("too many redirects"), "redirect_error"),
        (httpx.ConnectError("failed to connect"), "connect_error"),
        (tls_connect_err, "tls_error"),
        (httpx.RequestError("generic error"), "request_error"),
    ]

    for exc, expected_error in cases:

        def handler(request: httpx.Request, e=exc) -> httpx.Response:
            e.request = request
            raise e

        transport = httpx.MockTransport(handler)
        res = robust_ping(
            "https://example.com/test-characterisation",
            allow_loopback=True,
            transport=transport,
            dns_resolver=mock_resolver,
        )
        assert res.outcome == PingOutcome.UNREACHABLE, f"Failed for {expected_error}"
        assert res.status_code is None
        assert res.error_detail == expected_error, f"Failed for {expected_error}"
        assert res.latency_ms is not None
