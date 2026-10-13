"""
Network Resilience & Probing Engine.

Provides an observable network execution layer with timeouts, SSRF defense,
streaming response bounds, monotonic latency tracking, and structured outcome classification.
"""

import asyncio
import inspect
import ipaddress
import logging
import socket
import ssl
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import httpx

from app.config import get_settings
from app.enums import PingOutcome
from app.ssrf import (
    DNSResolutionError,
    SSRFBlockedError,
    is_ip_blocked,
    redact_url_credentials,
)
from app.status import classify_status_code

logger = logging.getLogger(__name__)

# =============================================================================
# 1. Result DTOs & Outcomes
# =============================================================================


@dataclass(frozen=True)
class PingResultDTO:
    """
    Structured outcome returned by the network prober.

    Attributes:
        outcome: Tagged classification (UP, DEGRADED, DOWN, UNREACHABLE).
        status_code: HTTP response code if target responded, else None.
        latency_ms: Round-trip duration in milliseconds (monotonic).
        error_detail: Concise, stable error identifier
            (e.g. 'connect_timeout', 'read_timeout', 'total_timeout', 'ssrf_blocked').
        original_url: Target URL provided for evaluation.
        final_url: Effective destination URL after following redirects.
    """

    outcome: PingOutcome
    status_code: int | None
    latency_ms: float | None
    error_detail: str | None
    original_url: str
    final_url: str | None


# =============================================================================
# 2. Configuration & Default Settings
# =============================================================================


# =============================================================================
# 3. SSRF Defense & Blocklists
# =============================================================================


def resolve_and_validate_target(
    url: str,
    allow_loopback: bool = False,
    dns_resolver: Callable[..., Any] | None = None,
) -> tuple[urllib.parse.SplitResult, list[str]]:
    """
    Validates scheme, normalizes URL, resolves hostname, and checks against SSRF blocklist.

    Args:
        url: The target URL to validate.
        allow_loopback: If True, permits loopback/private destinations (strictly for unit tests).
        dns_resolver: Optional custom resolver for deterministic testing
            (defaults to socket.getaddrinfo).

    Returns:
        tuple of (parsed_url, list_of_resolved_ips)

    Raises:
        SSRFBlockedError: If scheme is forbidden, or if ANY resolved IP falls in a blocked range.
        DNSResolutionError: If hostname resolution fails.
    """
    try:
        parsed = urllib.parse.urlsplit(url)
    except Exception as exc:
        raise SSRFBlockedError(f"Malformed URL: {exc}") from exc

    # 1. Enforce allowed schemes (HTTP/HTTPS only)
    if parsed.scheme.lower() not in ("http", "https"):
        raise SSRFBlockedError(
            f"Unsupported URL scheme: '{parsed.scheme}'. Only HTTP and HTTPS are permitted."
        )

    hostname = parsed.hostname
    if not hostname:
        raise SSRFBlockedError("URL must contain a valid hostname or IP address.")

    hostname_clean = hostname.strip().lower()

    # 2. Reject credentials in URL
    if parsed.username or parsed.password:
        raise SSRFBlockedError("Embedded credentials in URLs (user:pass@) are forbidden.")

    # 3. Direct literal IP check (handles IPv4/IPv6 literals without DNS)
    try:
        literal_ip = ipaddress.ip_address(hostname_clean)
        if is_ip_blocked(literal_ip):
            if allow_loopback and (literal_ip.is_loopback or str(literal_ip) == "127.0.0.1"):
                pass  # Permitted only for loopback testing
            else:
                raise SSRFBlockedError(
                    f"SSRF blocked: IP literal '{hostname_clean}' is private or reserved."
                )
        return parsed, [str(literal_ip)]
    except ValueError:
        pass  # Hostname is not an IP literal, proceed to DNS resolution

    # 4. Obvious loopback hostname check
    if hostname_clean in ("localhost", "localhost.localdomain") and not allow_loopback:
        raise SSRFBlockedError(f"SSRF blocked: Hostname '{hostname_clean}' is a loopback alias.")

    # 5. Resolve hostname to all associated IPs
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    resolver = dns_resolver or socket.getaddrinfo

    try:
        try:
            addr_info = resolver(hostname_clean, port, type=socket.SOCK_STREAM)
        except TypeError:
            addr_info = resolver(hostname_clean, port)
    except socket.gaierror as exc:
        raise DNSResolutionError(f"DNS resolution failed for '{hostname_clean}': {exc}") from exc
    except Exception as exc:
        raise DNSResolutionError(f"DNS lookup error for '{hostname_clean}': {exc}") from exc

    resolved_ips: list[str] = []
    for entry in addr_info:
        sockaddr = entry[4]
        ip_str = str(sockaddr[0])
        if ip_str not in resolved_ips:
            resolved_ips.append(ip_str)

    if not resolved_ips:
        raise DNSResolutionError(f"No IP addresses resolved for hostname '{hostname_clean}'.")

    # 6. Verify that NO resolved address is blocked
    for ip_str in resolved_ips:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if is_ip_blocked(ip_obj):
                if allow_loopback and (ip_obj.is_loopback or str(ip_obj) == "127.0.0.1"):
                    pass  # Permitted for local loopback testing
                else:
                    logger.warning(
                        "SSRF blocked target='%s': hostname '%s' resolved to forbidden IP '%s'",
                        redact_url_credentials(url),
                        hostname_clean,
                        ip_str,
                    )
                    raise SSRFBlockedError(
                        f"SSRF blocked: Hostname '{hostname_clean}' resolved to "
                        f"private/restricted IP '{ip_str}'."
                    )
        except ValueError as err:
            raise SSRFBlockedError(f"Invalid resolved IP format: '{ip_str}'.") from err

    return parsed, resolved_ips


async def async_resolve_and_validate_target(
    url: str,
    allow_loopback: bool = False,
    dns_resolver: Callable[..., Any] | None = None,
) -> tuple[urllib.parse.SplitResult, str]:
    """
    Asynchronously validates URL scheme, normalizes URL, resolves hostname,
    verifies that ALL returned IPs are safe against SSRF blocklists, and returns
    (parsed_url, pinned_ip) using the first validated IP address.
    """
    try:
        parsed = urllib.parse.urlsplit(url)
    except Exception as exc:
        raise SSRFBlockedError(f"Malformed URL: {exc}") from exc

    # 1. Enforce allowed schemes (HTTP/HTTPS only)
    if parsed.scheme.lower() not in ("http", "https"):
        raise SSRFBlockedError(
            f"Unsupported URL scheme: '{parsed.scheme}'. Only HTTP and HTTPS are permitted."
        )

    hostname = parsed.hostname
    if not hostname:
        raise SSRFBlockedError("URL must contain a valid hostname or IP address.")

    hostname_clean = hostname.strip().lower()

    # 2. Reject credentials in URL
    if parsed.username or parsed.password:
        raise SSRFBlockedError("Embedded credentials in URLs (user:pass@) are forbidden.")

    # 3. Direct literal IP check
    try:
        literal_ip = ipaddress.ip_address(hostname_clean)
        if is_ip_blocked(literal_ip):
            if allow_loopback and (literal_ip.is_loopback or str(literal_ip) == "127.0.0.1"):
                pass
            else:
                raise SSRFBlockedError(
                    f"SSRF blocked: IP literal '{hostname_clean}' is private or reserved."
                )
        return parsed, str(literal_ip)
    except ValueError:
        pass

    # 4. Obvious loopback hostname check
    if hostname_clean in ("localhost", "localhost.localdomain") and not allow_loopback:
        raise SSRFBlockedError(f"SSRF blocked: Hostname '{hostname_clean}' is a loopback alias.")

    # 5. Resolve hostname
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)

    try:
        if dns_resolver is not None:
            try:
                res = dns_resolver(hostname_clean, port, type=socket.SOCK_STREAM)
            except TypeError:
                res = dns_resolver(hostname_clean, port)
            if inspect.isawaitable(res):
                addr_info = await res
            else:
                addr_info = res
        else:
            loop = asyncio.get_running_loop()
            addr_info = await loop.getaddrinfo(hostname_clean, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise DNSResolutionError(f"DNS resolution failed for '{hostname_clean}': {exc}") from exc
    except Exception as exc:
        raise DNSResolutionError(f"DNS lookup error for '{hostname_clean}': {exc}") from exc

    resolved_ips: list[str] = []
    for entry in addr_info:
        sockaddr = entry[4]
        ip_str = str(sockaddr[0])
        if ip_str not in resolved_ips:
            resolved_ips.append(ip_str)

    if not resolved_ips:
        raise DNSResolutionError(f"No IP addresses resolved for hostname '{hostname_clean}'.")

    # 6. Verify that NO resolved address is blocked
    for ip_str in resolved_ips:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if is_ip_blocked(ip_obj):
                if allow_loopback and (ip_obj.is_loopback or str(ip_obj) == "127.0.0.1"):
                    pass
                else:
                    logger.warning(
                        "SSRF blocked target='%s': hostname '%s' resolved to forbidden IP '%s'",
                        redact_url_credentials(url),
                        hostname_clean,
                        ip_str,
                    )
                    raise SSRFBlockedError(
                        f"SSRF blocked: Hostname '{hostname_clean}' resolved to "
                        f"private/restricted IP '{ip_str}'."
                    )
        except ValueError as err:
            raise SSRFBlockedError(f"Invalid resolved IP format: '{ip_str}'.") from err

    return parsed, resolved_ips[0]


# =============================================================================
# 4. Exception Helper
# =============================================================================


def is_tls_exception(exc: Exception) -> bool:
    """Detects whether an exception stems from a TLS/SSL handshake or certificate error."""
    curr: Exception | None = exc
    while curr is not None:
        if isinstance(curr, ssl.SSLError | ssl.CertificateError):
            return True
        exc_str = str(curr).lower()
        exc_name = type(curr).__name__.lower()
        if "ssl" in exc_name or "certificate" in exc_str or "tls" in exc_str:
            return True
        curr = getattr(curr, "__cause__", None) or getattr(curr, "__context__", None)
    return False


# Table-driven mapping for probe exception dispatch.
# Evaluation order is strict: specific subclasses MUST precede parent classes.
HTTPX_EXCEPTION_TABLE: tuple[tuple[type[Exception], PingOutcome, str], ...] = (
    (httpx.ConnectTimeout, PingOutcome.UNREACHABLE, "connect_timeout"),
    (httpx.ReadTimeout, PingOutcome.UNREACHABLE, "read_timeout"),
    (httpx.WriteTimeout, PingOutcome.UNREACHABLE, "write_timeout"),
    (httpx.PoolTimeout, PingOutcome.UNREACHABLE, "pool_timeout"),
    (httpx.TooManyRedirects, PingOutcome.UNREACHABLE, "redirect_error"),
    (httpx.ConnectError, PingOutcome.UNREACHABLE, "connect_error"),
    (httpx.RequestError, PingOutcome.UNREACHABLE, "request_error"),
)


def _build_probe_error_result(
    url: str,
    error_detail: str,
    latency_ms: float | None = None,
    outcome: PingOutcome = PingOutcome.UNREACHABLE,
) -> PingResultDTO:
    """Helper to construct a standardized probe error PingResultDTO."""
    return PingResultDTO(
        outcome=outcome,
        status_code=None,
        latency_ms=latency_ms,
        error_detail=error_detail,
        original_url=url,
        final_url=None,
    )


# =============================================================================
# 5. Core Asynchronous Network Probe Engine
# =============================================================================


async def perform_http_probe(
    url: str,
    user_agent: str | None = None,
    connect_timeout: float | None = None,
    read_timeout: float | None = None,
    write_timeout: float | None = None,
    pool_timeout: float | None = None,
    max_response_bytes: int | None = None,
    max_redirects: int | None = None,
    allow_loopback: bool = False,
    dns_resolver: Callable[..., Any] | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
    total_timeout: float | None = None,
) -> PingResultDTO:
    """
    Executes an asynchronous HTTP GET probe against the target URL.

    Enforces SSRF defense with DNS pinning to mitigate DNS-rebinding (TOCTOU),
    granular timeouts, total probe deadline, streaming memory limits,
    and manual redirect verification.
    """
    settings = get_settings()
    effective_total_timeout = (
        total_timeout if total_timeout is not None else settings.probe_total_timeout_seconds
    )

    safe_url = redact_url_credentials(url)
    start_mono = time.monotonic()

    # Resolve runtime configuration and configure granular timeouts
    ua = user_agent or settings.http_user_agent
    c_timeout = connect_timeout if connect_timeout is not None else settings.http_connect_timeout
    r_timeout = read_timeout if read_timeout is not None else settings.http_read_timeout
    w_timeout = write_timeout if write_timeout is not None else settings.http_write_timeout
    p_timeout = pool_timeout if pool_timeout is not None else settings.http_pool_timeout
    max_bytes = (
        max_response_bytes if max_response_bytes is not None else settings.http_max_response_bytes
    )
    max_redirs = max_redirects if max_redirects is not None else settings.http_max_redirects

    timeouts = httpx.Timeout(
        connect=c_timeout,
        read=r_timeout,
        write=w_timeout,
        pool=p_timeout,
    )

    client_kwargs: dict[str, Any] = {
        "timeout": timeouts,
        "follow_redirects": False,
    }
    if transport is not None:
        client_kwargs["transport"] = transport

    try:
        async with asyncio.timeout(effective_total_timeout):
            current_url = url
            redirect_count = 0
            status_code: int | None = None
            final_url: str | None = None
            bytes_read = 0

            try:
                async with httpx.AsyncClient(**client_kwargs) as client:
                    while True:
                        # Step 1: Pre-hop SSRF & DNS validation with IP pinning
                        # Redirects must NEVER permit loopback, private, or cloud metadata
                        hop_allow_loopback = allow_loopback if redirect_count == 0 else False
                        try:
                            parsed, pinned_ip = await async_resolve_and_validate_target(
                                current_url,
                                allow_loopback=hop_allow_loopback,
                                dns_resolver=dns_resolver,
                            )
                        except SSRFBlockedError as exc:
                            if redirect_count == 0:
                                logger.warning(
                                    "Target rejected by SSRF defense: %s (%s)", safe_url, exc
                                )
                            else:
                                logger.warning(
                                    "SSRF blocked during redirect for '%s': %s", safe_url, exc
                                )
                            return _build_probe_error_result(url, "ssrf_blocked", latency_ms=None)
                        except DNSResolutionError as exc:
                            elapsed_ms = round((time.monotonic() - start_mono) * 1000, 2)
                            logger.warning("Target DNS resolution failed: %s (%s)", safe_url, exc)
                            return _build_probe_error_result(
                                url, "dns_error", latency_ms=elapsed_ms
                            )

                        # Step 2: Rewrite request target to pinned IP while preserving Host and SNI
                        host_literal = f"[{pinned_ip}]" if ":" in pinned_ip else pinned_ip
                        rewritten_netloc = (
                            f"{host_literal}:{parsed.port}" if parsed.port else host_literal
                        )
                        pinned_url = urllib.parse.urlunsplit(
                            (
                                parsed.scheme,
                                rewritten_netloc,
                                parsed.path or "/",
                                parsed.query,
                                parsed.fragment,
                            )
                        )

                        headers = {
                            "Host": parsed.netloc,
                            "User-Agent": ua,
                            "Accept": "*/*",
                        }
                        extensions: dict[str, Any] | None = None
                        if parsed.scheme.lower() == "https" and parsed.hostname:
                            extensions = {"sni_hostname": parsed.hostname}

                        request_kwargs: dict[str, Any] = {
                            "headers": headers,
                        }
                        if extensions is not None:
                            request_kwargs["extensions"] = extensions

                        # Step 3: Stream request to pinned IP
                        request = client.build_request("GET", pinned_url, **request_kwargs)
                        t0 = time.monotonic()
                        response = await client.send(request, stream=True)
                        t1 = time.monotonic()
                        latency_ms = round((t1 - t0) * 1000)

                        if response.is_redirect or (
                            response.status_code in (301, 302, 303, 307, 308)
                            and "Location" in response.headers
                        ):
                            await response.aclose()
                            if redirect_count >= max_redirs:
                                raise httpx.TooManyRedirects(
                                    f"Exceeded maximum allowed redirects ({max_redirs})"
                                )
                            location = response.headers.get("Location")
                            if not location:
                                status_code = response.status_code
                                final_url = current_url
                                break

                            next_url = urllib.parse.urljoin(current_url, location.strip())
                            next_parsed = urllib.parse.urlsplit(next_url)
                            if next_parsed.scheme.lower() not in ("http", "https"):
                                raise SSRFBlockedError(
                                    f"Unsupported redirect scheme '{next_parsed.scheme}'."
                                )

                            current_url = next_url
                            redirect_count += 1
                            continue

                        status_code = response.status_code
                        final_url = current_url

                        # Memory-bounded streaming: stop reading if body exceeds max_response_bytes
                        try:
                            async for chunk in response.aiter_bytes():
                                bytes_read += len(chunk)
                                if bytes_read > max_bytes:
                                    logger.warning(
                                        "Response from '%s' exceeded MAX_RESPONSE_BYTES (%d), "
                                        "terminating stream early",
                                        safe_url,
                                        max_bytes,
                                    )
                                    break
                        finally:
                            await response.aclose()
                        break

                # Step 4: Status code classification
                if status_code is not None:
                    try:
                        outcome = classify_status_code(status_code)
                    except ValueError:
                        outcome = PingOutcome.DOWN
                else:
                    outcome = PingOutcome.DOWN

                return PingResultDTO(
                    outcome=outcome,
                    status_code=status_code,
                    latency_ms=latency_ms,
                    error_detail=None,
                    original_url=url,
                    final_url=final_url,
                )

            except SSRFBlockedError as exc:
                logger.warning("SSRF blocked during redirect for '%s': %s", safe_url, exc)
                return _build_probe_error_result(url, "ssrf_blocked", latency_ms=None)

            except httpx.RequestError as exc:
                elapsed_ms = round((time.monotonic() - start_mono) * 1000, 2)
                outcome = PingOutcome.UNREACHABLE
                error_detail = "request_error"
                for exc_type, mapped_outcome, mapped_detail in HTTPX_EXCEPTION_TABLE:
                    if isinstance(exc, exc_type):
                        outcome = mapped_outcome
                        if exc_type is httpx.ConnectError and is_tls_exception(exc):
                            error_detail = "tls_error"
                            logger.info("TLS certificate error on '%s' (%s)", safe_url, exc)
                        else:
                            error_detail = mapped_detail
                            logger.info("%s on '%s' (%s)", mapped_detail, safe_url, exc)
                        break
                return _build_probe_error_result(
                    url, error_detail, latency_ms=elapsed_ms, outcome=outcome
                )

    except TimeoutError as exc:
        elapsed_ms = round((time.monotonic() - start_mono) * 1000, 2)
        logger.info("Total probe deadline exceeded for '%s' (%s)", safe_url, exc)
        return _build_probe_error_result(url, "total_timeout", latency_ms=elapsed_ms)


# =============================================================================
# 6. Synchronous Worker Bridge Functions
# =============================================================================


def robust_ping(
    url: str,
    allow_loopback: bool = False,
    transport: httpx.AsyncBaseTransport | None = None,
    dns_resolver: Callable[..., Any] | None = None,
    total_timeout: float | None = None,
) -> PingResultDTO:
    """
    Synchronous bridge for Celery workers to execute an uptime health probe.

    Uses asyncio.run() to safely invoke the asynchronous httpx network engine.
    """
    settings = get_settings()
    return asyncio.run(
        perform_http_probe(
            url=url,
            user_agent=settings.http_user_agent,
            allow_loopback=allow_loopback,
            transport=transport,
            dns_resolver=dns_resolver,
            total_timeout=total_timeout,
        )
    )
