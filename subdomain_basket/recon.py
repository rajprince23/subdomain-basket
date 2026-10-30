from __future__ import annotations

import html
import http.client
import json
import queue
import re
import shutil
import socket
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


MAX_HOSTS = 50
TIMEOUT_SECONDS = 5
TOOL_TIMEOUT_SECONDS = 70
MIN_REQUEST_INTERVAL_SECONDS = 1.0
MAX_CT_RESPONSE_BYTES = 5 * 1024 * 1024
MAX_PAGE_BYTES = 64 * 1024
USER_AGENT = "SubdomainBasket/0.1 (authorization-only reconnaissance)"
DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
TITLE_PATTERN = re.compile(rb"<title\b[^>]*>(.*?)</title\s*>", re.IGNORECASE | re.DOTALL)


class ReconError(ValueError):
    """Raised when an input or reconnaissance operation is invalid."""


class RateLimiter:
    def __init__(self, interval: float = MIN_REQUEST_INTERVAL_SECONDS) -> None:
        self._interval = interval
        self._last_request: float | None = None

    def wait(self) -> None:
        now = time.monotonic()
        if self._last_request is not None:
            delay = self._interval - (now - self._last_request)
            if delay > 0:
                time.sleep(delay)
        self._last_request = time.monotonic()


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def normalize_domain(value: str) -> str:
    candidate = value.strip().rstrip(".")
    if not candidate or "://" in candidate or any(char in candidate for char in "/:@?#"):
        raise ReconError("Enter a domain only, such as example.com; URLs and paths are not accepted.")
    try:
        domain = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ReconError("The domain contains invalid internationalized characters.") from exc
    if len(domain) > 253 or "." not in domain:
        raise ReconError("Enter a fully qualified domain name, such as example.com.")
    labels = domain.split(".")
    if any(not DOMAIN_LABEL.fullmatch(label) for label in labels):
        raise ReconError("The domain contains an invalid DNS label.")
    if all(char.isdigit() or char == "." for char in domain):
        raise ReconError("IP addresses are not accepted; enter an authorized domain name.")
    return domain


def is_in_scope(host: str, domain: str) -> bool:
    try:
        normalized_host = normalize_domain(host)
    except ReconError:
        return False
    return normalized_host == domain or normalized_host.endswith("." + domain)


def discover_subdomains(domain: str, limiter: RateLimiter) -> tuple[list[str], str | None]:
    query = urllib.parse.urlencode({"q": f"%.{domain}", "output": "json"})
    request = urllib.request.Request(
        f"https://crt.sh/?{query}",
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
    )
    limiter.wait()
    try:
        opener = urllib.request.build_opener(_NoRedirectHandler)
        with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
            body = response.read(MAX_CT_RESPONSE_BYTES + 1)
        if len(body) > MAX_CT_RESPONSE_BYTES:
            return [], f"Certificate Transparency response exceeded {MAX_CT_RESPONSE_BYTES} bytes."
        entries = json.loads(body)
        if not isinstance(entries, list):
            return [], "Certificate Transparency returned an unexpected response."
    except (
        OSError,
        urllib.error.URLError,
        http.client.HTTPException,
        json.JSONDecodeError,
        TimeoutError,
    ) as exc:
        return [], f"Passive Certificate Transparency lookup failed: {exc}"

    discovered: set[str] = {domain}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        names = entry.get("name_value", "")
        if not isinstance(names, str):
            continue
        for raw_host in names.splitlines():
            host = raw_host.strip().lower()
            if host.startswith("*."):
                host = host[2:]
            if is_in_scope(host, domain):
                discovered.add(host)
    return sorted(discovered)[:MAX_HOSTS], None


def _discovery_tool_commands(domain: str) -> list[tuple[str, list[str]]]:
    katana_scope = rf"^https?://(?:[a-z0-9-]+\.)*{re.escape(domain)}(?::\d+)?/"
    return [
        (
            "subfinder",
            [
                "subfinder", "-d", domain, "-silent", "-timeout", "5",
                "-max-time", "1", "-rl", "1", "-c", "1",
            ],
        ),
        ("amass", ["amass", "enum", "-passive", "-d", domain, "-timeout", "1"]),
        (
            "katana",
            [
                "katana", "-u", f"https://{domain}", "-silent", "-d", "1",
                "-c", "1", "-rl", "1", "-timeout", "5", "-cs", katana_scope,
            ],
        ),
        ("assetfinder", ["assetfinder", "--subs-only", domain]),
        ("sublist3r", ["sublist3r", "-d", domain, "-t", "1"]),
    ]


def _hosts_from_output(output: str, domain: str) -> set[str]:
    hosts: set[str] = set()
    for line in output.splitlines():
        candidate = line.strip()
        if not candidate:
            continue
        if "://" in candidate:
            try:
                candidate = urllib.parse.urlsplit(candidate).hostname or ""
            except ValueError:
                continue
        if candidate.startswith("*."):
            candidate = candidate[2:]
        candidate = candidate.rstrip(".")
        if is_in_scope(candidate, domain):
            try:
                hosts.add(normalize_domain(candidate))
            except ReconError:
                continue
        if len(hosts) >= MAX_HOSTS:
            break
    return hosts


def _text_from_process_output(output: str | bytes | None) -> str:
    if isinstance(output, bytes):
        return output.decode("utf-8", errors="replace")
    return output or ""


def run_discovery_tool(name: str, command: list[str], domain: str) -> tuple[set[str], dict[str, Any]]:
    if shutil.which(name) is None:
        return set(), {
            "name": name,
            "status": "unavailable",
            "hosts_found": 0,
            "error": f"{name} executable was not found on PATH.",
        }

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=TOOL_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = _text_from_process_output(exc.stdout)
        hosts = _hosts_from_output(stdout, domain)
        return hosts, {
            "name": name,
            "status": "timed_out",
            "hosts_found": len(hosts),
            "error": f"Exceeded the {TOOL_TIMEOUT_SECONDS}-second time limit.",
        }
    except OSError as exc:
        return set(), {
            "name": name,
            "status": "failed",
            "hosts_found": 0,
            "error": str(exc),
        }

    hosts = _hosts_from_output(completed.stdout, domain)
    if completed.returncode:
        error = completed.stderr.strip() or f"Exited with status {completed.returncode}."
        return hosts, {
            "name": name,
            "status": "failed",
            "hosts_found": len(hosts),
            "error": error[:1000],
        }
    return hosts, {
        "name": name,
        "status": "completed",
        "hosts_found": len(hosts),
        "error": None,
    }


def resolve_host(host: str, limiter: RateLimiter) -> tuple[list[str], str | None]:
    limiter.wait()
    result_queue: queue.Queue[tuple[list[tuple[Any, ...]] | None, str | None]] = queue.Queue(maxsize=1)

    def lookup() -> None:
        try:
            result_queue.put((socket.getaddrinfo(host, None, type=socket.SOCK_STREAM), None))
        except OSError as exc:
            result_queue.put((None, str(exc)))

    threading.Thread(target=lookup, daemon=True).start()
    try:
        records, error = result_queue.get(timeout=TIMEOUT_SECONDS)
    except queue.Empty:
        return [], f"DNS resolution exceeded the {TIMEOUT_SECONDS}-second timeout."
    if error:
        return [], error
    if records is None:
        return [], "DNS resolution returned no result."
    addresses = sorted({record[4][0] for record in records})
    return addresses, None if addresses else "DNS returned no addresses."


def _extract_title(body: bytes, headers: Any) -> str:
    match = TITLE_PATTERN.search(body)
    if not match:
        return ""
    charset = headers.get_content_charset() if headers is not None else None
    try:
        title = match.group(1).decode(charset or "utf-8", errors="replace")
    except LookupError:
        title = match.group(1).decode("utf-8", errors="replace")
    return html.unescape(" ".join(title.split()))[:300]


def _certificate_details(
    connection: http.client.HTTPSConnection, authorized_domain: str
) -> dict[str, Any]:
    if connection.sock is None:
        return {}
    certificate = connection.sock.getpeercert()
    if not certificate:
        return {}

    def format_name(parts: tuple[tuple[tuple[str, str], ...], ...]) -> str:
        return ", ".join(f"{key}={value}" for group in parts for key, value in group)

    details = {
        "subject": format_name(certificate.get("subject", ())),
        "issuer": format_name(certificate.get("issuer", ())),
        "not_before": certificate.get("notBefore", ""),
        "not_after": certificate.get("notAfter", ""),
        "subject_alt_names": [],
    }
    for kind, value in certificate.get("subjectAltName", ()):
        candidate = value[2:] if value.startswith("*.") else value
        if kind == "DNS" and is_in_scope(candidate, authorized_domain):
            details["subject_alt_names"].append(value)
            if len(details["subject_alt_names"]) == 50:
                break
    return details


@dataclass
class EndpointResult:
    status: int | None
    title: str
    tls_certificate: dict[str, Any] | None
    error: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "title": self.title,
            "tls_certificate": self.tls_certificate,
            "error": self.error,
        }


def check_endpoint(
    host: str, scheme: str, limiter: RateLimiter, authorized_domain: str
) -> EndpointResult:
    if scheme not in {"http", "https"}:
        raise ReconError("Only HTTP and HTTPS checks are supported.")
    limiter.wait()
    connection: http.client.HTTPConnection
    certificate = None
    status = None
    title = ""
    try:
        if scheme == "https":
            connection = http.client.HTTPSConnection(
                host,
                timeout=TIMEOUT_SECONDS,
                context=ssl.create_default_context(),
            )
            connection.connect()
            certificate = _certificate_details(connection, authorized_domain)
        else:
            connection = http.client.HTTPConnection(host, timeout=TIMEOUT_SECONDS)
        connection.request("GET", "/", headers={"User-Agent": USER_AGENT, "Connection": "close"})
        response = connection.getresponse()
        status = response.status
        body = response.read(MAX_PAGE_BYTES)
        title = _extract_title(body, response.headers)
        return EndpointResult(status, title, certificate, None)
    except (OSError, ssl.SSLError, http.client.HTTPException, TimeoutError) as exc:
        return EndpointResult(status, title, certificate, str(exc))
    finally:
        if "connection" in locals():
            connection.close()


def inspect_domain(domain: str) -> dict[str, Any]:
    domain = normalize_domain(domain)
    limiter = RateLimiter()
    ct_hosts, discovery_error = discover_subdomains(domain, limiter)
    source_results: list[dict[str, Any]] = [
        {
            "name": "crt.sh Certificate Transparency",
            "status": "failed" if discovery_error else "completed",
            "hosts_found": len(ct_hosts),
            "error": discovery_error,
        }
    ]
    host_sources: dict[str, set[str]] = {domain: {"root input"}}
    for host in ct_hosts:
        if is_in_scope(host, domain):
            host_sources.setdefault(host, set()).add("crt.sh")

    for name, command in _discovery_tool_commands(domain):
        discovered, status = run_discovery_tool(name, command, domain)
        source_results.append(status)
        for host in discovered:
            host_sources.setdefault(host, set()).add(name)

    hosts = sorted(host_sources)[:MAX_HOSTS]
    results: list[dict[str, Any]] = []
    for host in hosts:
        addresses, dns_error = resolve_host(host, limiter)
        if addresses:
            http_result = check_endpoint(host, "http", limiter, domain)
            https_result = check_endpoint(host, "https", limiter, domain)
        else:
            skip_message = f"Skipped because DNS resolution failed: {dns_error or 'no addresses returned'}"
            http_result = EndpointResult(None, "", None, skip_message)
            https_result = EndpointResult(None, "", None, skip_message)
        http_data = http_result.as_dict()
        https_data = https_result.as_dict()
        results.append(
            {
                "host": host,
                "discovery_sources": sorted(host_sources[host]),
                "dns_addresses": addresses,
                "dns_error": dns_error,
                "activity": {
                    "dns_resolved": bool(addresses),
                    "http_reachable": http_result.status is not None,
                    "http_status": http_result.status,
                    "https_reachable": https_result.status is not None,
                    "https_status": https_result.status,
                },
                "http": http_data,
                "https": https_data,
            }
        )
    return {
        "domain": domain,
        "discovery_source": ", ".join(source["name"] for source in source_results),
        "discovery_error": discovery_error,
        "discovery_sources": source_results,
        "activity_definition": (
            "Current DNS resolution and HTTP/HTTPS reachability observed during this run; "
            "no historical activity is measured."
        ),
        "hosts": results,
    }
