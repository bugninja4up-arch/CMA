"""Bounded browser-based inspection of an explicitly scoped HTML snapshot.

The target receives one direct GET with its query and fragment removed. The
response is capped, redirects are not followed, and Chromium inspects the
captured HTML offline with JavaScript and all resource requests disabled.
"""
from __future__ import annotations

import http.client
import os
import shutil
import time
from typing import Any
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

from tools.scope import is_url_in_scope, normalize_http_url

_MAX_RESPONSE_BYTES = 256 * 1024
_MAX_ITEMS = 30
_MAX_TEXT = 512
_MAX_URL_LENGTH = 4096
_HTTP_TIMEOUT_SECONDS = 4.0
_BROWSER_TIMEOUT_MS = 5000
_USER_AGENT = "CMA/0.1 (bounded page inspection)"
_NOTE = (
    "One bounded GET only; redirects are not followed. Chromium inspects the captured HTML offline; "
    "JavaScript and page resource requests are blocked, forms are never submitted, and the body is not returned."
)


def _origin(url: str) -> tuple[str, str, int] | None:
    try:
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        host = (parts.hostname or "").lower().rstrip(".")
        if scheme not in {"http", "https"} or not host:
            return None
        port = parts.port or (443 if scheme == "https" else 80)
        return scheme, host, port
    except ValueError:
        return None


def _request_url(value: object) -> str | None:
    """Return a credential-free HTTP URL with query and fragment removed."""
    if not isinstance(value, str) or not value or len(value) > _MAX_URL_LENGTH:
        return None
    if any(ord(char) <= 32 or ord(char) == 127 for char in value):
        return None
    candidate = value.strip()
    if not normalize_http_url(candidate):
        return None
    try:
        parts = urlsplit(candidate)
        if parts.username is not None or parts.password is not None:
            return None
        host = (parts.hostname or "").lower().rstrip(".")
        if not host:
            return None
        if ":" in host:
            host = f"[{host}]"
        port = parts.port
        netloc = host + (f":{port}" if port is not None else "")
        path = quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~")
        return urlunsplit((parts.scheme.lower(), netloc, path, "", ""))
    except (TypeError, ValueError):
        return None


def _safe_scope_allows(url: str, scope: dict | None) -> bool:
    try:
        return is_url_in_scope(url, scope)
    except (TypeError, ValueError, AttributeError):
        return False


def _path_metadata(raw: str | None, base_url: str) -> str | None:
    """Return same-origin path metadata only; omit queries, fragments and hosts."""
    if not raw or len(raw) > _MAX_URL_LENGTH:
        return None
    try:
        resolved = urljoin(base_url, raw)
        parts = urlsplit(resolved)
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            return None
        if _origin(resolved) != _origin(base_url):
            return None
        return (parts.path or "/")[:_MAX_TEXT]
    except (TypeError, ValueError):
        return None


def _empty_result(status: str, error: str | None, url: str | None) -> dict[str, Any]:
    return {
        "status": status,
        "executed": False,
        "error": error,
        "url": url,
        "http_status": None,
        "content_type": None,
        "response_bytes": 0,
        "truncated": False,
        "title": None,
        "hrefs": [],
        "script_src_paths": [],
        "forms": [],
        "request_count": 0,
        "blocked_browser_resource_count": 0,
        "redirect_seen": False,
        "redirect_blocked": False,
        "note": _NOTE,
    }


def _fetch_one(url: str) -> tuple[int, str, bytes, bool]:
    """Make exactly one direct GET; do not use proxies, cookies, or redirects."""
    parts = urlsplit(url)
    if not parts.hostname:
        raise ValueError("invalid target")
    connection_type = http.client.HTTPSConnection if parts.scheme == "https" else http.client.HTTPConnection
    connection = connection_type(parts.hostname, port=parts.port, timeout=_HTTP_TIMEOUT_SECONDS)
    path = quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~")
    try:
        connection.request(
            "GET",
            path,
            headers={
                "User-Agent": _USER_AGENT,
                "Accept": "text/html,application/xhtml+xml;q=0.9",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        declared_length = None
        try:
            raw_length = response.getheader("Content-Length")
            declared_length = int(raw_length) if raw_length is not None else None
        except (TypeError, ValueError):
            pass
        body = response.read(_MAX_RESPONSE_BYTES)
        truncated = (
            declared_length is not None and declared_length > len(body)
        ) or (declared_length is None and len(body) >= _MAX_RESPONSE_BYTES)
        content_type = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()[:100]
        return response.status, content_type, body, truncated
    finally:
        connection.close()


def _load_playwright():
    """Import the optional browser dependency lazily."""
    from playwright.sync_api import sync_playwright

    return sync_playwright


def _launch_options() -> dict[str, Any]:
    options: dict[str, Any] = {"headless": True, "timeout": _BROWSER_TIMEOUT_MS}
    executable = shutil.which("chromium") or shutil.which("chromium-browser")
    if executable:
        options["executable_path"] = executable
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            options["args"] = ["--no-sandbox"]
    return options


def _collect_metadata(page, base_url: str) -> tuple[str | None, list[str], list[str], list[dict[str, Any]]]:
    """Extract small DOM metadata sets without evaluating page-authored JavaScript."""
    deadline = time.monotonic() + 2.0
    title: str | None = None
    hrefs: list[str] = []
    script_paths: list[str] = []
    forms: list[dict[str, Any]] = []

    try:
        value = page.title()
        title = value[:_MAX_TEXT] if value else None
    except Exception:
        pass

    for selector, attribute, output in (
        ("a[href]", "href", hrefs),
        ("script[src]", "src", script_paths),
    ):
        try:
            locator = page.locator(selector)
            for index in range(min(locator.count(), _MAX_ITEMS)):
                if time.monotonic() >= deadline:
                    break
                try:
                    path = _path_metadata(locator.nth(index).get_attribute(attribute), base_url)
                    if path and path not in output:
                        output.append(path)
                except Exception:
                    continue
        except Exception:
            continue

    try:
        locator = page.locator("form")
        for index in range(min(locator.count(), _MAX_ITEMS)):
            if time.monotonic() >= deadline:
                break
            try:
                form = locator.nth(index)
                action = _path_metadata(form.get_attribute("action"), base_url)
                method = (form.get_attribute("method") or "GET").strip().upper()
                if method not in {"GET", "POST", "DIALOG"}:
                    method = "OTHER"
                fields: list[dict[str, str]] = []
                inputs = form.locator("input")
                for field_index in range(min(inputs.count(), _MAX_ITEMS)):
                    if time.monotonic() >= deadline:
                        break
                    try:
                        field = inputs.nth(field_index)
                        name = field.get_attribute("name") or ""
                        field_type = field.get_attribute("type") or "text"
                        fields.append({"name": name[:128], "type": field_type[:32]})
                    except Exception:
                        continue
                forms.append({"action": action, "method": method, "inputs": fields})
            except Exception:
                continue
    except Exception:
        pass

    return title, hrefs, script_paths, forms


def inspect_page(url: str, *, scope: dict | None = None) -> dict:
    """Inspect one scoped HTML page using one bounded GET and offline Chromium.

    Query strings and fragments are removed before the target request. The
    canonical request URL must itself be in scope. Redirects are observations,
    not followed. Chromium receives only the bounded HTML snapshot; JavaScript
    is disabled and every browser-originated network request is aborted.
    """
    canonical = _request_url(url)
    if canonical is None or not _safe_scope_allows(url, scope) or not _safe_scope_allows(canonical, scope):
        return _empty_result("blocked", "invalid_or_out_of_scope", canonical)

    try:
        sync_playwright = _load_playwright()
    except Exception:
        return _empty_result("dependency_missing", "playwright_or_chromium_not_installed", canonical)

    result = _empty_result("error", "inspection_failed", canonical)
    browser = context = page = None
    request_count = 0
    blocked_resources = 0
    try:
        with sync_playwright() as playwright:
            try:
                browser = playwright.chromium.launch(**_launch_options())
            except Exception:
                return _empty_result("browser_unavailable", "chromium_could_not_start", canonical)

            context = browser.new_context(
                java_script_enabled=False,
                service_workers="block",
                accept_downloads=False,
            )

            def abort_browser_request(route) -> None:
                nonlocal blocked_resources
                blocked_resources += 1
                try:
                    route.abort()
                except Exception:
                    pass

            context.route("**/*", abort_browser_request)
            page = context.new_page()

            request_count = 1
            try:
                http_status, content_type, body, truncated = _fetch_one(canonical)
            except (OSError, http.client.HTTPException, TimeoutError, ValueError):
                result = _empty_result("network_error", "request_failed", canonical)
                result.update({"executed": True, "request_count": request_count})
                return result

            redirect_seen = 300 <= http_status < 400
            base = _empty_result("ok", None, canonical)
            base.update({
                "executed": True,
                "http_status": http_status,
                "content_type": content_type or None,
                "response_bytes": len(body),
                "truncated": truncated,
                "request_count": request_count,
                "redirect_seen": redirect_seen,
                "redirect_blocked": redirect_seen,
            })
            if redirect_seen:
                base["status"] = "redirect_not_followed"
                base["blocked_browser_resource_count"] = blocked_resources
                return base
            if content_type not in {"text/html", "application/xhtml+xml"}:
                base["status"] = "not_html"
                base["blocked_browser_resource_count"] = blocked_resources
                return base

            try:
                page.set_default_timeout(1000)
                page.set_content(
                    body.decode("utf-8", errors="replace"),
                    wait_until="domcontentloaded",
                    timeout=3000,
                )
                title, hrefs, scripts, forms = _collect_metadata(page, canonical)
                base.update({
                    "status": "partial" if truncated else "ok",
                    "title": title,
                    "hrefs": hrefs,
                    "script_src_paths": scripts,
                    "forms": forms,
                })
            except Exception:
                base["status"] = "partial" if truncated else "error"
                base["error"] = "dom_inspection_failed"
            base["blocked_browser_resource_count"] = blocked_resources
            result = base
            return result
    finally:
        for resource in (page, context, browser):
            if resource is not None:
                try:
                    resource.close()
                except Exception:
                    pass
