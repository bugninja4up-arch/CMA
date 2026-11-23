"""Bounded, GET-only HTML inventory crawler for explicitly scoped targets."""
from __future__ import annotations

import http.client
import time
from html.parser import HTMLParser
from typing import Any
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

from tools.scope import is_url_in_scope

_MAX_PAGES = 5
_MAX_RESPONSE_BYTES = 256 * 1024
_REQUEST_TIMEOUT = 4.0
_REQUEST_INTERVAL = 0.2
_MAX_URL_LENGTH = 4096
_MAX_LINKS = 50
_MAX_SCRIPTS = 50
_MAX_FORMS = 20
_MAX_INPUTS_PER_FORM = 30
_MAX_TITLE_LENGTH = 200
_USER_AGENT = "CMA/0.1 (bounded HTML inventory)"
_NOTE = (
    "GET-only HTML inventory; no forms submitted, cookies/auth sent, redirects followed, "
    "or response bodies returned. Query strings and fragments are omitted from output."
)


def _safe_http_url(value: object) -> str | None:
    """Validate and return an HTTP(S) URL with query and fragment removed."""
    if not isinstance(value, str) or not value or len(value) > _MAX_URL_LENGTH:
        return None
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        return None
    try:
        parts = urlsplit(value)
        if (
            parts.scheme.lower() not in {"http", "https"}
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
        ):
            return None
        _ = parts.port  # Validate malformed and out-of-range ports.
    except ValueError:
        return None

    # Preserve a specified port while normalizing scheme/host casing. Bracket IPv6.
    host = parts.hostname.lower().rstrip(".")
    if not host:
        return None
    if ":" in host:
        host = f"[{host}]"
    port = parts.port
    netloc = host + (f":{port}" if port is not None else "")
    path = quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~")
    return urlunsplit((parts.scheme.lower(), netloc, path, "", ""))


def _origin(url: str) -> tuple[str, str, int] | None:
    try:
        parts = urlsplit(url)
        if not parts.hostname:
            return None
        scheme = parts.scheme.lower()
        port = parts.port or (443 if scheme == "https" else 80)
        return (scheme, parts.hostname.lower().rstrip("."), port)
    except ValueError:
        return None


def _scope_allows(url: str, scope: dict[str, Any] | None) -> bool:
    try:
        return is_url_in_scope(url, scope)
    except (TypeError, ValueError, AttributeError):
        return False


class _InventoryParser(HTMLParser):
    """Collect only explicitly allowed HTML inventory fields; never values."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_parts: list[str] = []
        self._in_title = False
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._form: dict[str, Any] | None = None

    @staticmethod
    def _attr(attrs: list[tuple[str, str | None]], key: str) -> str | None:
        for name, value in attrs:
            if name.lower() == key and value is not None:
                return value
        return None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag == "title":
            self._in_title = True
        if tag == "a":
            href = self._attr(attrs, "href")
            if href is not None:
                self.links.append(href)
        elif tag == "script":
            src = self._attr(attrs, "src")
            if src is not None:
                self.scripts.append(src)
        elif tag == "form":
            if len(self.forms) < _MAX_FORMS:
                raw_method = self._attr(attrs, "method") or "GET"
                method = raw_method.strip().upper()
                if method not in {"GET", "POST", "DIALOG"}:
                    method = "OTHER"
                self._form = {
                    "action_raw": self._attr(attrs, "action") or "",
                    "method": method,
                    "inputs": [],
                }
                self.forms.append(self._form)
            else:
                self._form = None
        elif tag == "input" and self._form is not None:
            inputs = self._form["inputs"]
            if len(inputs) < _MAX_INPUTS_PER_FORM:
                name = self._attr(attrs, "name")
                input_type = self._attr(attrs, "type") or "text"
                item: dict[str, str] = {"type": input_type[:40]}
                if name is not None:
                    item["name"] = name[:100]
                inputs.append(item)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "title":
            self._in_title = False
        elif tag == "form":
            self._form = None

    def handle_data(self, data: str) -> None:
        if self._in_title and sum(map(len, self.title_parts)) < _MAX_TITLE_LENGTH:
            self.title_parts.append(data[:_MAX_TITLE_LENGTH])

    def title(self) -> str | None:
        value = " ".join(" ".join(self.title_parts).split()).strip()
        return value[:_MAX_TITLE_LENGTH] or None


def _resolve_inventory_url(raw: str, page_url: str) -> str | None:
    try:
        return _safe_http_url(urljoin(page_url, raw.strip()))
    except (TypeError, ValueError):
        return None


def _open_get(url: str) -> tuple[int, str, bytes, bool]:
    """Issue exactly one direct HTTP(S) GET and return bounded response metadata."""
    parts = urlsplit(url)
    host = parts.hostname
    if host is None:
        raise ValueError("invalid URL")
    port = parts.port
    target = parts.path or "/"
    connection_type = http.client.HTTPSConnection if parts.scheme == "https" else http.client.HTTPConnection
    connection = connection_type(host, port=port, timeout=_REQUEST_TIMEOUT)
    try:
        connection.request(
            "GET",
            target,
            headers={
                "User-Agent": _USER_AGENT,
                "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        status_code = response.status
        content_type_header = response.getheader("Content-Type", "")
        content_type = content_type_header.split(";", 1)[0].strip().lower()[:100]
        mime = content_type
        declared_length: int | None = None
        try:
            if response.getheader("Content-Length") is not None:
                declared_length = int(response.getheader("Content-Length", ""))
        except (TypeError, ValueError):
            pass
        body = response.read(_MAX_RESPONSE_BYTES)
        truncated = len(body) >= _MAX_RESPONSE_BYTES or (
            declared_length is not None and declared_length > len(body)
        )
        if declared_length is not None and declared_length > _MAX_RESPONSE_BYTES:
            truncated = True
        return status_code, content_type, body, truncated
    finally:
        connection.close()


def crawl_site(
    start_url: str,
    *,
    scope: dict | None = None,
    max_pages: int = 5,
) -> dict:
    """Inventory a bounded set of in-scope HTML pages on the start URL's origin.

    Only explicitly scoped HTTP(S) URLs are requested. Requests are sequential,
    GET-only, direct (no environment proxy), and never follow redirects.
    """
    base_result: dict[str, Any] = {
        "executed": False,
        "request_count": 0,
        "pages": [],
        "note": _NOTE,
    }
    if isinstance(max_pages, bool) or not isinstance(max_pages, int) or not (1 <= max_pages <= _MAX_PAGES):
        return {**base_result, "status": "invalid", "error": "max_pages must be an integer from 1 to 5."}

    start = _safe_http_url(start_url)
    if start is None or not _scope_allows(start_url, scope) or not _scope_allows(start, scope):
        return {**base_result, "status": "blocked", "error": "Start URL is invalid or outside configured scope."}
    initial_origin = _origin(start)
    if initial_origin is None:
        return {**base_result, "status": "blocked", "error": "Start URL is invalid or outside configured scope."}

    queue = [start]
    queued = {start}
    visited: set[str] = set()
    last_request_at: float | None = None
    any_network_error = False
    base_result["executed"] = True

    while queue and len(visited) < max_pages and base_result["request_count"] < _MAX_PAGES:
        url = queue.pop(0)
        if url in visited:
            continue
        # Re-check both origin and configured scope immediately before each request.
        if _origin(url) != initial_origin or not _scope_allows(url, scope):
            continue
        if last_request_at is not None:
            delay = _REQUEST_INTERVAL - (time.monotonic() - last_request_at)
            if delay > 0:
                time.sleep(delay)
        visited.add(url)
        base_result["request_count"] += 1
        last_request_at = time.monotonic()

        page: dict[str, Any] = {
            "url": url,
            "status_code": None,
            "content_type": "",
            "bytes": 0,
            "truncated": False,
            "title": None,
            "links": [],
            "scripts": [],
            "forms": [],
        }
        try:
            status_code, content_type, body, truncated = _open_get(url)
            page.update(
                {
                    "status_code": status_code,
                    "content_type": content_type,
                    "bytes": len(body),
                    "truncated": truncated,
                }
            )
            if content_type in {"text/html", "application/xhtml+xml"}:
                text = body.decode("utf-8", errors="replace")
                parser = _InventoryParser()
                try:
                    parser.feed(text)
                    parser.close()
                except Exception:
                    # Malformed documents still yield whatever was safely parsed.
                    pass
                page["title"] = parser.title()
                safe_links: list[str] = []
                for raw in parser.links:
                    resolved = _resolve_inventory_url(raw, url)
                    if resolved is None or resolved in safe_links:
                        continue
                    if len(safe_links) < _MAX_LINKS:
                        safe_links.append(resolved)
                    if (
                        _origin(resolved) == initial_origin
                        and resolved not in queued
                        and resolved not in visited
                        and _scope_allows(resolved, scope)
                    ):
                        queued.add(resolved)
                        if len(queued) <= _MAX_PAGES:
                            queue.append(resolved)
                safe_scripts: list[str] = []
                for raw in parser.scripts:
                    resolved = _resolve_inventory_url(raw, url)
                    if resolved is not None and resolved not in safe_scripts and len(safe_scripts) < _MAX_SCRIPTS:
                        safe_scripts.append(resolved)
                forms: list[dict[str, Any]] = []
                for form in parser.forms:
                    action = _resolve_inventory_url(form["action_raw"], url)
                    forms.append(
                        {
                            "action": action,
                            "method": form["method"],
                            "inputs": form["inputs"],
                        }
                    )
                page["links"] = safe_links
                page["scripts"] = safe_scripts
                page["forms"] = forms
            page["status"] = "http"
        except (OSError, http.client.HTTPException, ValueError, TimeoutError):
            # Do not include exception text: it can contain target URLs or response data.
            any_network_error = True
            page["status"] = "network_error"
        base_result["pages"].append(page)

    base_result["status"] = "partial" if any_network_error else "completed"
    return base_result
