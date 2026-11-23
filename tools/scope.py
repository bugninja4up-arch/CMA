"""Shared fail-closed URL scope checks for active tools."""
from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit


def normalize_http_url(value: object) -> str:
    """Return a valid HTTP(S) URL without a trailing slash, or an empty string."""
    if not isinstance(value, str):
        return ""
    candidate = value.strip()
    try:
        parts = urlsplit(candidate)
        if (
            parts.scheme not in {"http", "https"}
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
        ):
            return ""
        # Accessing .port validates malformed ports and out-of-range values.
        _ = parts.port
    except ValueError:
        return ""
    return candidate.rstrip("/")


def is_url_in_scope(url: str, scope: dict[str, Any] | None) -> bool:
    """Check an exact URL or hostname allowlist; domains cover standard ports only."""
    normalized = normalize_http_url(url)
    if not normalized or not isinstance(scope, dict):
        return False

    allowed_urls = scope.get("allowed_urls", []) or []
    if isinstance(allowed_urls, (list, tuple)):
        for allowed_url in allowed_urls:
            if normalized == normalize_http_url(allowed_url):
                return True

    parts = urlsplit(normalized)
    default_port = 443 if parts.scheme == "https" else 80
    if parts.port not in (None, default_port):
        return False

    hostname = (parts.hostname or "").lower().rstrip(".")
    allowed_domains = scope.get("allowed_domains", []) or []
    if not isinstance(allowed_domains, (list, tuple)):
        return False
    for domain_entry in allowed_domains:
        candidate = str(domain_entry).strip().lower()
        if "://" in candidate:
            try:
                candidate = (urlsplit(candidate).hostname or "").lower()
            except ValueError:
                continue
        candidate = candidate.lstrip("*.").rstrip(".")
        if candidate and (hostname == candidate or hostname.endswith("." + candidate)):
            return True
    return False
