"""Synthetic, loopback-only training lab for CMA."""
from __future__ import annotations

from typing import Any

__all__ = ["LocalLabServer", "MAX_POST_BYTES", "allowed_urls_for_port"]


def __getattr__(name: str) -> Any:
    if name in __all__:
        from . import server

        return getattr(server, name)
    raise AttributeError(name)
