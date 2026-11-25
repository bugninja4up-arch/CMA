"""One-time, scope-bound authorization for bounded live HTTP tools."""
from __future__ import annotations

import json
from typing import Any, Callable
from urllib.parse import urlsplit, urlunsplit

SESSION_HTTP_BUDGET = 100
REMOTE_HTTP_TOOLS = frozenset({"mutate_and_fuzz_request", "crawl_site", "inspect_page"})


def _has_targets(scope: dict[str, Any]) -> bool:
    domains = scope.get("allowed_domains", []) or []
    urls = scope.get("allowed_urls", []) or []
    return bool(
        isinstance(domains, (list, tuple)) and any(str(item).strip() for item in domains)
    ) or bool(
        isinstance(urls, (list, tuple)) and any(str(item).strip() for item in urls)
    )


def _redact_url(value: object) -> str:
    """Display an explicit scope URL without query, fragment, or credentials."""
    if not isinstance(value, str):
        return "[عنوان غير صالح]"
    try:
        parts = urlsplit(value)
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            return "[عنوان غير صالح]"
        host = parts.hostname
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        port = parts.port
        default_port = 443 if parts.scheme.lower() == "https" else 80
        authority = host if port in (None, default_port) else f"{host}:{port}"
        return urlunsplit((parts.scheme.lower(), authority, parts.path or "/", "", ""))
    except (TypeError, ValueError):
        return "[عنوان غير صالح]"


def _request_cost(name: str, arguments: dict[str, Any]) -> int:
    """Conservatively reserve the maximum number of requests a tool may send."""
    if name == "crawl_site":
        count = arguments.get("max_pages", 5)
        if isinstance(count, bool) or not isinstance(count, int):
            return 5
        return min(5, max(1, count))
    if name == "inspect_page":
        return 1
    if name == "mutate_and_fuzz_request":
        method = str(arguments.get("method", "")).strip().upper()
        if arguments.get("baseline_only") is True or method == "GET":
            return 1
        try:
            payload = json.loads(arguments.get("payload_json", ""))
        except (TypeError, json.JSONDecodeError):
            return 4
        return 1 + min(3, len(payload)) if isinstance(payload, dict) else 4
    return 0


class SessionAuthorization:
    """Authorize bounded live HTTP tools once per CLI run, not once per call."""

    def __init__(
        self,
        scope: dict[str, Any] | None,
        *,
        budget: int = SESSION_HTTP_BUDGET,
        input_fn: Callable[[str], str] = input,
        output_fn: Callable[..., Any] = print,
    ) -> None:
        if isinstance(budget, bool) or not isinstance(budget, int) or budget < 1:
            raise ValueError("Session HTTP budget must be a positive integer.")
        self.scope = scope if isinstance(scope, dict) else {}
        self.budget = budget
        self.remaining = budget
        self.input_fn = input_fn
        self.output_fn = output_fn
        self.authorized = False

    def authorize_session(self) -> bool:
        """Prompt once, showing exactly which configured scope will be enabled."""
        if not _has_targets(self.scope):
            self.output_fn("لا توجد نطاقات مضبوطة؛ طلبات HTTP إلى أهداف حية ستبقى معطلة.")
            return False

        self.output_fn("\nتفويض حملة الفحص لهذه الجلسة فقط:")
        domains = self.scope.get("allowed_domains", []) or []
        urls = self.scope.get("allowed_urls", []) or []
        if isinstance(domains, (list, tuple)) and domains:
            self.output_fn("  النطاقات المسموحة: " + ", ".join(str(item) for item in domains))
        if isinstance(urls, (list, tuple)) and urls:
            self.output_fn("  العناوين الدقيقة: " + ", ".join(_redact_url(item) for item in urls))
        self.output_fn(
            f"  الحد الإجمالي للأهداف الحية: {self.budget} طلب HTTP لهذه الجلسة. "
            "الزحف حتى 5 صفحات، وفحص GET واحد، أو حتى 4 طلبات مقارنة POST؛ "
            "لا تُرسل الأداة ملفات تعريف ارتباط أو بيانات اعتماد، ولا تتبع التحويلات."
        )
        self.output_fn("  يتوقف التفويض عند إغلاق CLI، ولا يتجاوز قائمة النطاق المهيأة.")
        try:
            answer = self.input_fn("تفويض طلبات HTTP المحدودة إلى هذا النطاق؟ [y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        self.authorized = answer in {"y", "yes"}
        if not self.authorized:
            self.output_fn("لم يتم تفويض طلبات الأهداف الحية؛ تبقى الأدوات المحلية متاحة.")
        return self.authorized

    def __call__(self, name: str, arguments: dict[str, Any]) -> bool:
        """Allow in-scope tools while reserving their conservative request ceiling."""
        if name not in REMOTE_HTTP_TOOLS:
            return True
        if not self.authorized:
            return False
        cost = _request_cost(name, arguments)
        if cost > self.remaining:
            self.output_fn(
                f"تم إيقاف الاستدعاء: يحتاج حتى {cost} طلبات، والمتبقي {self.remaining} "
                "ضمن ميزانية الجلسة. أعد تشغيل CLI لتفويض جلسة جديدة."
            )
            return False
        self.remaining -= cost
        return True
