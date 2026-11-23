"""CLI entry point for Anomaly-Engineer."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

try:
    import yaml
except ImportError as exc:
    raise SystemExit(
        "PyYAML is required. Install dependencies with: "
        "python -m pip install openai PyYAML"
    ) from exc

from agent import AIProvider, Agent
from db_manager import DBManager


PROJECT_DIR = Path(__file__).resolve().parent
SENSITIVE_KEY = re.compile(r"(?i)(?:secret|password|token|api[_-]?key|authorization|cookie)")


def _redact_payload(value: Any) -> Any:
    """Redact values under secret-like JSON keys before showing approval details."""
    if isinstance(value, dict):
        return {
            key: ("[REDACTED]" if SENSITIVE_KEY.search(str(key)) else _redact_payload(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_payload(item) for item in value]
    return value


def _redact_url(value: str) -> str:
    """Show the target path but never query, fragment, or URL credentials."""
    try:
        parts = urlsplit(value)
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            return "[URL غير صالح أو مخفي]"
        host = parts.hostname
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        port = parts.port
        default_port = 443 if parts.scheme.lower() == "https" else 80
        authority = host if port in (None, default_port) else f"{host}:{port}"
        return urlunsplit((parts.scheme.lower(), authority, parts.path or "/", "", ""))
    except (TypeError, ValueError):
        return "[URL غير صالح أو مخفي]"


def load_config(path: Path = PROJECT_DIR / "config.yaml") -> dict[str, Any]:
    """Load the YAML configuration file."""
    with path.open("r", encoding="utf-8") as config_file:
        data = yaml.safe_load(config_file) or {}
    if not isinstance(data, dict):
        raise ValueError("The top-level YAML configuration must be a mapping.")
    return data


def approve_tool_call(name: str, arguments: dict[str, Any]) -> bool:
    """Require explicit confirmation before every tool invocation."""
    print("\nطلب الوكيل استدعاء أداة:")
    print(f"  الأداة: {name}")
    for key, value in arguments.items():
        if key == "source" and isinstance(value, str):
            display = f"[محتوى محلي مخفي؛ {len(value)} حرفًا]"
        elif key == "findings_json" and isinstance(value, str):
            display = f"[ملخص أدلة محلي مخفي؛ {len(value)} حرفًا]"
        elif key in {"url", "base_url"} and isinstance(value, str):
            display = _redact_url(value)
        elif key == "payload_json" and isinstance(value, str):
            try:
                parsed = json.loads(value)
                display = json.dumps(_redact_payload(parsed), ensure_ascii=False)
            except json.JSONDecodeError:
                display = "[JSON غير صالح؛ المحتوى مخفي]"
        else:
            display = value
        print(f"  {key}: {display}")
    if name == "mutate_and_fuzz_request":
        print("  ملاحظة: قد ترسل الأداة حتى 4 طلبات HTTP إلى العنوان أعلاه؛ لا تتبع التحويلات.")
    elif name == "crawl_site":
        print("  ملاحظة: حتى 5 طلبات GET متتابعة للأصل نفسه، بفاصل زمني؛ لا تتبع التحويلات أو ترسل النماذج.")
    elif name == "inspect_page":
        print("  ملاحظة: طلب GET واحد بعد حذف query/fragment؛ جسم أقصاه 256 KiB؛ لا JavaScript أو موارد خارجية أو إرسال نماذج.")
    elif name == "analyze_javascript":
        print("  ملاحظة: تحليل محلي للنص فقط؛ لا تُرسل طلبات شبكة.")
    elif name == "evaluate_local_lab_chain":
        print("  ملاحظة: حتى 5 طلبات HTTP ثابتة إلى 127.0.0.1 فقط؛ لا تحويلات أو اتصال خارجي، ويُحجب الرمز الاصطناعي من الأدلة.")
    elif name == "build_attack_chain_matrix":
        print("  ملاحظة: تحليل محلي بلا شبكة؛ يربط الاعتماديات الصريحة فقط ولا يرفع فرضية إلى ثغرة مؤكدة.")
    try:
        answer = input("الموافقة على هذا الاستدعاء؟ [y/N]: ").strip().lower()
    except EOFError:
        return False
    return answer in {"y", "yes"}


def main() -> int:
    try:
        config = load_config()
        provider_name = str(config.get("provider", "openai")).lower()
        provider_settings = config.get("providers", {}).get(provider_name, {})
        if not isinstance(provider_settings, dict):
            raise ValueError(f"Invalid settings for provider {provider_name!r}.")

        database_value = Path(str(config.get("database", "evidence.db")))
        database_path = database_value if database_value.is_absolute() else PROJECT_DIR / database_value
        db_manager = DBManager(database_path)
        db_manager.initialize()

        provider = AIProvider(provider_name, provider_settings)
        agent = Agent(
            provider=provider,
            db_manager=db_manager,
            scope=config.get("scope", {}),
            approval_callback=approve_tool_call,
        )
    except (OSError, ValueError, TypeError) as exc:
        print(f"تعذر تهيئة Anomaly-Engineer: {exc}", file=sys.stderr)
        return 1

    print("Anomaly-Engineer — اكتب exit أو quit للخروج.")
    while True:
        try:
            prompt = input("\nأنت> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nإلى اللقاء.")
            break
        if not prompt:
            continue
        if prompt.lower() in {"exit", "quit"}:
            print("إلى اللقاء.")
            break
        try:
            print(f"\nAnomaly-Engineer> {agent.respond(prompt)}")
        except Exception as exc:  # Keep the REPL alive after provider/tool errors.
            print(f"تعذر إكمال الطلب: {exc}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
