"""CLI entry point for Anomaly-Engineer."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError as exc:
    raise SystemExit(
        "PyYAML is required. Install dependencies with: "
        "python -m pip install openai PyYAML"
    ) from exc

from agent import AIProvider, Agent
from db_manager import DBManager
from session_authorization import SessionAuthorization

PROJECT_DIR = Path(__file__).resolve().parent


def load_config(path: Path = PROJECT_DIR / "config.yaml") -> dict[str, Any]:
    """Load the YAML configuration file."""
    with path.open("r", encoding="utf-8") as config_file:
        data = yaml.safe_load(config_file) or {}
    if not isinstance(data, dict):
        raise ValueError("The top-level YAML configuration must be a mapping.")
    return data


def main() -> int:
    try:
        config = load_config()
        provider_name = str(config.get("provider", "openai")).lower()
        provider_settings = config.get("providers", {}).get(provider_name, {})
        if not isinstance(provider_settings, dict):
            raise ValueError(f"Invalid settings for provider {provider_name!r}.")

        scope = config.get("scope", {})
        if not isinstance(scope, dict):
            raise ValueError("Scope configuration must be a mapping.")
        session_authorization = SessionAuthorization(scope)
        session_authorization.authorize_session()

        database_value = Path(str(config.get("database", "evidence.db")))
        database_path = database_value if database_value.is_absolute() else PROJECT_DIR / database_value
        db_manager = DBManager(database_path)
        db_manager.initialize()

        provider = AIProvider(provider_name, provider_settings)
        agent = Agent(
            provider=provider,
            db_manager=db_manager,
            scope=scope,
            approval_callback=session_authorization,
        )
    except (OSError, ValueError, TypeError) as exc:
        print(f"تعذر تهيئة Anomaly-Engineer: {exc}", file=sys.stderr)
        return 1

    print(
        "Anomaly-Engineer — تفويض HTTP محدود لهذه الجلسة؛ "
        f"المتبقي: {session_authorization.remaining}/{session_authorization.budget}. "
        "اكتب exit أو quit للخروج."
    )
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
            print(
                f"[ميزانية HTTP المتبقية: "
                f"{session_authorization.remaining}/{session_authorization.budget}]"
            )
        except Exception as exc:  # Keep the REPL alive after provider/tool errors.
            print(f"تعذر إكمال الطلب: {exc}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
