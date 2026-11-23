"""Tool schemas and fail-closed dispatch for the agent."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from tools.browser_engine import inspect_page
from tools.differential_engine import mutate_and_fuzz_request
from tools.js_analyzer import analyze_javascript_source
from tools.recon_engine import crawl_site

TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "mutate_and_fuzz_request",
            "description": (
                "Send one baseline plus at most three JSON type-substitution requests "
                "to one explicitly scoped HTTP endpoint. Requires human approval; "
                "GET/POST only, no cookies, no redirects, bounded bodies, fingerprints only."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL."},
                    "method": {
                        "type": "string",
                        "enum": ["GET", "POST"],
                        "description": "HTTP method; only GET and POST are supported.",
                    },
                    "payload_json": {
                        "type": "string",
                        "description": "Non-empty JSON object sent as the request body.",
                    },
                },
                "required": ["url", "method", "payload_json"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "crawl_site",
            "description": (
                "Inventory up to five same-origin, explicitly scoped HTML pages using "
                "sequential GET requests. Requires human approval. Does not follow redirects, "
                "submit forms, send cookies/auth, return bodies, or preserve discovered query strings."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "In-scope starting URL."},
                    "max_pages": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 5,
                        "description": "Maximum pages to fetch (hard limit: 5).",
                    },
                },
                "required": ["url"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "inspect_page",
            "description": (
                "Make one bounded GET to an explicitly scoped URL, then inspect the captured "
                "HTML snapshot offline in Chromium. Requires human approval. Strips query/fragment; "
                "does not follow redirects, run JavaScript, fetch page resources, submit forms, "
                "send cookies/auth, or return the body. Requires optional Playwright+Chromium."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "In-scope page URL."},
                },
                "required": ["url"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_javascript",
            "description": (
                "Analyze caller-provided JavaScript text offline for API-like endpoint strings "
                "and potential secret literals. Makes no network requests and never returns matched secret values."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "source": {
                        "type": "string",
                        "description": "JavaScript source text, up to 1 MB.",
                    }
                },
                "required": ["source"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "load_skill",
            "description": "Read a Markdown skill from the project's skills directory.",
            "parameters": {
                "type": "object",
                "properties": {
                    "skill_name": {
                        "type": "string",
                        "description": "Skill filename with or without the .md suffix.",
                    }
                },
                "required": ["skill_name"],
                "additionalProperties": False,
            },
        },
    },
]


def load_skill(skill_name: str) -> dict[str, Any]:
    """Read one Markdown skill, rejecting paths and names outside the skills folder."""
    name = skill_name.strip()
    stem = name[:-3] if name.endswith(".md") else name
    if not re.fullmatch(r"[A-Za-z0-9_-]+", stem):
        return {"error": "Skill name must be a simple Markdown filename."}

    skills_dir = (Path(__file__).resolve().parent.parent / "skills").resolve()
    skill_path = (skills_dir / f"{stem}.md").resolve()
    if skill_path.parent != skills_dir or not skill_path.is_file():
        return {"error": f"Skill not found: {stem}.md"}
    return {"skill_name": f"{stem}.md", "content": skill_path.read_text(encoding="utf-8")}


def execute_tool(
    name: str,
    arguments: str | dict[str, Any],
    *,
    scope: dict[str, Any] | None = None,
) -> str:
    """Dispatch declared tools; all active HTTP use independently fails closed without scope."""
    if isinstance(arguments, str):
        try:
            parsed = json.loads(arguments)
        except json.JSONDecodeError as exc:
            return json.dumps({"error": f"Invalid tool argument JSON: {exc}"})
    else:
        parsed = arguments

    if not isinstance(parsed, dict):
        return json.dumps({"error": "Tool arguments must be a JSON object."})

    if name == "load_skill":
        if set(parsed) != {"skill_name"} or not isinstance(parsed.get("skill_name"), str):
            return json.dumps({"error": "Expected exactly one string field: skill_name."})
        return json.dumps(load_skill(parsed["skill_name"]), ensure_ascii=False)

    if name == "mutate_and_fuzz_request":
        required = {"url", "method", "payload_json"}
        if set(parsed) != required or not all(
            isinstance(parsed.get(field), str) for field in required
        ):
            return json.dumps(
                {"error": "Expected exactly three string fields: url, method, payload_json."}
            )
        result = mutate_and_fuzz_request(
            url=parsed["url"],
            method=parsed["method"],
            payload_json=parsed["payload_json"],
            scope=scope,
        )
        return json.dumps(result, ensure_ascii=False)

    if name == "crawl_site":
        if set(parsed) not in ({"url"}, {"url", "max_pages"}) or not isinstance(parsed.get("url"), str):
            return json.dumps({"error": "Expected url and optional integer max_pages."})
        max_pages = parsed.get("max_pages", 5)
        if isinstance(max_pages, bool) or not isinstance(max_pages, int):
            return json.dumps({"error": "max_pages must be an integer from 1 to 5."})
        result = crawl_site(parsed["url"], scope=scope, max_pages=max_pages)
        return json.dumps(result, ensure_ascii=False)

    if name == "inspect_page":
        if set(parsed) != {"url"} or not isinstance(parsed.get("url"), str):
            return json.dumps({"error": "Expected exactly one string field: url."})
        result = inspect_page(parsed["url"], scope=scope)
        return json.dumps(result, ensure_ascii=False)

    if name == "analyze_javascript":
        if set(parsed) != {"source"} or not isinstance(parsed.get("source"), str):
            return json.dumps({"error": "Expected exactly one string field: source."})
        return json.dumps(analyze_javascript_source(parsed["source"]), ensure_ascii=False)

    return json.dumps({"error": f"Unknown tool: {name}"})
