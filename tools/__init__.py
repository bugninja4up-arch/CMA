"""Tool schemas and fail-closed dispatch for the agent."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from tools.browser_engine import inspect_page
from tools.chain_engine import build_attack_chain_matrix
from tools.differential_engine import LAB_ACTORS, mutate_and_fuzz_request
from tools.js_analyzer import analyze_javascript_source
from tools.recon_engine import crawl_site
from labs.local_web_lab.evaluation import evaluate_local_saas_chain

TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "mutate_and_fuzz_request",
            "description": (
                "Send one baseline plus at most three JSON type-substitution requests "
                "to one explicitly scoped HTTP endpoint. Requires human approval; "
                "GET/POST only, no cookies, no redirects, bounded bodies, fingerprints only. "
                "Synthetic lab actors are limited to the CMA lab API routes over literal loopback IP URLs."
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
                        "description": "JSON object; GET requires {}, POST requires a non-empty object.",
                    },
                    "baseline_only": {
                        "type": "boolean",
                        "description": "If true, send exactly one baseline request and no mutations.",
                    },
                    "lab_actor": {
                        "type": "string",
                        "enum": sorted(LAB_ACTORS),
                        "description": "Synthetic actor for the CMA invitation lab; requires a lab API route on literal loopback IP.",
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
            "name": "evaluate_local_lab_chain",
            "description": (
                "Run the fixed synthetic tenant-export/report exercise against the CMA lab on "
                "127.0.0.1 only. Requires human approval, makes at most five bounded local HTTP "
                "requests, follows no redirects, never accepts a non-loopback host, suppresses the "
                "fake integration bearer, and returns an evidence-backed explicit attack-chain matrix."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "base_url": {
                        "type": "string",
                        "description": "Exact local origin, e.g. http://127.0.0.1:8765 (no path, query, or fragment).",
                    }
                },
                "required": ["base_url"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "build_attack_chain_matrix",
            "description": (
                "Build an offline matrix from structured findings. Links only explicit depends_on IDs; "
                "does not infer chains from similar titles. A confirmed step must include a non-empty impact statement and evidence plus "
                "passed reproduction, concrete-impact, and negative-control checks, each referencing "
                "one-based evidence indexes. This formatter does not execute tests or verify artifacts. "
                "Secret-like values are redacted."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "findings_json": {
                        "type": "string",
                        "maxLength": 50000,
                        "description": "JSON findings with id, title, status, evidence, explicit depends_on IDs, and verification checks. For confirmed status, provide reproduction/impact/negative_control objects with passed=true and evidence=[one-based indexes] into the evidence array.",
                    }
                },
                "required": ["findings_json"],
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
        optional = {"baseline_only", "lab_actor"}
        if (
            not required.issubset(parsed)
            or set(parsed) - required - optional
            or not all(isinstance(parsed.get(field), str) for field in required)
            or ("baseline_only" in parsed and not isinstance(parsed["baseline_only"], bool))
            or ("lab_actor" in parsed and not isinstance(parsed["lab_actor"], str))
        ):
            return json.dumps(
                {"error": "Expected url, method, payload_json, and only valid optional lab fields."}
            )
        result = mutate_and_fuzz_request(
            url=parsed["url"],
            method=parsed["method"],
            payload_json=parsed["payload_json"],
            scope=scope,
            baseline_only=parsed.get("baseline_only", False),
            lab_actor=parsed.get("lab_actor"),
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

    if name == "evaluate_local_lab_chain":
        if set(parsed) != {"base_url"} or not isinstance(parsed.get("base_url"), str):
            return json.dumps({"error": "Expected exactly one string field: base_url."})
        return json.dumps(evaluate_local_saas_chain(parsed["base_url"]), ensure_ascii=False)

    if name == "build_attack_chain_matrix":
        if set(parsed) != {"findings_json"} or not isinstance(parsed.get("findings_json"), str):
            return json.dumps({"error": "Expected exactly one string field: findings_json."})
        if len(parsed["findings_json"]) > 50_000:
            return json.dumps({"status": "invalid_input", "error": "findings_json exceeds 50000 characters."})
        try:
            findings = json.loads(parsed["findings_json"])
        except json.JSONDecodeError:
            return json.dumps({"status": "invalid_input", "error": "findings_json must be valid JSON."})
        return json.dumps(build_attack_chain_matrix(findings), ensure_ascii=False)

    return json.dumps({"error": f"Unknown tool: {name}"})
