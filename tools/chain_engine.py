"""Deterministic attack-chain matrix builder for explicitly evidenced findings.

This module does not discover vulnerabilities or infer relationships from prose.
It links only caller-supplied dependency IDs and marks a chain confirmed only
when every step is explicitly confirmed with evidence.
"""
from __future__ import annotations

import re
from typing import Any

MAX_FINDINGS = 50
MAX_TEXT_LENGTH = 600
MAX_ITEMS_PER_LIST = 10
_VALID_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_VALID_STATUS = {"confirmed", "observed", "hypothesis", "rejected"}
_VERIFICATION_CHECKS = ("reproduction", "impact", "negative_control")
_BEARER_VALUE = re.compile(r"(?i)\bBearer\s+[^\s,;]+")
_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password|secret|token|"
    r"authorization|cookie|session[_-]?id|invite[_-]?(?:code|token)|invitation[_-]?code|"
    r"reset[_-]?code|verification[_-]?code|otp)\b"
    r"\s*[:=]\s*(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_LAB_TOKEN = re.compile(r"(?i)\b(?:lab[-_]?token|labtok)[-_A-Za-z0-9.]{6,}")


def _safe_text(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    text = " ".join(value.replace("\x00", " ").split())
    text = _BEARER_VALUE.sub("Bearer [REDACTED]", text)
    text = _SENSITIVE_ASSIGNMENT.sub("[REDACTED]", text)
    text = _LAB_TOKEN.sub("[REDACTED]", text)
    return text[:MAX_TEXT_LENGTH]


def _text_list(value: Any, field: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{field} must be an array of strings.")
    if len(value) > MAX_ITEMS_PER_LIST:
        raise ValueError(f"{field} supports at most {MAX_ITEMS_PER_LIST} entries.")
    result = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"{field} must contain only strings.")
        text = _safe_text(item)
        if text:
            result.append(text)
    return result


def _normalize_verification(value: Any, finding_id: str, evidence_count: int) -> dict[str, Any] | None:
    """Validate checklist claims and one-based references into the safe evidence list."""
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != set(_VERIFICATION_CHECKS):
        raise ValueError(
            f"Finding {finding_id} verification must contain exactly reproduction, impact, and negative_control."
        )

    normalized: dict[str, Any] = {}
    for check in _VERIFICATION_CHECKS:
        item = value[check]
        if not isinstance(item, dict) or set(item) != {"passed", "evidence"}:
            raise ValueError(
                f"Finding {finding_id} verification.{check} must contain passed and evidence."
            )
        if type(item["passed"]) is not bool:
            raise ValueError(f"Finding {finding_id} verification.{check}.passed must be a boolean.")
        references = item["evidence"]
        if not isinstance(references, list) or not references or len(references) > MAX_ITEMS_PER_LIST:
            raise ValueError(
                f"Finding {finding_id} verification.{check}.evidence must contain 1–10 evidence indexes."
            )
        checked: list[int] = []
        for reference in references:
            if (
                isinstance(reference, bool)
                or not isinstance(reference, int)
                or reference < 1
                or reference > evidence_count
            ):
                raise ValueError(
                    f"Finding {finding_id} verification.{check} references evidence outside the supplied list."
                )
            if reference in checked:
                raise ValueError(f"Finding {finding_id} verification.{check} repeats an evidence index.")
            checked.append(reference)
        normalized[check] = {"passed": item["passed"], "evidence": checked}
    return normalized


def _normalize_finding(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError("Each finding must be an object.")
    finding_id = raw.get("id")
    title = raw.get("title")
    status = raw.get("status")
    if not isinstance(finding_id, str) or not _VALID_ID.fullmatch(finding_id):
        raise ValueError("Finding id must use 1–64 letters, digits, underscore, or hyphen.")
    if not isinstance(title, str) or not title.strip():
        raise ValueError(f"Finding {finding_id} requires a title.")
    if not isinstance(status, str) or status.lower() not in _VALID_STATUS:
        raise ValueError(f"Finding {finding_id} has an unsupported status.")

    dependencies = raw.get("depends_on", [])
    if dependencies is None:
        dependencies = []
    if not isinstance(dependencies, list) or len(dependencies) > MAX_ITEMS_PER_LIST:
        raise ValueError(f"Finding {finding_id} dependencies must be an array of at most 10 IDs.")
    normalized_dependencies = []
    for dependency in dependencies:
        if not isinstance(dependency, str) or not _VALID_ID.fullmatch(dependency):
            raise ValueError(f"Finding {finding_id} has an invalid dependency ID.")
        if dependency not in normalized_dependencies:
            normalized_dependencies.append(dependency)

    raw_evidence = raw.get("evidence", [])
    evidence = _text_list(raw_evidence, f"Finding {finding_id} evidence")
    if isinstance(raw_evidence, list) and len(evidence) != len(raw_evidence):
        raise ValueError(f"Finding {finding_id} evidence entries must not be empty.")
    verification = _normalize_verification(raw.get("verification"), finding_id, len(evidence))
    capability = raw.get("capability_gain", "")
    impact = raw.get("impact", "")
    summary = raw.get("summary", "")
    for field_name, field_value in (("summary", summary), ("impact", impact), ("capability_gain", capability)):
        if not isinstance(field_value, str):
            raise ValueError(f"Finding {finding_id} {field_name} must be text.")

    normalized_status = status.lower()
    status_note = None
    if normalized_status == "confirmed":
        if not evidence:
            normalized_status = "hypothesis"
            status_note = "Downgraded to hypothesis because no evidence summary was supplied."
        elif not impact.strip():
            normalized_status = "observed"
            status_note = "Downgraded to observed because no concrete impact statement was supplied."
        elif verification is None:
            normalized_status = "observed"
            status_note = (
                "Downgraded to observed because passed reproduction, concrete-impact, "
                "and negative-control checks with evidence references were not supplied."
            )
        else:
            failed_checks = [check for check in _VERIFICATION_CHECKS if not verification[check]["passed"]]
            if failed_checks:
                normalized_status = "observed"
                status_note = "Downgraded to observed because these checks did not pass: " + ", ".join(failed_checks) + "."

    item = {
        "id": finding_id,
        "title": _safe_text(title),
        "status": normalized_status,
        "summary": _safe_text(summary),
        "preconditions": _text_list(raw.get("preconditions", []), f"Finding {finding_id} preconditions"),
        "evidence": evidence,
        "capability_gain": _safe_text(capability),
        "impact": _safe_text(impact),
        "remediation": _text_list(raw.get("remediation", []), f"Finding {finding_id} remediation"),
        "depends_on": normalized_dependencies,
    }
    if verification is not None:
        item["verification"] = verification
    if status_note:
        item["status_note"] = status_note
    return item


def _check_graph(findings: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    by_id = {finding["id"]: finding for finding in findings}
    if len(by_id) != len(findings):
        raise ValueError("Finding IDs must be unique.")
    for finding in findings:
        if finding["id"] in finding["depends_on"]:
            raise ValueError(f"Finding {finding['id']} cannot depend on itself.")
        for dependency in finding["depends_on"]:
            if dependency not in by_id:
                raise ValueError(f"Finding {finding['id']} references an unknown dependency.")

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(finding_id: str) -> None:
        if finding_id in visiting:
            raise ValueError("Dependency graph contains a cycle.")
        if finding_id in visited:
            return
        visiting.add(finding_id)
        for dependency in by_id[finding_id]["depends_on"]:
            visit(dependency)
        visiting.remove(finding_id)
        visited.add(finding_id)

    for finding in findings:
        visit(finding["id"])
    return by_id


def build_attack_chain_matrix(findings: Any) -> dict[str, Any]:
    """Create a dependency matrix without inventing chains or upgrading evidence.

    Each finding is a mapping with ``id``, ``title``, and ``status``. Optional
    fields are ``depends_on`` (explicit prior finding IDs), ``preconditions``,
    ``evidence``, a non-empty concrete ``impact``, ``verification`` (passed reproduction, impact, and negative
    control checks, each citing one-based evidence indexes), ``capability_gain``,
    ``impact``, ``summary``, and ``remediation``. Secret-like text is redacted.
    This formatter validates checklist structure and references; it does not
    execute tests or independently authenticate caller-supplied claims.
    """
    if not isinstance(findings, list):
        return {"status": "invalid_input", "error": "findings must be an array."}
    if len(findings) > MAX_FINDINGS:
        return {"status": "invalid_input", "error": f"At most {MAX_FINDINGS} findings are supported."}

    try:
        normalized = [_normalize_finding(item) for item in findings]
        by_id = _check_graph(normalized)
    except ValueError as exc:
        return {"status": "invalid_input", "error": str(exc)}

    depended_on = {dependency for finding in normalized for dependency in finding["depends_on"]}
    terminals = [
        finding["id"]
        for finding in normalized
        if finding["depends_on"] and finding["id"] not in depended_on
    ]
    chains: list[dict[str, Any]] = []
    matrix: list[dict[str, Any]] = []
    linked_ids: set[str] = set()

    for chain_number, terminal_id in enumerate(terminals, start=1):
        ordered: list[dict[str, Any]] = []
        visited: set[str] = set()

        def collect(finding_id: str) -> None:
            if finding_id in visited:
                return
            for dependency in by_id[finding_id]["depends_on"]:
                collect(dependency)
            visited.add(finding_id)
            ordered.append(by_id[finding_id])

        collect(terminal_id)
        linked_ids.update(item["id"] for item in ordered)
        chain_id = f"CHAIN-{chain_number:03d}"
        rejected = [item["id"] for item in ordered if item["status"] == "rejected"]
        unconfirmed = [item["id"] for item in ordered if item["status"] != "confirmed"]
        chain_status = "confirmed" if not unconfirmed else "incomplete"
        if rejected:
            chain_status = "blocked_by_rejected_step"

        step_rows = []
        for step_number, item in enumerate(ordered, start=1):
            row = {
                "chain_id": chain_id,
                "step": step_number,
                "finding_id": item["id"],
                "status": item["status"],
                "depends_on": item["depends_on"],
                "title": item["title"],
                "preconditions": item["preconditions"],
                "evidence": item["evidence"],
                "capability_gain": item["capability_gain"],
                "impact": item["impact"],
                "remediation": item["remediation"],
            }
            if "verification" in item:
                row["verification"] = item["verification"]
            if "status_note" in item:
                row["status_note"] = item["status_note"]
            matrix.append(row)
            step_rows.append({key: value for key, value in row.items() if key not in {"chain_id", "step"}})

        terminal = by_id[terminal_id]
        chains.append({
            "chain_id": chain_id,
            "status": chain_status,
            "title": " → ".join(item["title"] for item in ordered),
            "finding_ids": [item["id"] for item in ordered],
            "steps": step_rows,
            "overall_impact": terminal["impact"],
            "unconfirmed_steps": unconfirmed,
            "rejected_steps": rejected,
            "note": "Only explicit depends_on links are represented; no relationship is inferred from titles or similarity.",
        })

    standalone = [
        {
            "id": item["id"],
            "title": item["title"],
            "status": item["status"],
            "summary": item["summary"],
            "preconditions": item["preconditions"],
            "evidence": item["evidence"],
            "capability_gain": item["capability_gain"],
            "impact": item["impact"],
            "remediation": item["remediation"],
        }
        for item in normalized
        if item["id"] not in linked_ids
    ]
    for item, output in zip(
        (finding for finding in normalized if finding["id"] not in linked_ids),
        standalone,
    ):
        if "verification" in item:
            output["verification"] = item["verification"]
        if "status_note" in item:
            output["status_note"] = item["status_note"]
    return {
        "status": "completed",
        "finding_count": len(normalized),
        "chain_count": len(chains),
        "confirmed_chain_count": sum(chain["status"] == "confirmed" for chain in chains),
        "chains": chains,
        "attack_chain_matrix": matrix,
        "standalone_findings": standalone,
        "note": (
            "A chain is labeled confirmed only when every step includes evidence and caller-recorded passed "
            "reproduction, impact, and negative-control checks with valid evidence indexes. This offline "
            "builder validates structure and references only; it does not execute tests or verify artifact contents."
        ),
    }
