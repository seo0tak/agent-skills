"""Canonical risk-processing scope validation, classification, and counts."""

from __future__ import annotations

from datetime import datetime
import re
from typing import Any


RISK_LEVELS = ("critical", "very-high", "high", "medium", "low")
SCOPE_FIELDS = {
    "workspaceId",
    "reportId",
    "minRisk",
    "updatedAt",
    "updatedBy",
    "reason",
}
RFC3339_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


def _nonempty_string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _identifier(value: Any, name: str) -> str:
    text = _nonempty_string(value, name)
    if text.strip().lower() == "uninitialized":
        raise ValueError(f"{name} is not initialized")
    return text


def _timestamp(value: Any) -> str:
    text = _nonempty_string(value, "processingScope.updatedAt")
    if not RFC3339_PATTERN.fullmatch(text):
        raise ValueError("processingScope.updatedAt must be an RFC 3339 date-time")
    if not text.endswith("Z"):
        offset_hour = int(text[-5:-3])
        offset_minute = int(text[-2:])
        if offset_hour > 23 or offset_minute > 59:
            raise ValueError("processingScope.updatedAt has an invalid timezone offset")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("processingScope.updatedAt must be a valid date-time") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("processingScope.updatedAt must include a timezone")
    return text


def resolve_scope(profile: Any) -> dict[str, Any]:
    """Return the validated processing scope, or an explicit unconfigured value."""
    if not isinstance(profile, dict):
        raise ValueError("project profile must be an object")
    if "processingScope" not in profile:
        return {"configured": False}
    raw = profile["processingScope"]
    if not isinstance(raw, dict):
        raise ValueError("processingScope must be an object")
    missing = sorted(SCOPE_FIELDS.difference(raw))
    if missing:
        raise ValueError(f"processingScope is missing required field: {missing[0]}")
    unexpected = sorted(set(raw).difference(SCOPE_FIELDS))
    if unexpected:
        raise ValueError(f"processingScope has unexpected field: {unexpected[0]}")

    workspace_id = _identifier(profile.get("workspaceId"), "project profile workspaceId")
    report = profile.get("report")
    if not isinstance(report, dict):
        raise ValueError("project profile report must be an object")
    report_id = _identifier(report.get("id"), "project profile report.id")
    if _identifier(raw.get("workspaceId"), "processingScope.workspaceId") != workspace_id:
        raise ValueError("processingScope workspaceId does not match project profile")
    if _identifier(raw.get("reportId"), "processingScope.reportId") != report_id:
        raise ValueError("processingScope reportId does not match project profile")
    min_risk = raw.get("minRisk")
    if not isinstance(min_risk, str) or min_risk not in RISK_LEVELS:
        raise ValueError(f"processingScope.minRisk has invalid value: {min_risk!r}")

    return {
        "configured": True,
        "workspaceId": workspace_id,
        "reportId": report_id,
        "minRisk": min_risk,
        "updatedAt": _timestamp(raw.get("updatedAt")),
        "updatedBy": _nonempty_string(raw.get("updatedBy"), "processingScope.updatedBy"),
        "reason": _nonempty_string(raw.get("reason"), "processingScope.reason"),
    }


def _risk_level(finding: Any) -> Any:
    if not isinstance(finding, dict):
        return None
    risk = finding.get("risk")
    return risk.get("level") if isinstance(risk, dict) else None


def scope_bucket(finding: Any, scope: dict[str, Any]) -> str:
    """Classify one finding without consulting numeric risk ranks."""
    level = _risk_level(finding)
    if level is None or level == "unknown" or level not in (*RISK_LEVELS, "info"):
        return "unknown"
    if not scope.get("configured"):
        return "unconfigured"
    min_risk = scope.get("minRisk")
    if min_risk not in RISK_LEVELS:
        raise ValueError(f"processingScope.minRisk has invalid value: {min_risk!r}")
    if level == "info":
        return "out-of-scope"
    return (
        "in-scope"
        if RISK_LEVELS.index(level) <= RISK_LEVELS.index(min_risk)
        else "out-of-scope"
    )


def scope_summary(profile: Any, findings: Any, progress: Any) -> dict[str, Any]:
    """Summarize workflow-status completion separately from scope classification."""
    scope = resolve_scope(profile)
    if not isinstance(findings, list):
        raise ValueError("findings must be a list")
    if not isinstance(progress, dict) or not isinstance(progress.get("items"), dict):
        raise ValueError("progress items must be a mapping")
    progress_items = progress["items"]
    counts = {
        "total": len(findings),
        "inScope": 0,
        "outOfScope": 0,
        "unknown": 0,
        "unconfigured": 0,
        "inScopeVerified": 0,
        "inScopeRemaining": 0,
        "totalVerified": 0,
    }
    for finding in findings:
        bucket = scope_bucket(finding, scope)
        counts[{"in-scope": "inScope", "out-of-scope": "outOfScope"}.get(bucket, bucket)] += 1
        finding_id = finding.get("id") if isinstance(finding, dict) else None
        item_progress = progress_items.get(finding_id)
        verified = isinstance(item_progress, dict) and item_progress.get("workflowStatus") == "verified"
        if verified:
            counts["totalVerified"] += 1
            if bucket == "in-scope":
                counts["inScopeVerified"] += 1
    counts["inScopeRemaining"] = counts["inScope"] - counts["inScopeVerified"]
    selected_complete = (
        counts["inScope"] > 0
        and counts["inScopeVerified"] == counts["inScope"]
    )
    all_complete = (
        scope["configured"]
        and counts["total"] > 0
        and counts["unknown"] == 0
        and counts["totalVerified"] == counts["total"]
    )
    return {
        "scope": scope,
        "counts": counts,
        "selectedComplete": selected_complete,
        "allComplete": all_complete,
        "completionBasis": "workflow-status-only",
    }
