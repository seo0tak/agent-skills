#!/usr/bin/env python3
"""Append-only local activity journal. A successful command is not verification."""
from __future__ import annotations

import argparse
from contextlib import contextmanager, nullcontext
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sys
import tempfile
import uuid

try:
    from .sast_io import writer_lock, write_text_atomic
except ImportError:
    from sast_io import writer_lock, write_text_atomic

ROOT = Path(__file__).resolve().parent.parent
KINDS = {"started", "finished", "changed", "observation"}
OUTCOMES = {"running", "succeeded", "failed", "blocked", "stopped", "info"}
SOURCES = {"toolkit", "agent", "browser", "external"}
ACTION_LABELS = {"toolkit.preflight": "입력 사전 점검", "toolkit.gate": "입력 승인 확인",
                 "toolkit.init": "초기 분석 준비", "toolkit.sync": "대시보드 동기화",
                 "toolkit.scope": "처리 범위 변경", "state.checkpoint": "체크포인트 저장",
                 "state.snapshot": "검증 전 스냅샷 저장", "state.seal-verification": "검증 근거 연결",
                 "state.recover-progress": "진행상태 복구"}
OUTCOME_LABELS = {"succeeded": "성공", "failed": "실패", "blocked": "차단", "stopped": "중단"}
FIELDS = {"schemaVersion", "eventId", "recordedAt", "workspaceId", "reportId", "operationId",
          "attemptId", "kind", "action", "outcome", "source", "actor", "itemIds", "summary",
          "before", "after", "evidence", "important"}
SECRET_NAMES = r"password|passwd|pwd|token|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|private[_-]?key|authorization"
SECRET_KEY = re.compile(r"^(?:" + SECRET_NAMES + r")$", re.I)
SECRET_ASSIGNMENT = re.compile(r"\b(" + SECRET_NAMES + r")\b(\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)", re.I)
BEARER = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]+", re.I)
FORBIDDEN_KEYS = {"__proto__", "prototype", "constructor"}


def redact(value):
    """Mask explicit credential values only; this is not a general secret detector."""
    if isinstance(value, str):
        return BEARER.sub("Bearer [REDACTED]", SECRET_ASSIGNMENT.sub(lambda match: match[1] + match[2] + "[REDACTED]", value))
    if isinstance(value, dict):
        return {key: "[REDACTED]" if SECRET_KEY.fullmatch(str(key)) else redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def compact(value, depth=0):
    value = redact(value)
    if isinstance(value, str):
        return value if len(value) <= 2000 else value[:1987] + "…[truncated]"
    if isinstance(value, (dict, list)) and depth >= 5:
        return "[TRUNCATED]"
    if isinstance(value, dict):
        allowed = [(key, item) for key, item in value.items() if key not in FORBIDDEN_KEYS]
        result = {str(key)[:2000]: compact(item, depth + 1) for key, item in allowed[:50]}
        omitted = [key for key in value if key in FORBIDDEN_KEYS]
        if omitted:
            result["_omittedKeys"] = omitted
        if len(allowed) > 50:
            result["_truncated"] = len(allowed) - 50
        return result
    if isinstance(value, list):
        return [compact(item, depth + 1) for item in value[:50]]
    return value


def prepare_event(event):
    for key in ("action", "actor", "summary", "before", "after", "evidence"):
        event[key] = compact(event[key])
    for key in ("action", "actor"):
        if isinstance(event[key], str):
            event[key] = event[key][:200]
    # Keep small snapshots, never drop the lifecycle or item identity to fit.
    if len(json_text(event).encode()) > 32768:
        for key in ("before", "after"):
            original = event[key]
            # Reconciliation relies on these fields even when a value is large.
            identity = {field: original[field] for field in ("record", "exists", "sha256", "itemIds") if field in original}
            preview = json_text(original.get("value", original)).encode()[:4000].decode("utf-8", errors="ignore")
            value = {"preview": preview, "truncated": True}
            event[key] = {**identity, "value": value} if "record" in identity else value
    validate_event(event)
    return event


def now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def json_text(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n"


def fsync_directory(path):
    # Windows does not provide a portable directory fsync through os.open.
    if os.name != "nt":
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError("activity recordedAt must be a date-time string")
    match = re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]+)?(?:Z|[+-]([0-9]{2}):([0-9]{2}))", value)
    if (match is None or any(int(part or "0") >= limit
                             for part, limit in zip(match.groups(), (24, 60, 60, 24, 60)))):
        raise ValueError("activity recordedAt requires strict ISO date-time with seconds and timezone")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("activity recordedAt requires a timezone")
    return parsed


def validate_metadata(value, depth=0):
    if depth > 8:
        raise ValueError("activity metadata exceeds nesting depth 8")
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, (int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("activity metadata requires finite JSON numbers")
        return
    if isinstance(value, list):
        for item in value:
            validate_metadata(item, depth + 1)
        return
    if not isinstance(value, dict):
        raise ValueError("activity metadata requires JSON values")
    for key, item in value.items():
        if not isinstance(key, str) or key in FORBIDDEN_KEYS:
            raise ValueError("activity metadata contains a forbidden key")
        validate_metadata(item, depth + 1)


def validate_event(event):
    if not isinstance(event, dict) or set(event) != FIELDS or event.get("schemaVersion") != "1.0":
        raise ValueError("unsupported activity event fields or schemaVersion")
    for key in ("eventId", "operationId", "attemptId"):
        if not isinstance(event[key], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}", event[key]):
            raise ValueError(f"invalid activity {key}")
    timestamp(event["recordedAt"])
    for key in ("workspaceId", "reportId"):
        if event[key] is not None and (not isinstance(event[key], str) or not event[key].strip()):
            raise ValueError(f"activity {key} must be a nonempty string or null")
    for key, values in (("kind", KINDS), ("outcome", OUTCOMES), ("source", SOURCES)):
        if not isinstance(event[key], str) or event[key] not in values:
            raise ValueError(f"unsupported activity {key}")
    for key in ("action", "actor", "summary"):
        if not isinstance(event[key], str) or not event[key].strip():
            raise ValueError(f"activity {key} must be a nonempty string")
    for key in ("itemIds", "evidence"):
        if not isinstance(event[key], list) or not all(isinstance(item, str) and item.strip() for item in event[key]):
            raise ValueError(f"activity {key} must be an array of nonempty strings")
    if not isinstance(event["before"], dict) or not isinstance(event["after"], dict) or not isinstance(event["important"], bool):
        raise ValueError("activity before/after must be objects and important must be boolean")
    validate_metadata(event["before"])
    validate_metadata(event["after"])
    if event["kind"] == "started" and event["outcome"] != "running":
        raise ValueError("a started activity must be running")
    if event["kind"] == "finished" and event["outcome"] not in {"succeeded", "failed", "blocked", "stopped"}:
        raise ValueError("a finished activity requires an actual terminal outcome")
    if event["action"] == "canonical.reconcile" and (event["source"] not in {"toolkit", "external"}
                                                      or event["kind"] not in {"changed", "observation"}):
        raise ValueError("canonical.reconcile is reserved for local canonical observations")
    if len(json_text(event).encode()) > 32768:
        raise ValueError("activity event exceeds 32768 bytes; retain compact references only")
    if any(redact(event[key]) != event[key] for key in ("action", "actor", "summary", "before", "after", "evidence")):
        raise ValueError("activity contains an explicit credential value; redact it before import")
    return event


def event_order(event):
    return timestamp(event["recordedAt"]), 0 if event["kind"] == "started" else 1, event["eventId"]


def lifecycle_issues(events):
    attempts, operations, issues = {}, {}, []
    for event in events:
        # Canonical observations can accompany a command's operation as evidence;
        # all other attempts in an operation must describe the same logical work.
        if event["action"] != "canonical.reconcile":
            identity = tuple(event[key] for key in ("workspaceId", "reportId", "action", "source")) + (tuple(sorted(set(event["itemIds"]))),)
            previous = operations.setdefault(event["operationId"], identity)
            if previous != identity:
                issues.append(f"operation {event['operationId']} has conflicting logical work identity")
        if event["kind"] not in {"started", "finished"}:
            continue
        pair = attempts.setdefault(event["attemptId"], {})
        if event["kind"] in pair:
            issues.append(f"attempt {event['attemptId']} has duplicate {event['kind']} events")
        pair[event["kind"]] = event
    for attempt, pair in attempts.items():
        start, finish = pair.get("started"), pair.get("finished")
        if finish is None:
            continue
        if start is None:
            issues.append(f"attempt {attempt} has a finish without a start")
            continue
        if any(start[key] != finish[key] for key in ("operationId", "workspaceId", "reportId", "action", "source", "itemIds")):
            issues.append(f"attempt {attempt} has a mismatched finish")
        if timestamp(finish["recordedAt"]) < timestamp(start["recordedAt"]):
            issues.append(f"attempt {attempt} finish precedes its start")
    return issues


class ActivityJournal:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self._cached = None
        self._dirty = False

    @contextmanager
    def mutation(self, *, locked=False):
        """A lock-scoped journal read; a batch publishes its display mirror once."""
        if self._cached is not None:
            yield
            return
        with nullcontext() if locked else writer_lock(self.root):
            self._cached = self.projection()
            successful = False
            try:
                yield
                successful = True
            finally:
                try:
                    if successful and self._dirty:
                        self.refresh()
                finally:
                    self._cached = None
                    self._dirty = False

    def safe_path(self, relative):
        path = self.root / relative
        if Path(relative).is_absolute() or ".." in Path(relative).parts:
            raise ValueError("activity path escapes toolkit")
        current = self.root
        for part in Path(relative).parts:
            current = current / part
            if current.is_symlink():
                raise ValueError(f"activity path must not be a symlink: {relative}")
        if not path.resolve().is_relative_to(self.root):
            raise ValueError("activity path escapes toolkit")
        return path

    def identity(self):
        try:
            value = json.loads(self.safe_path("data/project-profile.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None, None
        workspace = value.get("workspaceId") if isinstance(value, dict) else None
        report = value.get("report") if isinstance(value, dict) else None
        report_id = report.get("id") if isinstance(report, dict) else None
        return (workspace if isinstance(workspace, str) and workspace.strip() and workspace != "uninitialized" else None,
                report_id if isinstance(report_id, str) and report_id.strip() else None)

    def active(self):
        return self.identity()[0] is not None or (self.root / "data/activity").exists() or (self.root / "data/activity").is_symlink()

    def refresh(self):
        value = self.projection()
        if not value["events"] and not value["warnings"]:
            value["generatedAt"] = None
        write_text_atomic(self.safe_path("data/activity.js"),
                          "window.SAST_TOOLKIT_DATA = window.SAST_TOOLKIT_DATA || {};\n"
                          "window.SAST_TOOLKIT_DATA.activity = JSON.parse(" +
                          json.dumps(json_text(value).rstrip(), ensure_ascii=True) + ");\n")
        self._dirty = False

    def projection(self):
        if self._cached is not None:
            return {**self._cached, "generatedAt": now(), "events": sorted(self._cached["events"], key=event_order)}
        events, warnings, seen = [], [], {}
        try:
            directory = self.safe_path("data/activity")
            if directory.exists():
                for month in sorted(directory.iterdir()):
                    if month.name.startswith("."):
                        continue
                    try:
                        self.safe_path(str(month.relative_to(self.root)))
                        if not month.is_dir() or not re.fullmatch(r"\d{4}-\d{2}", month.name):
                            raise ValueError("unexpected activity month entry")
                        for path in sorted(month.iterdir()):
                            if path.name.startswith("."):
                                continue
                            try:
                                self.safe_path(str(path.relative_to(self.root)))
                                if path.suffix != ".json" or not path.is_file() or path.stat().st_size > 32768:
                                    raise ValueError("unsupported activity record file")
                                event = validate_event(json.loads(path.read_text(encoding="utf-8")))
                                if path.stem != event["eventId"] or timestamp(event["recordedAt"]).strftime("%Y-%m") != month.name:
                                    raise ValueError("activity path does not match event identity/date")
                                if event["eventId"] in seen:
                                    raise ValueError("duplicate activity eventId in journal")
                                seen[event["eventId"]] = event
                                events.append(event)
                            except (OSError, ValueError, TypeError, RecursionError) as error:
                                warnings.append(f"{path.relative_to(self.root)}: {error}")
                    except (OSError, ValueError, TypeError) as error:
                        warnings.append(f"{month.relative_to(self.root)}: {error}")
        except (OSError, ValueError) as error:
            warnings.append(str(error))
        events.sort(key=event_order)
        warnings.extend(lifecycle_issues(events))
        return {"schemaVersion": "1.0", "generatedAt": now(), "events": events, "warnings": warnings}

    def append(self, event, *, locked=False):
        validate_event(event)
        with self.mutation(locked=locked):
            current = self.projection()
            if current["warnings"]:
                raise ValueError("activity journal requires review: " + "; ".join(current["warnings"]))
            for existing in current["events"]:
                if existing["eventId"] == event["eventId"]:
                    if existing != event:
                        raise ValueError("conflicting payload for activity eventId")
                    return existing
            issues = lifecycle_issues(current["events"] + [event])
            if issues:
                raise ValueError("; ".join(issues))
            month = timestamp(event["recordedAt"]).strftime("%Y-%m")
            directory = self.safe_path(f"data/activity/{month}")
            for relative in ("data", "data/activity", f"data/activity/{month}"):
                folder = self.safe_path(relative)
                if not folder.exists():
                    folder.mkdir()
                    fsync_directory(folder.parent)
            target = self.safe_path(f"data/activity/{month}/{event['eventId']}.json")
            descriptor, temporary = tempfile.mkstemp(prefix=".pending-", dir=directory)
            temporary = Path(temporary)
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    handle.write(json_text(event))
                    handle.flush()
                    os.fsync(handle.fileno())
                os.link(temporary, target)  # Atomic publication without ever replacing an event.
                fsync_directory(directory)
            finally:
                temporary.unlink(missing_ok=True)
            self._cached["events"].append(event)
            self._dirty = True
            return event

    def start(self, action, summary, actor, *, item_ids=None, operation_id=None, attempt_id=None,
              source="agent", before=None, evidence=None, important=False, locked=False):
        workspace, report = self.identity()
        event = {"schemaVersion": "1.0", "eventId": uuid.uuid4().hex, "recordedAt": now(),
                 "workspaceId": workspace, "reportId": report,
                 "operationId": operation_id or uuid.uuid4().hex, "attemptId": attempt_id or uuid.uuid4().hex,
                 "kind": "started", "action": action, "outcome": "running", "source": source,
                 "actor": actor, "itemIds": item_ids or [], "summary": summary, "before": before or {},
                 "after": {}, "evidence": evidence or [], "important": important}
        prepare_event(event)
        with self.mutation(locked=locked):
            current = self.projection()
            if current["warnings"]:
                raise ValueError("activity journal requires review: " + "; ".join(current["warnings"]))
            for existing in current["events"]:
                if existing["attemptId"] == event["attemptId"] and existing["kind"] == "started":
                    if operation_id is None:
                        event["operationId"] = existing["operationId"]
                    if any(event[key] != existing[key] for key in FIELDS - {"eventId", "recordedAt"}):
                        raise ValueError("conflicting start for activity attempt")
                    return existing
            return self.append(event, locked=True)

    def finish(self, attempt_id, outcome, summary, *, after=None, evidence=None, important=False, locked=False):
        with self.mutation(locked=locked):
            current = self.projection()
            if current["warnings"]:
                raise ValueError("activity journal requires review: " + "; ".join(current["warnings"]))
            starts = [event for event in current["events"] if event["attemptId"] == attempt_id and event["kind"] == "started"]
            if len(starts) != 1:
                raise ValueError("activity attempt has no unique recorded start")
            start = starts[0]
            event = {**start, "eventId": uuid.uuid4().hex, "recordedAt": now(), "kind": "finished",
                     "outcome": outcome, "summary": summary, "before": {}, "after": after or {},
                     "evidence": evidence or [], "important": important or start["important"] or outcome != "succeeded"}
            prepare_event(event)
            for existing in current["events"]:
                if existing["attemptId"] == attempt_id and existing["kind"] == "finished":
                    if any(event[key] != existing[key] for key in FIELDS - {"eventId", "recordedAt"}):
                        raise ValueError("conflicting finish for activity attempt")
                    return existing
            return self.append(event, locked=True)

    def note(self, action, summary, actor, *, item_ids=None, source="agent", kind="observation", outcome="info",
             before=None, after=None, evidence=None, important=False, operation_id=None, attempt_id=None, locked=False):
        if action == "canonical.reconcile":
            raise ValueError("canonical.reconcile is reserved; use the reconcile command")
        return self._note(action, summary, actor, item_ids=item_ids, source=source, kind=kind, outcome=outcome,
                          before=before, after=after, evidence=evidence, important=important,
                          operation_id=operation_id, attempt_id=attempt_id, locked=locked)

    def _note(self, action, summary, actor, *, item_ids=None, source="agent", kind="observation", outcome="info",
              before=None, after=None, evidence=None, important=False, operation_id=None, attempt_id=None, locked=False):
        workspace, report = self.identity()
        event = {"schemaVersion": "1.0", "eventId": uuid.uuid4().hex, "recordedAt": now(),
                 "workspaceId": workspace, "reportId": report, "operationId": operation_id or uuid.uuid4().hex,
                 "attemptId": attempt_id or uuid.uuid4().hex, "kind": kind, "action": action, "outcome": outcome,
                 "source": source, "actor": actor, "itemIds": item_ids or [], "summary": summary,
                 "before": before or {}, "after": after or {}, "evidence": evidence or [],
                 "important": important or kind == "changed" or outcome in {"failed", "blocked", "stopped"}}
        return self.append(prepare_event(event), locked=locked)

    def canonical_state(self):
        """Read compact observations. No source files, raw output, or old states are reconstructed."""
        records, warnings = {}, []

        def add(key, value, item_ids=None, *, raw=None):
            records[key] = {"record": key, "exists": True,
                            "sha256": hashlib.sha256(raw if raw is not None else json_text(value).encode()).hexdigest(),
                            "value": compact(value), "itemIds": item_ids or []}

        def read(relative):
            try:
                path = self.safe_path(relative)
                if not path.exists():
                    return None
                raw = path.read_bytes()
                try:
                    parsed = json.loads(raw)
                    if not isinstance(parsed, dict):
                        raise ValueError("unsupported object structure")
                    return parsed
                except (ValueError, UnicodeError, RecursionError):
                    add(relative, {"readable": False}, raw=raw)
                    warnings.append(f"{relative}: malformed JSON; only its digest was observed")
            except (OSError, ValueError) as error:
                warnings.append(f"{relative}: {error}")
            return None

        relative = "data/project-profile.json"
        profile = read(relative)
        if isinstance(profile, dict):
            add(relative, {key: profile.get(key) for key in ("workspaceId", "report", "processingScope")})
        relative = "data/input-validation.json"
        validation = read(relative)
        if isinstance(validation, dict):
            add(relative, {key: validation.get(key) for key in ("status", "matching", "blockers")})
        relative = "data/progress.json"
        progress = read(relative)
        if isinstance(progress, dict):
            add(relative, {"schemaVersion": progress.get("schemaVersion"), "workspaceId": progress.get("workspaceId"),
                           "itemsReadable": isinstance(progress.get("items"), dict)})
            if not isinstance(progress.get("items"), dict):
                warnings.append(f"{relative}: progress items are unreadable; prior items are unknown, not deleted")
            else:
                for finding_id, item in sorted(progress["items"].items()):
                    add(relative + "#items/" + finding_id, item, [finding_id])
            drafts = progress.get("draftResults", {})
            if isinstance(drafts, dict):
                for finding_id, draft in sorted(drafts.items()):
                    result = draft.get("result", {}) if isinstance(draft, dict) else {}
                    selected = {key: result.get(key) for key in ("workflowStatus", "conclusion", "summary", "updatedAt")} if isinstance(result, dict) else {}
                    add(relative + "#draftResults/" + finding_id, selected, [finding_id], raw=json_text(draft).encode())
        relative = "data/decisions.json"
        decisions = read(relative)
        if isinstance(decisions, dict) and isinstance(decisions.get("decisions"), list):
            for index, decision in enumerate(decisions["decisions"]):
                if isinstance(decision, dict):
                    key = str(decision.get("id", index))
                    ids = decision.get("findingIds", [])
                    add(relative + "#decisions/" + key, decision, ids if isinstance(ids, list) else [])
        relative = "data/resume-state.json"
        state = read(relative)
        if isinstance(state, dict):
            for field in ("checkpoints", "snapshots"):
                if isinstance(state.get(field), dict):
                    for finding_id, item in sorted(state[field].items()):
                        add(relative + "#" + field + "/" + finding_id, item, [finding_id])
        for directory in ("security-results", "security-guides"):
            try:
                paths = sorted(self.safe_path(directory).glob("*.json"))
            except (OSError, ValueError) as error:
                warnings.append(f"{directory}: {error}")
                continue
            for path in paths:
                if path.name == "index.json":
                    continue
                relative = str(path.relative_to(self.root))
                value = read(relative)
                if isinstance(value, dict):
                    selected = {key: value.get(key) for key in
                                ("id", "workflowStatus", "conclusion", "reason", "resultSummary", "evidenceNote",
                                 "summary", "resultFiles", "policyQuestions") if key in value}
                    verification = value.get("verification")
                    if isinstance(verification, dict):
                        selected["verification"] = {key: verification.get(key) for key in
                                                    ("status", "method", "results", "limitations", "verifiedAt", "sourceSnapshot") if key in verification}
                    add(relative, selected, [str(value.get("id", path.stem))], raw=json_text(value).encode())
        for relative in ("project/PROJECT_SECURITY_POLICY.md", "project/PROJECT_ANALYSIS.md"):
            try:
                path = self.safe_path(relative)
                if path.exists():
                    add(relative, {"content": "digest only"}, raw=path.read_bytes())
            except (OSError, ValueError) as error:
                warnings.append(f"{relative}: {error}")
        return records, warnings

    def drift(self, projection=None):
        projection = projection or self.projection()
        workspace, report = self.identity()
        observed = {}
        for event in projection["events"]:
            if (event["workspaceId"] == workspace and event["reportId"] == report
                    and event["action"] == "canonical.reconcile" and event["source"] in {"toolkit", "external"}
                    and event["kind"] in {"observation", "changed"}):
                record = event["after"].get("record")
                if isinstance(record, str):
                    observed[record] = event["after"]
        current, warnings = self.canonical_state()
        changes = []
        for key in sorted(observed.keys() | current.keys()):
            before = observed.get(key, {})
            after = current.get(key, {"record": key, "exists": False, "sha256": None, "value": {}, "itemIds": before.get("itemIds", [])})
            if key not in current and any(warning.startswith(key.split("#")[0] + ":") for warning in warnings):
                after = {**after, "exists": None, "value": {"readable": False}}
            if before.get("sha256") != after.get("sha256") or before.get("exists") != after.get("exists"):
                changes.append({"before": before, "after": after, "baseline": not bool(before)})
        return {"changes": changes, "warnings": warnings, "baselineRequired": not bool(observed)}

    def reconcile(self, *, source="external", actor="unknown", operation_id=None, attempt_id=None, locked=False):
        with self.mutation(locked=locked):
            projection = self.projection()
            if projection["warnings"]:
                raise ValueError("activity journal requires review: " + "; ".join(projection["warnings"]))
            drift = self.drift(projection)
            for change in drift["changes"]:
                after = change["after"]
                self._note("canonical.reconcile",
                          ("기준 상태 관측: " if change["baseline"] else "정본 변경 발견: ") + after["record"],
                          actor, source=source, kind="observation" if change["baseline"] else "changed",
                          item_ids=after["itemIds"], before=change["before"], after=after,
                          evidence=[after["record"]], important=not change["baseline"],
                          operation_id=operation_id, attempt_id=attempt_id, locked=True)
            return {"ok": True, "observedCount": sum(change["baseline"] for change in drift["changes"]),
                    "changedCount": sum(not change["baseline"] for change in drift["changes"]), "warnings": drift["warnings"]}

    def import_browser(self, path, *, locked=False):
        path = Path(path)
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 50 * 1024 * 1024:
            raise ValueError("browser backup must be a regular file under 50 MiB; symlinks are not accepted")
        value = json.loads(path.read_text(encoding="utf-8"))
        workspace, report = self.identity()
        if not isinstance(value, dict) or value.get("schemaVersion") != "1.0" or not workspace or value.get("workspaceId") != workspace:
            raise ValueError("browser backup belongs to a different or uninitialized workspace")
        imported = value.get("activityEvents")
        if not isinstance(imported, list):
            raise ValueError("browser backup requires an activityEvents array")
        with self.mutation(locked=locked):
            projection = self.projection()
            if projection["warnings"]:
                raise ValueError("activity journal requires review: " + "; ".join(projection["warnings"]))
            known = {event["eventId"]: event for event in projection["events"]}
            new = []
            for event in imported:
                validate_event(event)
                if event["source"] != "browser" or event["workspaceId"] != workspace:
                    raise ValueError("browser activity requires browser source and matching workspaceId")
                if event["eventId"] in known:
                    if known[event["eventId"]] != event:
                        raise ValueError("conflicting payload for activity eventId")
                else:
                    known[event["eventId"]] = event
                    new.append(event)
            issues = lifecycle_issues(projection["events"] + new)
            if issues:
                raise ValueError("; ".join(issues))
            for event in sorted(new, key=event_order):
                self.append(event, locked=True)
            return {"ok": True, "importedCount": len(new), "duplicateCount": len(imported) - len(new),
                    "priorReportCount": sum(event["reportId"] != report for event in imported)}

    def status(self):
        projection = self.projection()
        drift = self.drift(projection)
        starts = {event["attemptId"]: event for event in projection["events"] if event["kind"] == "started"}
        finished = {event["attemptId"] for event in projection["events"]
                    if event["kind"] == "finished" and event["attemptId"] in starts
                    and not lifecycle_issues([starts[event["attemptId"]], event])}
        unfinished = [event for event in projection["events"]
                      if event["kind"] == "started" and event["attemptId"] not in finished]
        return {"schemaVersion": "1.0", "eventCount": len(projection["events"]),
                "unfinishedCount": len(unfinished), "unfinishedAttempts": unfinished,
                "warnings": projection["warnings"] + drift["warnings"],
                "baselineRequired": drift["baselineRequired"], "driftCount": len(drift["changes"]),
                "canonicalChanges": drift["changes"],
                **{outcome + "Count": sum(event["outcome"] == outcome for event in projection["events"])
                   for outcome in ("failed", "blocked", "stopped", "succeeded")}}


def record_action(root, action, callback, *, actor="toolkit", item_ids=None, details=None,
                  automatic=False, locked=False):
    """Write and fsync a start before executing. Callers may already hold the writer lock.

    Log failure after an action is explicitly different from action failure: the
    business files may already have changed and must be inspected before retry.
    """
    journal = ActivityJournal(root)
    journal.safe_path("data/activity.js")
    if automatic and not journal.active():
        return callback()
    with journal.mutation(locked=locked):
        journal.reconcile(locked=True)
        label = ACTION_LABELS.get(action, action)
        start = journal.start(action, f"작업 시작: {label}", actor, item_ids=item_ids,
                              source="toolkit", before=details or {}, locked=True)
        journal.refresh()  # An unwritable projection also blocks the business action.
        try:
            result = callback()
        except BaseException as error:
            outcome = "stopped" if isinstance(error, KeyboardInterrupt) else "failed"
            try:
                journal.reconcile(source="toolkit", actor=actor, operation_id=start["operationId"],
                                  attempt_id=start["attemptId"], locked=True)
                journal.finish(start["attemptId"], outcome,
                               f"작업 종료: {label} ({OUTCOME_LABELS[outcome]}) — {type(error).__name__}: {error}", locked=True)
                journal.refresh()
            except (OSError, ValueError, TypeError) as log_error:
                raise RuntimeError("action did not complete normally and its finish could not be saved; "
                                   "inspect current files and unfinished activity before retry: " + str(log_error)) from error
            raise
        code = result if isinstance(result, int) and not isinstance(result, bool) else 0
        outcome = "blocked" if code or (isinstance(result, dict) and result.get("ok") is False) else "succeeded"
        try:
            journal.reconcile(source="toolkit", actor=actor, operation_id=start["operationId"],
                              attempt_id=start["attemptId"], locked=True)
            journal.finish(start["attemptId"], outcome, f"작업 종료: {label} ({OUTCOME_LABELS[outcome]})",
                           after={"result": result} if isinstance(result, dict) else {"returnCode": code},
                           important=action in {"state.checkpoint", "state.snapshot", "state.seal-verification",
                                                "state.recover-progress", "toolkit.scope"}, locked=True)
            journal.refresh()
        except (OSError, ValueError, TypeError) as error:
            raise RuntimeError("action returned but its finish could not be saved; changes may already be applied; "
                               "inspect current files and unfinished activity before retry: " + str(error)) from error
        return result


def validate_browser_events(value, workspace_id):
    if not isinstance(value, list):
        raise ValueError("activityEvents must be an array")
    seen = {}
    for event in value:
        validate_event(event)
        if event["source"] != "browser" or event["workspaceId"] != workspace_id:
            raise ValueError("activityEvents requires browser source and matching workspaceId")
        if event["eventId"] in seen:
            raise ValueError("activityEvents contains duplicate eventId")
        seen[event["eventId"]] = event
    return value


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    start = commands.add_parser("start")
    for option in ("action", "summary", "actor"):
        start.add_argument("--" + option, required=True)
    start.add_argument("--id", action="append", default=[])
    start.add_argument("--operation-id")
    start.add_argument("--attempt-id")
    start.add_argument("--before", type=json.loads, default={})
    start.add_argument("--evidence", action="append", default=[])
    start.add_argument("--important", action="store_true")
    finish = commands.add_parser("finish")
    finish.add_argument("--attempt-id", required=True)
    finish.add_argument("--outcome", required=True, choices=("succeeded", "failed", "blocked", "stopped"))
    finish.add_argument("--summary", required=True)
    finish.add_argument("--after", type=json.loads, default={})
    finish.add_argument("--evidence", action="append", default=[])
    finish.add_argument("--important", action="store_true")
    note = commands.add_parser("note")
    for option in ("action", "summary", "actor"):
        note.add_argument("--" + option, required=True)
    note.add_argument("--id", action="append", default=[])
    note.add_argument("--source", choices=sorted(SOURCES), default="agent")
    note.add_argument("--kind", choices=("changed", "observation"), default="observation")
    note.add_argument("--outcome", choices=("info", "failed", "blocked", "stopped"), default="info")
    note.add_argument("--before", type=json.loads, default={})
    note.add_argument("--after", type=json.loads, default={})
    note.add_argument("--evidence", action="append", default=[])
    note.add_argument("--important", action="store_true")
    browser = commands.add_parser("import-browser")
    browser.add_argument("--file", type=Path, required=True)
    commands.add_parser("reconcile")
    commands.add_parser("status")
    query = commands.add_parser("query")
    query.add_argument("--id")
    return parser.parse_args()


def main():
    args = parse_args()
    journal = ActivityJournal(ROOT)
    try:
        if args.command == "start":
            result = journal.start(args.action, args.summary, args.actor, item_ids=args.id,
                                   operation_id=args.operation_id, attempt_id=args.attempt_id,
                                   before=args.before, evidence=args.evidence, important=args.important)
        elif args.command == "finish":
            result = journal.finish(args.attempt_id, args.outcome, args.summary, after=args.after,
                                    evidence=args.evidence, important=args.important)
        elif args.command == "note":
            result = journal.note(args.action, args.summary, args.actor, item_ids=args.id, source=args.source,
                                  kind=args.kind, outcome=args.outcome, before=args.before, after=args.after,
                                  evidence=args.evidence, important=args.important)
        elif args.command == "import-browser":
            result = journal.import_browser(args.file)
        elif args.command == "reconcile":
            result = journal.reconcile()
        elif args.command == "status":
            result = journal.status()
        else:
            result = journal.projection()
            if args.id:
                result["events"] = [event for event in result["events"] if args.id in event["itemIds"]]
        print(json_text(result), end="")
        return 0
    except (OSError, ValueError, TypeError) as error:
        print(json_text({"ok": False, "error": str(error)}), end="")
        return 2


if __name__ == "__main__":
    sys.exit(main())
