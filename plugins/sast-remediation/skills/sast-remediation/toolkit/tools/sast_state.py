#!/usr/bin/env python3
"""User-invoked checkpoints and conservative recovery. Never executes commands."""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
import uuid

try:
    from .sast_io import writer_lock, write_text_atomic, write_bytes_atomic
except ImportError:
    from sast_io import writer_lock, write_text_atomic, write_bytes_atomic

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = {"todo", "in-progress", "analyzed", "change-complete", "verified", "deferred"}
CONCLUSIONS = {"unreviewed", "fix", "false-positive", "operations", "exception", "needs-review"}


def now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def read_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ValueError(f"cannot read {path}: {error}") from error


def save_json(path, value):
    write_text_atomic(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}", value) or value in {"index"}:
        raise ValueError(f"invalid finding identifier: {value!r}")
    return value


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError("timestamp must be an ISO date-time string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return parsed


def safe_record(root, relative):
    path = root / relative
    if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
        raise ValueError(f"record path escapes toolkit or is a symlink: {relative}")
    return path


def source_path(project_root, relative):
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise ValueError("source path must be a nonempty relative POSIX path")
    parts = PurePosixPath(relative)
    if parts.is_absolute() or ".." in parts.parts or str(parts) != relative or ":" in relative:
        raise ValueError(f"unsafe source path: {relative}")
    path = project_root / relative
    if not path.resolve().is_relative_to(project_root.resolve()) or not path.is_file():
        raise ValueError(f"source is missing or outside project root: {relative}")
    return path


def progress_item(item):
    if (not isinstance(item, dict) or not isinstance(item.get("workflowStatus"), str)
            or item["workflowStatus"] not in WORKFLOWS or not isinstance(item.get("conclusion"), str)
            or item["conclusion"] not in CONCLUSIONS or not isinstance(item.get("note"), str)):
        raise ValueError("invalid progress item: workflowStatus and conclusion must be supported string values; note must be a string")
    if item.get("updatedAt") is not None:
        timestamp(item["updatedAt"])
    return item


def evidence_digest(result):
    value = copy.deepcopy(result)
    value.get("verification", {}).pop("sourceSnapshot", None)
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def passed_evidence(verification):
    results = verification.get("results")
    return (verification.get("status") == "passed"
            and isinstance(verification.get("method"), str) and bool(verification["method"].strip())
            and isinstance(results, list) and bool(results)
            and all(isinstance(result, str) and result.strip() for result in results))


class Workspace:
    def __init__(self, root, project_root):
        self.root = root.resolve()
        self.project_root = project_root.resolve()
        if not self.project_root.is_dir():
            raise ValueError("project root must be an existing directory")
        profile = read_json(safe_record(self.root, "data/project-profile.json"))
        if not isinstance(profile, dict) or profile.get("schemaVersion") != "1.0":
            raise ValueError("unsupported project profile")
        self.workspace_id = profile.get("workspaceId")
        if not isinstance(self.workspace_id, str) or not self.workspace_id.strip() or self.workspace_id == "uninitialized":
            raise ValueError("workspaceId is not initialized")
        findings = read_json(safe_record(self.root, "data/findings.json"))
        if not isinstance(findings, list):
            raise ValueError("findings must be a list")
        self.ids = {identifier(item.get("id")) for item in findings if isinstance(item, dict)}
        if len(self.ids) != len(findings):
            raise ValueError("unsupported or duplicate findings")
        self.sequences = {item["id"]: item.get("sequence") for item in findings}
        self.state_path = safe_record(self.root, "data/resume-state.json")
        self.progress_path = safe_record(self.root, "data/progress.json")

    def check_id(self, finding_id):
        identifier(finding_id)
        if finding_id not in self.ids:
            raise ValueError(f"unknown finding: {finding_id}")

    def envelope(self, record):
        if not isinstance(record, dict) or record.get("schemaVersion") != "1.0" or record.get("workspaceId") != self.workspace_id:
            raise ValueError("unsupported schemaVersion or foreign workspaceId")

    def progress(self, record):
        self.envelope(record)
        if "draftResults" in record:
            self.drafts(record["draftResults"])
        if not isinstance(record.get("items"), dict):
            raise ValueError("progress items must be a mapping")
        for key, item in record["items"].items():
            self.check_id(key)
            progress_item(item)
        return record

    def drafts(self, drafts):
        if not isinstance(drafts, dict):
            raise ValueError("draftResults must be a mapping of browser draft wrappers")
        try:
            from .sast_toolkit import ValidationReport, validate_schema_contract
        except ImportError:
            from sast_toolkit import ValidationReport, validate_schema_contract
        for key, draft in drafts.items():
            self.check_id(key)
            if not isinstance(draft, dict) or draft.get("source") != "browser-answer":
                raise ValueError(f"draft {key} requires browser-answer source provenance")
            timestamp(draft.get("savedAt"))
            result = draft.get("result")
            if (not isinstance(result, dict) or result.get("schemaVersion") != "1.0"
                    or result.get("id") != key or result.get("sequence") != self.sequences[key]):
                raise ValueError(f"draft {key} result identity/schema/sequence does not match findings")
            for value in (draft, result):
                if "workspaceId" in value and value["workspaceId"] != self.workspace_id:
                    raise ValueError(f"draft {key} has foreign workspaceId")
            report = ValidationReport()
            if not validate_schema_contract(report, result, "result.schema.json", f"draft {key}"):
                raise ValueError(f"unsupported draft {key} result schema: {report.errors}")
            timestamp(result.get("updatedAt"))
            verification = result["verification"]
            if verification.get("verifiedAt") is not None:
                timestamp(verification["verifiedAt"])
            if "sourceSnapshot" in verification:
                self.validate_snapshot(verification["sourceSnapshot"], key)
                timestamp(verification["sourceSnapshot"].get("sealedAt"))

    def state(self):
        if not self.state_path.exists():
            return {"schemaVersion": "1.0", "workspaceId": self.workspace_id,
                    "projectRoot": str(self.project_root), "checkpoints": {}, "snapshots": {}}
        record = read_json(self.state_path)
        self.envelope(record)
        if record.get("projectRoot") != str(self.project_root):
            raise ValueError("resume state belongs to a different project root")
        for kind in ("checkpoints", "snapshots"):
            if not isinstance(record.get(kind), dict):
                raise ValueError(f"resume state {kind} must be a mapping")
            for key, item in record[kind].items():
                self.check_id(key)
                if not isinstance(item, dict):
                    raise ValueError(f"invalid {kind} record")
                if kind == "checkpoints":
                    progress_item(item.get("progress"))
                    timestamp(item.get("recordedAt"))
                    if not isinstance(item.get("phase"), str) or item["phase"] not in {"before-edit", "after-edit"} or not isinstance(item.get("note"), str) or not isinstance(item.get("nextAction"), str):
                        raise ValueError("invalid checkpoint: phase must be before-edit or after-edit; note and nextAction must be strings")
                    if "sourceSnapshot" in item:
                        self.validate_snapshot(item["sourceSnapshot"], key)
                else:
                    self.validate_snapshot(item, key)
        return record

    def capture(self, finding_id, paths):
        self.check_id(finding_id)
        files = {path: hashlib.sha256(source_path(self.project_root, path).read_bytes()).hexdigest()
                 for path in paths}
        if not files:
            raise ValueError("snapshot requires at least one source path")
        return {"schemaVersion": "1.0", "workspaceId": self.workspace_id,
                "projectRoot": str(self.project_root), "id": finding_id,
                "capturedAt": now(), "files": files}

    def validate_snapshot(self, snapshot, finding_id):
        self.envelope(snapshot)
        if snapshot.get("projectRoot") != str(self.project_root) or snapshot.get("id") != finding_id:
            raise ValueError("source snapshot belongs to another item or project root")
        timestamp(snapshot.get("capturedAt"))
        files = snapshot.get("files")
        if not isinstance(files, dict) or not files:
            raise ValueError("source snapshot files must be a nonempty mapping")
        for path, digest in files.items():
            # Validate syntax without requiring an old source file still to exist.
            if not isinstance(path, str) or "\\" in path or ":" in path or not path or PurePosixPath(path).is_absolute() or ".." in PurePosixPath(path).parts or str(PurePosixPath(path)) != path:
                raise ValueError("unsafe snapshot source path")
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError("invalid source digest")

    def snapshot_changes(self, snapshot, finding_id):
        self.validate_snapshot(snapshot, finding_id)
        changed = []
        for relative, digest in snapshot["files"].items():
            try:
                current = hashlib.sha256(source_path(self.project_root, relative).read_bytes()).hexdigest()
            except (OSError, ValueError):
                current = None
            if current != digest:
                changed.append(relative)
        return changed

    def checkpoint(self, args):
        self.check_id(args.id)
        state = self.state()
        progress = self.progress(read_json(self.progress_path))
        item = progress["items"].get(args.id, {"workflowStatus": "todo", "conclusion": "unreviewed", "note": ""})
        previous = state["checkpoints"].get(args.id, {})
        record = {**copy.deepcopy(previous), "recordedAt": now(), "phase": args.phase,
                  "note": args.note if args.note is not None else previous.get("note", ""),
                  "nextAction": args.next_action if args.next_action is not None else previous.get("nextAction", ""),
                  "progress": copy.deepcopy(item)}
        if args.path:
            record["sourceSnapshot"] = self.capture(args.id, args.path)
        state["checkpoints"][args.id] = record
        state["updatedAt"] = now()
        save_json(self.state_path, state)
        return {"ok": True, "checkpoint": record}

    def results(self):
        directory = safe_record(self.root, "security-results")
        results = {}
        for path in sorted(directory.glob("*.json")):
            if path.name == "index.json":
                continue
            self.check_id(path.stem)
            result = read_json(safe_record(self.root, str(path.relative_to(self.root))))
            if not isinstance(result, dict) or result.get("schemaVersion") != "1.0" or result.get("id") != path.stem:
                raise ValueError(f"unsupported result record: {path.name}")
            if result.get("workflowStatus") not in WORKFLOWS or result.get("conclusion") not in CONCLUSIONS or not isinstance(result.get("verification"), dict):
                raise ValueError(f"unsupported result fields: {path.name}")
            # Reuse the shipped result schema without an external dependency.
            try:
                from .sast_toolkit import ValidationReport, validate_schema_contract
            except ImportError:
                from sast_toolkit import ValidationReport, validate_schema_contract
            report = ValidationReport()
            if not validate_schema_contract(report, result, "result.schema.json", f"result {path.stem}"):
                raise ValueError(f"unsupported result schema: {path.name}: {report.errors}")
            results[path.stem] = result
        return results

    def verification_status(self, finding_id, result):
        verification = result["verification"]
        binding = verification.get("sourceSnapshot")
        if "sourceSnapshot" not in verification:
            return {"status": "unbound" if result.get("workflowStatus") == "verified" or verification.get("status") == "passed" else "not-verified",
                    "reason": "No source binding; legacy passed strings require a new snapshot and verification."}
        try:
            self.validate_snapshot(binding, finding_id)
            sealed_at = timestamp(binding.get("sealedAt"))
            verified_at = timestamp(verification.get("verifiedAt"))
            if not passed_evidence(verification):
                raise ValueError("binding has no passed verification evidence")
            if not timestamp(binding["capturedAt"]) < verified_at <= sealed_at:
                raise ValueError("verification timestamp is outside snapshot/seal interval")
            if binding.get("evidenceDigest") != evidence_digest(result):
                raise ValueError("result evidence changed since sealing")
            changed = self.snapshot_changes(binding, finding_id)
            if changed:
                raise ValueError("source changed: " + ", ".join(changed))
        except (ValueError, TypeError, KeyError) as error:
            return {"status": "stale", "reason": str(error)}
        return {"status": "fresh", "sealedAt": binding["sealedAt"],
                "scope": sorted(binding["files"])}

    def snapshot(self, args):
        state = self.state()
        snapshot = self.capture(args.id, args.path)
        state["snapshots"][args.id] = snapshot
        state["updatedAt"] = now()
        save_json(self.state_path, state)
        return {"ok": True, "snapshot": snapshot}

    def seal(self, args):
        self.check_id(args.id)
        snapshot = self.state()["snapshots"].get(args.id)
        if snapshot is None:
            raise ValueError("capture a snapshot before running verification")
        result = self.results().get(args.id)
        if result is None:
            raise ValueError("canonical result is required")
        verification = result["verification"]
        if not passed_evidence(verification):
            raise ValueError("passed verification with method and results is required")
        verified_at = timestamp(verification.get("verifiedAt"))
        if verified_at <= timestamp(snapshot["capturedAt"]):
            raise ValueError("verification predates or equals snapshot; rerun verification and record a later timestamp")
        sealed_at = now()
        if verified_at > timestamp(sealed_at):
            raise ValueError("verification timestamp is in the future")
        if not set(result["resultFiles"]).issubset(snapshot["files"]):
            raise ValueError("snapshot does not cover all resultFiles")
        changed = self.snapshot_changes(snapshot, args.id)
        if changed:
            raise ValueError("source changed since snapshot: " + ", ".join(changed))
        binding = {**snapshot, "sealedAt": sealed_at, "evidenceDigest": evidence_digest(result)}
        verification["sourceSnapshot"] = binding
        save_json(safe_record(self.root, f"security-results/{args.id}.json"), result)
        return {"ok": True, "id": args.id, "verification": self.verification_status(args.id, result)}

    def recovery(self, args):
        state = self.state()
        warnings = []
        current_parsed = False
        try:
            current = read_json(self.progress_path)
            current_parsed = True
        except (OSError, ValueError) as error:
            current = None
            warnings.append(f"Current progress unavailable: {error}")
        if current_parsed:
            # A parseable foreign/unsupported envelope is not same-workspace
            # corruption. Establish identity before salvaging any item.
            self.envelope(current)
            if "draftResults" in current:
                self.drafts(current["draftResults"])
            current = copy.deepcopy(current)
            items = current.get("items")
            current["items"] = {}
            if not isinstance(items, dict):
                warnings.append("Current progress items are structurally damaged; reconstructing from other records.")
            else:
                for key, item in items.items():
                    self.check_id(key)
                    try:
                        current["items"][key] = progress_item(item)
                    except ValueError as error:
                        warnings.append(f"Current progress item {key} is damaged; its partial fields remain in the original backup: {error}")
        supplied = self.progress(read_json(Path(args.backup))) if args.backup else None
        recovered = copy.deepcopy(current or supplied or {"schemaVersion": "1.0", "workspaceId": self.workspace_id, "items": {}})
        if supplied is not None:
            for key, value in supplied.items():
                if key in {"items", "updatedAt"}:
                    continue
                if key in recovered and recovered[key] != value:
                    raise ValueError(f"ambiguous recovery conflict in backup field {key}")
                recovered[key] = copy.deepcopy(value)
        for origin, candidate in (("backup", supplied), ("checkpoint", {"items": {key: value["progress"] for key, value in state["checkpoints"].items()}})):
            if candidate is None:
                continue
            for key, item in candidate["items"].items():
                existing = recovered["items"].get(key)
                if existing is not None and existing != item:
                    raise ValueError(f"ambiguous recovery conflict for {key} ({origin}); reconcile explicitly")
                recovered["items"][key] = copy.deepcopy(item)
        results = self.results()
        verification = {key: self.verification_status(key, value) for key, value in results.items()}
        lost_notes = []
        for key, result in results.items():
            if key not in recovered["items"]:
                lost_notes.append(key)
                recovered["items"][key] = {"note": ""}
            recovered["items"][key].update({field: result[field] for field in ("workflowStatus", "conclusion")})
        missing = sorted(self.ids - recovered["items"].keys())
        if missing:
            warnings.append("Unrecoverable provisional progress/notes for: " + ", ".join(missing))
        if lost_notes:
            warnings.append("Results cannot recover provisional notes for: " + ", ".join(lost_notes))
        recovered["updatedAt"] = now()
        output = {"ok": True, "applied": False, "progress": recovered,
                  "warnings": warnings, "unrecoverable": sorted(set(missing + lost_notes)),
                  "verification": verification}
        if args.apply:
            if self.progress_path.exists():
                backup = safe_record(self.root, f"data/progress.recovery-{uuid.uuid4().hex}.bak")
                write_bytes_atomic(backup, self.progress_path.read_bytes())
                output["backup"] = str(backup.relative_to(self.root))
            save_json(self.progress_path, recovered)
            output["applied"] = True
        return output

    def status(self):
        state = self.state()
        progress = self.progress(read_json(self.progress_path))
        results = self.results()
        verification = {key: self.verification_status(key, value) for key, value in results.items()}
        candidates = {key for key in self.ids
                      if progress["items"].get(key, {}).get("workflowStatus") != "verified"
                      or results.get(key, {}).get("workflowStatus") != "verified"
                      or verification.get(key, {}).get("status") != "fresh"
                      or progress["items"].get(key, {}).get("conclusion") != results.get(key, {}).get("conclusion")}
        pending = []
        changes = {}
        for key, checkpoint in state["checkpoints"].items():
            if "sourceSnapshot" in checkpoint:
                changes[key] = self.snapshot_changes(checkpoint["sourceSnapshot"], key)
            fresh = verification.get(key, {})
            if fresh.get("status") != "fresh" or timestamp(checkpoint["recordedAt"]) > timestamp(fresh["sealedAt"]):
                candidates.add(key)
                pending.append(key)
        return {"ok": True, "workspaceId": self.workspace_id,
                "resumeCandidates": sorted(candidates), "checkpoints": state["checkpoints"],
                "pendingCheckpoints": sorted(pending), "checkpointSourceChanges": changes,
                "verification": verification}


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("checkpoint", "snapshot", "seal-verification", "status", "recover-progress"):
        child = commands.add_parser(name)
        child.add_argument("--project-root", type=Path, default=ROOT.parent,
                           help="Source project root (default: toolkit parent)")
        if name in {"checkpoint", "snapshot", "seal-verification"}:
            child.add_argument("--id", required=True)
        if name in {"checkpoint", "snapshot"}:
            child.add_argument("--path", action="append", required=name == "snapshot",
                               help="Source file relative to project root; repeat for multiple files")
        if name == "checkpoint":
            child.add_argument("--phase", choices=("before-edit", "after-edit"), default="before-edit")
            child.add_argument("--note")
            child.add_argument("--next-action")
        if name == "recover-progress":
            child.add_argument("--backup", type=Path, help="Progress/browser backup JSON; drafts remain drafts")
            child.add_argument("--apply", action="store_true", help="Back up and replace progress; default previews only")
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        def execute():
            workspace = Workspace(ROOT, args.project_root)
            if args.command == "checkpoint":
                return workspace.checkpoint(args)
            if args.command == "status":
                return workspace.status()
            if args.command == "recover-progress":
                return workspace.recovery(args)
            if args.command == "snapshot":
                return workspace.snapshot(args)
            return workspace.seal(args)
        if args.command in {"status", "recover-progress"} and not getattr(args, "apply", False):
            result = execute()
        else:
            with writer_lock(ROOT):
                result = execute()
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except (OSError, ValueError, TypeError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    sys.exit(main())
