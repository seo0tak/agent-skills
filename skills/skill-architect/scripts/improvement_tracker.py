#!/usr/bin/env python3
"""Validate local improvement records. Never execute their contents or grant authority."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tempfile


STATES = ("captured", "proposed", "evaluated", "approved", "applied", "verified",
          "rejected", "rolled-back")
NOTICE = ("Recorded references are unverified claims: check actual user permission, "
          "its scope and current target outside this helper before taking action.")


class InvalidRecord(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise InvalidRecord(message)


def shape(value, fields):
    require(isinstance(value, dict), "Expected an object")
    require(set(value) == set(fields.split()), "Expected exactly these fields: " + fields)


def strings(value, fields):
    for field in fields.split():
        require(isinstance(value[field], str) and bool(value[field].strip()),
                field + " must be a nonempty string")


def sha(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None,
            "Expected a lowercase SHA256 digest")


def digest(value):
    raw = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def identifier(value):
    require(isinstance(value, str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", value) is not None,
            "id must contain 1-64 lowercase letters, digits or hyphens; start with a letter or digit")


def proposal(data):
    shape(data, "baseline target candidate rollback")
    for key, fields in (("baseline", "reproduction observed"), ("target", "path sha256"),
                        ("candidate", "summary change"), ("rollback", "version plan")):
        shape(data[key], fields)
        strings(data[key], fields)
    path = data["target"]["path"]
    require(not PurePosixPath(path).is_absolute() and not any(
        part in ("", ".", "..") for part in path.split("/")) and
        "\\" not in path and ":" not in path and not any(ord(c) < 32 for c in path),
        "target.path must be a project-relative POSIX path without traversal")
    sha(data["target"]["sha256"])


def bound(data, current):
    sha(data["binding"])
    require(data["binding"] == current["binding"], "Candidate/target binding changed; renew evaluation and authority")


def checkpoint(data):
    shape(data, "completed remaining notes nextAction")
    strings(data, "notes nextAction")
    for key in ("completed", "remaining"):
        require(isinstance(data[key], list) and all(
            isinstance(item, str) and item.strip() for item in data[key]),
            key + " must be an array of nonempty strings")


def advance(current, action, data):
    """Replay one event; only validated events contribute to the derived state."""
    state = current["state"]
    if action == "checkpoint":
        require(state is not None, "Capture a record before checkpointing")
        checkpoint(data)
        current["checkpoint"] = data
        return
    require(action in STATES, "Unknown lifecycle action")
    if action == "captured":
        require(state is None, "Record already captured")
        shape(data, "problem reproduction context")
        strings(data, "problem reproduction context")
        current["problem"] = data["problem"]
    elif action == "proposed":
        require(state in ("captured", "proposed", "evaluated", "approved"), "Cannot propose from " + str(state))
        proposal(data)
        current.update(proposal=data, binding=digest(data), evaluation=None,
                       evaluationDigest=None, authority=None, authorityReference=None)
    elif action == "evaluated":
        require(state == "proposed", "Evaluation requires a proposal")
        shape(data, "binding result baselineObserved candidateObserved evidence regressionResult regressionEvidence")
        strings(data, "baselineObserved candidateObserved evidence regressionEvidence")
        bound(data, current)
        require(data["result"] in ("pass", "fail") and data["regressionResult"] in ("pass", "fail"),
                "Evaluation results must be pass or fail")
        current.update(evaluation=data, evaluationDigest=digest(data))
    elif action == "approved":
        require(state == "evaluated", "Record a bound evaluation before its authority reference")
        shape(data, "binding evaluationDigest reference scope")
        strings(data, "reference scope")
        bound(data, current)
        require(data["evaluationDigest"] == current["evaluationDigest"], "Authority references a different evaluation")
        require(current["evaluation"]["result"] == "pass" and current["evaluation"]["regressionResult"] == "pass",
                "Failed evaluation or regression cannot advance to approved")
        current.update(authority=data, authorityReference=data["reference"])
    elif action == "applied":
        require(state == "approved", "Applied requires a bound evaluation and authority reference")
        shape(data, "binding evaluationDigest authorityReference preApplyTargetSha256 resultingTargetSha256 version evidence")
        strings(data, "authorityReference version evidence")
        bound(data, current)
        sha(data["preApplyTargetSha256"])
        sha(data["resultingTargetSha256"])
        require(data["preApplyTargetSha256"] == current["proposal"]["target"]["sha256"],
                "Target changed since proposal; reconcile and renew the proposal before application")
        require(data["evaluationDigest"] == current["evaluationDigest"] and
                data["authorityReference"] == current["authorityReference"],
                "Application must reference the recorded evaluation and authority")
        current["application"] = data
    elif action == "verified":
        require(state == "applied", "Verify only after recording application")
        shape(data, "binding resultingTargetSha256 version regressionResult regressionEvidence rollbackChecked")
        strings(data, "version regressionEvidence rollbackChecked")
        bound(data, current)
        require(data["resultingTargetSha256"] == current["application"]["resultingTargetSha256"] and
                data["version"] == current["application"]["version"],
                "Verification must match the recorded applied content and version")
        require(data["regressionResult"] == "pass", "Successful post-application regression required before verified")
        current["verification"] = data
    elif action == "rejected":
        require(state in ("captured", "proposed", "evaluated", "approved"), "Reject only before application")
        shape(data, "reason")
        strings(data, "reason")
    elif action == "rolled-back":
        require(state in ("applied", "verified"), "Rollback outcome requires recorded application")
        shape(data, "reason restoredVersion evidence")
        strings(data, "reason restoredVersion evidence")
        require(data["restoredVersion"] == current["proposal"]["rollback"]["version"],
                "Rollback outcome must identify the planned restored version")
        current["rollbackOutcome"] = data
    current["state"] = action
    current["checkpoint"] = None


def replay(record, record_id):
    shape(record, "schemaVersion id revision events")
    require(record["schemaVersion"] == "1.0", "Unsupported schemaVersion")
    identifier(record["id"])
    require(record["id"] == record_id, "Record id does not match its filename")
    require(type(record["revision"]) is int and isinstance(record["events"], list) and
            record["revision"] == len(record["events"]) and record["revision"] > 0,
            "Revision/event count mismatch or empty record")
    current = dict(id=record_id, revision=record["revision"], state=None, binding=None,
                   evaluationDigest=None, authorityReference=None, checkpoint=None)
    for event in record["events"]:
        shape(event, "action at data")
        strings(event, "action at")
        try:
            stamp = datetime.fromisoformat(event["at"])
            require(stamp.tzinfo is not None, "Event timestamp requires a timezone")
        except ValueError as exc:
            raise InvalidRecord("Invalid event timestamp") from exc
        advance(current, event["action"], event["data"])
    return current


def summary(current):
    evaluation = current.get("evaluation") or {}
    regression = current.get("verification") or evaluation
    actions = {
        "captured": "Describe baseline, exact target, candidate and rollback plan.",
        "proposed": "Evaluate the bound candidate and record observed regression results.",
        "evaluated": "Check evaluation results and actual user authority before recording a reference.",
        "approved": "Recheck actual user permission and target content before any application outside this helper.",
        "applied": "Reconcile actual files, run post-application regression, and check rollback availability.",
        "verified": "Recorded verification only; recheck current files before reusing this conclusion.",
        "rejected": "No application planned; capture a new record for a different improvement.",
        "rolled-back": "Rollback recorded; reconcile restored files before follow-up work."}
    result = {key: current[key] for key in (
        "id", "revision", "state", "problem", "binding", "evaluationDigest", "authorityReference", "checkpoint")}
    result.update(authorityAuthenticated=False, authorityNotice=NOTICE,
                  version=current.get("application", {}).get("version"),
                  rollbackVersion=current.get("proposal", {}).get("rollback", {}).get("version"),
                  evaluationResult=evaluation.get("result"),
                  regressionResult=regression.get("regressionResult"),
                  lifecycleNextAction=actions[current["state"]],
                  nextAction=(current["checkpoint"] or {}).get("nextAction", actions[current["state"]]))
    if current["state"] == "rolled-back":
        result.update(version=current["rollbackOutcome"]["restoredVersion"], regressionResult=None)
    return result


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON key: " + key)
        result[key] = value
    return result


def read_json(path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle, object_pairs_hook=unique_object,
                         parse_constant=lambda value: (_ for _ in ()).throw(InvalidRecord("Invalid JSON constant: " + value)))


def record_path(store, record_id):
    identifier(record_id)
    require(not store.is_symlink(), "Record store must not be a symlink")
    path = store / (record_id + ".json")
    require(not path.is_symlink(), "Record must not be a symlink")
    return path


@contextmanager
def writer(store):
    store.mkdir(parents=True, exist_ok=True)
    lock = store / ".write-lock"
    try:
        lock.mkdir()
    except FileExistsError as exc:
        raise InvalidRecord("Store writer lock exists; inspect interrupted/concurrent writer before recovery") from exc
    try:
        yield
    finally:
        lock.rmdir()


def save(path, record):
    descriptor, temporary = tempfile.mkstemp(prefix=".record-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(record, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise InvalidRecord(message)


def main(argv=None):
    try:
        parser = Parser(description=__doc__)
        parser.add_argument("--store", required=True, type=Path, help="Explicit local record directory; helper writes only here")
        commands = parser.add_subparsers(dest="command", required=True)
        for command in ("capture", "transition", "checkpoint", "validate", "summary"):
            child = commands.add_parser(command)
            child.add_argument("--id", required=True)
            if command in ("capture", "transition", "checkpoint"):
                child.add_argument("--data", required=True, type=Path, help="JSON payload file; content is inert data")
            if command in ("transition", "checkpoint"):
                child.add_argument("--expected-revision", type=int, required=True)
            if command == "transition":
                child.add_argument("--to", choices=STATES[1:], required=True)
        args = parser.parse_args(argv)
        path = record_path(args.store, args.id)
        if args.command in ("validate", "summary"):
            result = replay(read_json(path), args.id)
        else:
            data = read_json(args.data)
            with writer(args.store):
                path = record_path(args.store, args.id)
                if args.command == "capture":
                    require(not path.exists(), "Record already exists; capture never overwrites it")
                    record = dict(schemaVersion="1.0", id=args.id, revision=0, events=[])
                    action = "captured"
                else:
                    record = read_json(path)
                    replay(record, args.id)
                    require(args.expected_revision == record["revision"], "Revision conflict; validate and resume from current record")
                    action = args.to if args.command == "transition" else "checkpoint"
                record["events"].append(dict(action=action, at=datetime.now(timezone.utc).isoformat(), data=data))
                record["revision"] += 1
                result = replay(record, args.id)
                save(path, record)
        print(json.dumps(dict(ok=True, summary=summary(result)), ensure_ascii=False))
        return 0
    except (InvalidRecord, OSError, ValueError, TypeError, RecursionError) as exc:
        print(json.dumps(dict(ok=False, error=str(exc)), ensure_ascii=False))
        return 2


if __name__ == "__main__":
    sys.exit(main())
