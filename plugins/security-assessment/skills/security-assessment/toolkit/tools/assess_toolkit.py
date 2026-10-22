"""security-assessment 툴킷 — M0: 인가 게이트와 검증 (표준 라이브러리만).

서브커맨드:
  validate   스코프 파일의 형식·정합성을 검사한다. --strict는 게이트 미통과를 에러로.
  authorize  현재 스코프의 의미 지문을 기록하고 status를 authorized로 만든다.
  gate       기록된 승인과 현재 스코프·기간을 재대조해 READY/BLOCKED를 보고한다.

M0은 어떤 스캐너도 실행하지 않는다. 게이트만 다룬다. 게이트가 막는 것은
'사용자가 선언한 범위를 벗어나는 실수'와 '인가 주장의 기록'이다. 스킬은 동의가
진짜인지 검증하지 못하므로 악의적 사용자는 막지 못한다 (CONTEXT.md, SKILL.md).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
SCOPE_FILE = DATA_DIR / "scope.json"
ADAPTER_DIR = ROOT / "adapters"
SCHEMA_VERSION = "1.0"

TARGET_TYPES = {"repo", "web", "infra"}
# 침습도는 순서가 있다: passive < active-nondestructive < intrusive.
INTRUSIVENESS_RANK = {"passive": 0, "active-nondestructive": 1, "intrusive": 2}
INTRUSIVENESS = set(INTRUSIVENESS_RANK)
ADAPTER_CATEGORIES = {"sast", "sca", "secret", "dast", "iac"}
ADAPTER_ID_RE = re.compile(r"^[a-z][a-z0-9-]*$")
# M1a까지 정의된 출력 형식. 정규화기가 생기면(M1c~) 그 이름을 추가한다.
KNOWN_OUTPUT_FORMATS = {"sarif"}
# 티켓 ID(예: SEC-1234) 또는 http(s) URL.
REFERENCE_RE = re.compile(r"^(https?://\S+|[A-Za-z][A-Za-z0-9]*-\d+)$")


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json_atomic(path: Path, value: Any) -> None:
    text = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    descriptor, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


class Report:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def error(self, message: str) -> None:
        self.errors.append(message)

    def warn(self, message: str) -> None:
        self.warnings.append(message)

    def print(self) -> None:
        for message in self.errors:
            print(f"ERROR: {message}")
        for message in self.warnings:
            print(f"WARN: {message}")
        if self.errors:
            print(f"FAILED: {len(self.errors)} error(s), {len(self.warnings)} warning(s)")
        else:
            print(f"OK: validation completed with {len(self.warnings)} warning(s)")


def parse_day(value: str) -> datetime | None:
    """YYYY-MM-DD 또는 ISO 날짜시간을 받는다. Z 접미사를 허용한다."""
    text = str(value).strip()
    if not text:
        return None
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def semantic_fingerprint(scope: dict[str, Any]) -> str:
    """승인 무효 판정의 기준. 의미 필드만 넣고 notes·상태·지문 자체는 뺀다."""
    targets = sorted(
        ((str(t.get("type", "")), str(t.get("value", ""))) for t in scope.get("targets", []) if isinstance(t, dict)),
    )
    window = scope.get("window") or {}
    consent = scope.get("consent") or {}
    material = {
        "targets": targets,
        "exclusions": sorted(str(x) for x in scope.get("exclusions", [])),
        "window": {"start": str(window.get("start", "")), "end": str(window.get("end", ""))},
        "consent": {k: str(consent.get(k, "")) for k in ("authorizer", "role", "date", "reference")},
        "intrusiveness": str(scope.get("intrusiveness", "")),
    }
    encoded = json.dumps(material, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_scope(report: Report, scope: Any) -> None:
    if not isinstance(scope, dict):
        report.error("scope must be a JSON object")
        return
    if scope.get("schemaVersion") != SCHEMA_VERSION:
        report.error(f"scope schemaVersion must be {SCHEMA_VERSION!r}")
    if scope.get("status") not in {"unauthorized", "authorized"}:
        report.error("scope status must be 'unauthorized' or 'authorized'")

    targets = scope.get("targets")
    if not isinstance(targets, list) or not targets:
        report.error("scope.targets must be a non-empty list")
    else:
        for index, target in enumerate(targets):
            if not isinstance(target, dict):
                report.error(f"targets[{index}] must be an object")
                continue
            if target.get("type") not in TARGET_TYPES:
                report.error(f"targets[{index}].type must be one of {sorted(TARGET_TYPES)}")
            if not str(target.get("value", "")).strip():
                report.error(f"targets[{index}].value is empty")

    exclusions = scope.get("exclusions")
    if not isinstance(exclusions, list) or any(not str(x).strip() for x in exclusions):
        report.error("scope.exclusions must be a list of non-empty strings")

    window = scope.get("window")
    if not isinstance(window, dict):
        report.error("scope.window must be an object with start and end")
    else:
        start, end = parse_day(window.get("start", "")), parse_day(window.get("end", ""))
        if start is None:
            report.error("scope.window.start is missing or not a valid date")
        if end is None:
            report.error("scope.window.end is missing or not a valid date")
        if start is not None and end is not None and start > end:
            report.error("scope.window.start is after end")

    consent = scope.get("consent")
    if not isinstance(consent, dict):
        report.error("scope.consent must be an object")
    else:
        for field in ("authorizer", "role", "date", "reference"):
            if not str(consent.get(field, "")).strip():
                report.error(f"scope.consent.{field} is empty")
        reference = str(consent.get("reference", "")).strip()
        if reference and not REFERENCE_RE.match(reference):
            report.error("scope.consent.reference must be a ticket id (e.g. SEC-1234) or an http(s) URL")

    if scope.get("intrusiveness") not in INTRUSIVENESS:
        report.error(f"scope.intrusiveness must be one of {sorted(INTRUSIVENESS)}")

    # 승인 상태의 정합성: 지문이 현재 스코프와 일치해야 한다.
    if scope.get("status") == "authorized":
        if not str(scope.get("authorizedAt", "")).strip():
            report.error("authorized scope has no authorizedAt")
        recorded = scope.get("approvalFingerprint")
        current = semantic_fingerprint(scope)
        if not recorded:
            report.error("authorized scope has no approvalFingerprint; re-run authorize")
        elif recorded != current:
            report.error(
                "scope changed since authorization (semantic fields differ); "
                "approval is void, re-run authorize"
            )


def load_adapters() -> list[tuple[str, Any]]:
    """adapters/*.json을 (파일 stem, 내용)으로 읽는다. 없으면 빈 목록."""
    if not ADAPTER_DIR.is_dir():
        return []
    result: list[tuple[str, Any]] = []
    for path in sorted(ADAPTER_DIR.glob("*.json")):
        try:
            result.append((path.stem, load_json(path)))
        except (OSError, json.JSONDecodeError) as error:
            result.append((path.stem, {"__error__": str(error)}))
    return result


def validate_adapter(report: Report, name: str, adapter: Any) -> None:
    where = f"adapter {name}"
    if not isinstance(adapter, dict):
        report.error(f"{where} must be a JSON object")
        return
    if "__error__" in adapter:
        report.error(f"{where} cannot be read: {adapter['__error__']} (likely half-written)")
        return
    adapter_id = str(adapter.get("id", ""))
    if not ADAPTER_ID_RE.match(adapter_id):
        report.error(f"{where}.id must match ^[a-z][a-z0-9-]*$")
    elif adapter_id != name:
        report.error(f"{where}.id {adapter_id!r} does not match filename {name!r}")
    if adapter.get("category") not in ADAPTER_CATEGORIES:
        report.error(f"{where}.category must be one of {sorted(ADAPTER_CATEGORIES)}")
    if adapter.get("intrusiveness") not in INTRUSIVENESS:
        report.error(f"{where}.intrusiveness must be one of {sorted(INTRUSIVENESS)}")
    for field in ("availability", "command"):
        if not str(adapter.get(field, "")).strip():
            report.error(f"{where}.{field} is empty")
    output_format = str(adapter.get("output_format", ""))
    if not output_format:
        report.error(f"{where}.output_format is empty")
    elif output_format not in KNOWN_OUTPUT_FORMATS:
        report.error(
            f"{where}.output_format {output_format!r} has no normalizer yet; "
            f"known formats: {sorted(KNOWN_OUTPUT_FORMATS)}"
        )


def execution_decision(
    adapter: dict[str, Any], scope: dict[str, Any], direct_requested: bool
) -> tuple[str, str]:
    """어댑터를 스킬이 직접 실행할지 판정한다. 순수 함수 — 명령을 실행하지 않는다.

    반환: ("run" | "operator" | "forbidden", 사유). 침습도 세 겹 (ADR 0002):
      ① 어댑터 침습도 > 스코프 상한 → forbidden
      ② active-nondestructive 이하 + 사용자 직접 실행 명시 → run
      ③ 그 외(intrusive, 또는 미명시) → operator
    """
    adapter_level = INTRUSIVENESS_RANK.get(str(adapter.get("intrusiveness")), None)
    scope_cap = INTRUSIVENESS_RANK.get(str(scope.get("intrusiveness")), None)
    if adapter_level is None:
        return "forbidden", "어댑터 침습도가 유효하지 않음"
    if scope_cap is None:
        return "forbidden", "스코프 침습도 상한이 유효하지 않음"
    if adapter_level > scope_cap:
        return "forbidden", (
            f"어댑터 침습도({adapter.get('intrusiveness')})가 스코프 상한"
            f"({scope.get('intrusiveness')})을 넘음"
        )
    if adapter_level > INTRUSIVENESS_RANK["active-nondestructive"]:
        return "operator", "intrusive 어댑터는 스코프 건별 인가 + 운영자 실행만"
    if not direct_requested:
        return "operator", "사용자가 직접 실행을 명시하지 않음 — 명령을 지시"
    return "run", "active-nondestructive 이하 + 직접 실행 명시"


def gate_status(scope: dict[str, Any]) -> tuple[bool, list[str]]:
    """게이트 판정. (ready, blockers). 기계 점검만. 의미 확인은 프롬프트 단계."""
    blockers: list[str] = []
    if scope.get("status") != "authorized":
        blockers.append("scope is not authorized; record consent and run authorize")
        return False, blockers
    recorded = scope.get("approvalFingerprint")
    if recorded != semantic_fingerprint(scope):
        blockers.append("scope changed since authorization; approval is void, re-run authorize")
    window = scope.get("window") or {}
    start, end = parse_day(window.get("start", "")), parse_day(window.get("end", ""))
    today = now_utc()
    if start is not None and today < start:
        blockers.append(f"assessment window has not started (starts {window.get('start')})")
    if end is not None:
        # 날짜만 주어진 종료는 그 날의 끝까지 유효로 본다.
        end_of = end.replace(hour=23, minute=59, second=59) if end.hour == end.minute == 0 else end
        if today > end_of:
            blockers.append(f"assessment window has expired (ended {window.get('end')})")
    return (not blockers), blockers


def run_validate(strict: bool) -> int:
    report = Report()
    if not SCOPE_FILE.exists():
        report.error(f"{SCOPE_FILE.relative_to(ROOT)} not found; create it from examples/scope.json")
        report.print()
        return 1
    try:
        scope = load_json(SCOPE_FILE)
    except (OSError, json.JSONDecodeError) as error:
        report.error(f"cannot read data/scope.json: {error} (likely half-written)")
        report.print()
        return 1
    validate_scope(report, scope)
    for name, adapter in load_adapters():
        validate_adapter(report, name, adapter)
    if strict and isinstance(scope, dict) and not report.errors:
        ready, blockers = gate_status(scope)
        if not ready:
            for blocker in blockers:
                report.error(f"gate not ready: {blocker}")
    report.print()
    return 1 if report.errors else 0


def run_authorize() -> int:
    report = Report()
    try:
        scope = load_json(SCOPE_FILE)
    except (OSError, json.JSONDecodeError) as error:
        print(f"ERROR: cannot read data/scope.json: {error}")
        return 1
    validate_scope(report, scope)
    # 승인 지문 불일치/미기록은 authorize 자체가 고치는 문제이므로 그것만 제외하고 막는다.
    blocking = [e for e in report.errors if "approvalFingerprint" not in e and "scope changed since authorization" not in e]
    if blocking:
        for message in blocking:
            print(f"ERROR: {message}")
        print("FAILED: fix scope errors before authorizing")
        return 1
    scope["status"] = "authorized"
    scope["authorizedAt"] = now_utc().strftime("%Y-%m-%dT%H:%M:%SZ")
    scope["approvalFingerprint"] = semantic_fingerprint(scope)
    write_json_atomic(SCOPE_FILE, scope)
    print("OK: scope authorized. The gate accepts the declared scope; it cannot verify consent is genuine.")
    print(f"     authorizedAt {scope['authorizedAt']}  fingerprint {scope['approvalFingerprint'][:12]}")
    return 0


def run_gate() -> int:
    try:
        scope = load_json(SCOPE_FILE)
    except (OSError, json.JSONDecodeError) as error:
        print(f"GATE: BLOCKED\n- cannot read data/scope.json: {error}")
        return 1
    ready, blockers = gate_status(scope) if isinstance(scope, dict) else (False, ["scope is not an object"])
    if ready:
        print("GATE: READY")
        print(f"- targets: {len(scope.get('targets', []))}  intrusiveness: {scope.get('intrusiveness')}")
        print("- machine checks only; confirm target reachability and exclusions semantically before scanning")
        return 0
    print("GATE: BLOCKED")
    for blocker in blockers:
        print(f"- {blocker}")
    return 1


def run_adapters(direct: bool) -> int:
    """어댑터별 실행 판정을 보여 준다. 어떤 명령도 실행하지 않는다(판정만)."""
    adapters = load_adapters()
    if not adapters:
        print("선언된 어댑터가 없습니다 (adapters/*.json). M1b 이후 추가됩니다.")
        return 0
    try:
        scope = load_json(SCOPE_FILE)
    except (OSError, json.JSONDecodeError) as error:
        print(f"ERROR: cannot read data/scope.json: {error}")
        return 1
    if not isinstance(scope, dict):
        print("ERROR: scope is not an object")
        return 1
    ready, _ = gate_status(scope)
    print(f"gate: {'READY' if ready else 'BLOCKED'}  |  직접 실행 명시: {direct}")
    if not ready:
        print("게이트가 READY가 아니면 'run' 판정이어도 실제 실행은 막힙니다.")
    for name, adapter in adapters:
        if not isinstance(adapter, dict) or "__error__" in adapter:
            print(f"- {name}: (선언 오류 — validate로 확인)")
            continue
        decision, reason = execution_decision(adapter, scope, direct)
        print(f"- {name} [{adapter.get('category')}/{adapter.get('intrusiveness')}] → {decision}: {reason}")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="security-assessment authorization gate and adapter decisions (M1a).")
    parser.add_argument("command", choices=("validate", "authorize", "gate", "adapters"))
    parser.add_argument("--strict", action="store_true", help="treat a not-ready gate as a validation error")
    parser.add_argument("--direct", action="store_true", help="adapters: 사용자가 직접 실행을 명시했다고 본다")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "validate":
        return run_validate(args.strict)
    if args.command == "authorize":
        return run_authorize()
    if args.command == "adapters":
        return run_adapters(args.direct)
    return run_gate()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        sys.exit(0)
