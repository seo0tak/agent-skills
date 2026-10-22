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
# 카테고리가 어떤 대상 타입에 적용되는지. 어댑터는 자기 카테고리에 맞는 대상에만
# 실행된다 (SAST를 web 대상에 돌리지 않는다). infra 타입은 아직 매핑되는 카테고리가
# 없다 — 라이브 인프라 스캐너가 생기면 추가한다. iac는 저장소의 IaC 파일을 보므로 repo.
CATEGORY_TARGET_TYPES = {
    "sast": {"repo"},
    "sca": {"repo"},
    "secret": {"repo"},
    "iac": {"repo"},
    "dast": {"web"},
}
ADAPTER_ID_RE = re.compile(r"^[a-z][a-z0-9-]*$")
# 출력 형식 → SARIF 정규화기. 어댑터가 output_format으로 이 중 하나를 가리킨다.
# "sarif"는 변환 없이 통과. 새 형식의 도구를 붙이려면 정규화기 하나만 추가한다.
def _identity_sarif(raw: Any) -> Any:
    return raw


def osv_to_sarif(raw: Any) -> dict[str, Any]:
    """OSV-scanner JSON을 SARIF로 변환한다. 순수 함수.

    의존성 취약점: 위치는 매니페스트/락 파일, 논리 위치는 패키지(지문이 패키지로
    묶이도록), CWE는 database_specific.cwe_ids에서, 심각도는 vuln.severity에서.
    """
    results: list[dict[str, Any]] = []
    if not isinstance(raw, dict):
        return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "osv"}}, "results": results}]}
    for block in raw.get("results") or []:
        source_path = str(((block or {}).get("source") or {}).get("path") or "")
        for package_entry in (block or {}).get("packages") or []:
            package = (package_entry or {}).get("package") or {}
            package_name = str(package.get("name") or "")
            package_version = str(package.get("version") or "")
            qualified = f"{package_name}@{package_version}" if package_version else package_name
            for vuln in (package_entry or {}).get("vulnerabilities") or []:
                vuln = vuln or {}
                cwe_ids = ((vuln.get("database_specific") or {}).get("cwe_ids")) or []
                severity = ""
                for entry in vuln.get("severity") or []:
                    if isinstance(entry, dict) and entry.get("score"):
                        severity = str(entry.get("score"))
                        break
                results.append({
                    "ruleId": str(vuln.get("id") or ""),
                    "level": "warning",
                    "message": {"text": str(vuln.get("summary") or vuln.get("id") or "")},
                    "properties": {"cwe": list(cwe_ids), "severity": severity},
                    "locations": [{
                        "physicalLocation": {"artifactLocation": {"uri": source_path}},
                        "logicalLocations": [{"fullyQualifiedName": qualified}],
                    }],
                })
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "osv"}}, "results": results}]}


NORMALIZERS = {"sarif": _identity_sarif, "osv-json": osv_to_sarif}
KNOWN_OUTPUT_FORMATS = set(NORMALIZERS)


def normalize_to_sarif(output_format: str, raw: Any) -> Any:
    normalizer = NORMALIZERS.get(output_format)
    if normalizer is None:
        raise ValueError(f"no normalizer for output_format {output_format!r}")
    return normalizer(raw)
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


def targets_for_adapter(adapter: dict[str, Any], scope: dict[str, Any]) -> list[str]:
    """어댑터 카테고리에 맞는 대상 값만 돌려준다. 순수 함수."""
    accepted = CATEGORY_TARGET_TYPES.get(str(adapter.get("category")), set())
    return [
        str(t.get("value", ""))
        for t in scope.get("targets", [])
        if isinstance(t, dict) and t.get("value") and str(t.get("type")) in accepted
    ]


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


FINDINGS_FILE = DATA_DIR / "findings.json"
CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)


def normalize_cwe(values: Any) -> str:
    """여러 후보에서 첫 CWE 식별자를 'CWE-NN'으로 정규화한다."""
    for value in values or []:
        match = CWE_RE.search(str(value))
        if match:
            return f"CWE-{match.group(1)}"
    return ""


def cwe_from_result(result: dict[str, Any], rule: dict[str, Any] | None) -> str:
    candidates: list[str] = []
    props = result.get("properties") or {}
    candidates += list(props.get("cwe") or [])
    candidates += list(props.get("tags") or [])
    if rule:
        rule_props = rule.get("properties") or {}
        candidates += list(rule_props.get("cwe") or [])
        candidates += list(rule_props.get("tags") or [])
    return normalize_cwe(candidates)


def fingerprint_for(file: str, function: str | None, snippet: str) -> str:
    """위치 독립 지문. 스캐너·줄 번호에 비의존(파일+함수, 없으면 파일+정규화 스니펫)."""
    if function:
        material = f"{file}|fn:{function}"
    else:
        material = f"{file}|snip:{' '.join(snippet.split())}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def findings_from_sarif(sarif: Any, fallback_scanner: str) -> list[dict[str, Any]]:
    """SARIF 하나를 정규화된 검출 목록으로. 순수 함수."""
    out: list[dict[str, Any]] = []
    if not isinstance(sarif, dict):
        return out
    for run in sarif.get("runs") or []:
        driver = (run.get("tool") or {}).get("driver") or {}
        scanner = str(driver.get("name") or fallback_scanner)
        rules = {str(r.get("id")): r for r in (driver.get("rules") or []) if isinstance(r, dict)}
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            rule_id = str(result.get("ruleId") or "")
            rule = rules.get(rule_id)
            locations = result.get("locations") or [{}]
            loc = locations[0] if isinstance(locations[0], dict) else {}
            phys = loc.get("physicalLocation") or {}
            file = str((phys.get("artifactLocation") or {}).get("uri") or "")
            region = phys.get("region") or {}
            line = region.get("startLine")
            snippet = str((region.get("snippet") or {}).get("text") or "")
            logicals = loc.get("logicalLocations") or [{}]
            logical = logicals[0] if isinstance(logicals[0], dict) else {}
            function = logical.get("fullyQualifiedName") or logical.get("name")
            out.append({
                "fingerprint": fingerprint_for(file, function, snippet),
                "cwe": cwe_from_result(result, rule),
                "location": {"file": file, "line": line, "function": function},
                "message": str((result.get("message") or {}).get("text") or ""),
                # properties.severity(예: OSV의 CVSS 점수)를 우선, 없으면 SARIF level.
                "severity": str((result.get("properties") or {}).get("severity") or result.get("level") or ""),
                "sources": [{"scanner": scanner, "ruleId": rule_id, "line": line}],
            })
    return out


def merge_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """지문+CWE가 같은 검출을 하나로 묶고 출처를 합친다. 순수 함수 (ADR 없음; grill 질문5)."""
    bucket: dict[tuple[str, str], dict[str, Any]] = {}
    order: list[tuple[str, str]] = []
    for finding in findings:
        key = (finding["fingerprint"], finding["cwe"])
        if key not in bucket:
            bucket[key] = {**finding, "sources": [dict(s) for s in finding["sources"]]}
            order.append(key)
            continue
        existing = bucket[key]
        for source in finding["sources"]:
            if source not in existing["sources"]:
                existing["sources"].append(dict(source))
        if not existing.get("message") and finding.get("message"):
            existing["message"] = finding["message"]
    return [bucket[key] for key in order]


def execute_adapter(command_template: str, target: str, output_path: Path, timeout: int = 600) -> int:
    """어댑터 명령을 shell 없이 실행한다. 자리표시자는 argv 토큰으로 치환(주입 방지).

    테스트는 실제 스캐너 대신 이 함수를 교체해 픽스처를 쓴다(도구 미실행).
    """
    import shlex
    import subprocess

    argv: list[str] = []
    for token in shlex.split(command_template):
        token = token.replace("{target}", target).replace("{output}", str(output_path))
        argv.append(token)
    completed = subprocess.run(argv, shell=False, timeout=timeout, capture_output=True, text=True)
    return completed.returncode


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
    validate_findings_file(report)
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


def validate_findings_file(report: Report) -> None:
    if not FINDINGS_FILE.exists():
        return
    try:
        data = load_json(FINDINGS_FILE)
    except (OSError, json.JSONDecodeError) as error:
        report.error(f"cannot read data/findings.json: {error} (likely half-written)")
        return
    if not isinstance(data, dict):
        report.error("findings file must be an object")
        return
    if data.get("schemaVersion") != SCHEMA_VERSION:
        report.error(f"findings schemaVersion must be {SCHEMA_VERSION!r}")
    findings = data.get("findings")
    if not isinstance(findings, list):
        report.error("findings.findings must be a list")
        return
    seen: set[tuple[str, str]] = set()
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            report.error(f"findings[{index}] must be an object")
            continue
        fingerprint = str(finding.get("fingerprint", ""))
        cwe = str(finding.get("cwe", ""))
        if not fingerprint:
            report.error(f"findings[{index}] has no fingerprint")
        key = (fingerprint, cwe)
        if key in seen:
            report.error(f"findings[{index}] duplicates fingerprint+cwe {key}; merge was not applied")
        seen.add(key)
        location = finding.get("location")
        if not isinstance(location, dict) or not str(location.get("file", "")).strip():
            report.error(f"findings[{index}].location.file is empty")
        sources = finding.get("sources")
        if not isinstance(sources, list) or not sources:
            report.error(f"findings[{index}].sources must be a non-empty list")


def run_scan(direct: bool) -> int:
    """실행 판정이 'run'인 어댑터만 스킬이 돌리고, 출력을 수집·묶어 findings에 쓴다.

    게이트 READY가 전제. operator/forbidden 어댑터는 실행하지 않고 안내만 한다.
    """
    try:
        scope = load_json(SCOPE_FILE)
    except (OSError, json.JSONDecodeError) as error:
        print(f"ERROR: cannot read data/scope.json: {error}")
        return 1
    if not isinstance(scope, dict):
        print("ERROR: scope is not an object")
        return 1
    ready, blockers = gate_status(scope)
    if not ready:
        print("SCAN: BLOCKED (gate not ready)")
        for blocker in blockers:
            print(f"- {blocker}")
        return 1
    adapters = load_adapters()
    if not adapters:
        print("선언된 어댑터가 없습니다 (adapters/*.json).")
        return 0
    collected: list[dict[str, Any]] = []
    import tempfile as _tempfile
    for name, adapter in adapters:
        if not isinstance(adapter, dict) or "__error__" in adapter:
            print(f"- {name}: 선언 오류, 건너뜀 (validate로 확인)")
            continue
        targets = targets_for_adapter(adapter, scope)
        if not targets:
            accepted = sorted(CATEGORY_TARGET_TYPES.get(str(adapter.get("category")), set())) or ["(없음)"]
            print(f"- {name}: 적용 대상 없음 ({adapter.get('category')} → {accepted} 타입), 건너뜀")
            continue
        decision, reason = execution_decision(adapter, scope, direct)
        if decision == "forbidden":
            print(f"- {name}: forbidden — {reason}")
            continue
        if decision == "operator":
            print(f"- {name}: operator — {reason}")
            for target in targets:
                rendered = str(adapter.get("command", "")).replace("{target}", target).replace("{output}", f"{name}.sarif")
                print(f"    운영자 실행 후 출력을 수집: {rendered}")
            continue
        for target in targets:
            with _tempfile.TemporaryDirectory() as tmp:
                output = Path(tmp) / f"{name}.sarif"
                try:
                    code = execute_adapter(str(adapter.get("command", "")), target, output)
                except Exception as error:  # noqa: BLE001 — 도구 부재·실행 오류를 안내로
                    print(f"- {name} @ {target}: 실행 실패 ({error}); availability로 설치 확인")
                    continue
                if not output.exists():
                    print(f"- {name} @ {target}: 출력 파일 없음 (종료코드 {code})")
                    continue
                try:
                    raw = load_json(output)
                except json.JSONDecodeError:
                    print(f"- {name} @ {target}: 출력이 JSON이 아님")
                    continue
                try:
                    sarif = normalize_to_sarif(str(adapter.get("output_format", "")), raw)
                except ValueError as error:
                    print(f"- {name} @ {target}: {error}")
                    continue
                items = findings_from_sarif(sarif, name)
                collected += items
                print(f"- {name} @ {target}: run — 검출 {len(items)}건")
    merged = merge_findings(collected)
    write_json_atomic(FINDINGS_FILE, {
        "schemaVersion": SCHEMA_VERSION,
        "generatedAt": now_utc().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "findings": merged,
    })
    print(f"SCAN: 수집 {len(collected)}건 → 묶음 후 {len(merged)}건. data/findings.json")
    return 0


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
    parser.add_argument("command", choices=("validate", "authorize", "gate", "adapters", "scan"))
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
    if args.command == "scan":
        return run_scan(args.direct)
    return run_gate()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        sys.exit(0)
