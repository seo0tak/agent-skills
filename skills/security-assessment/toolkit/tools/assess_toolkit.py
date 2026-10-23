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
ADAPTER_CATEGORIES = {"sast", "sca", "secret", "dast", "iac", "cloud"}
# 카테고리가 어떤 대상 타입에 적용되는지. 어댑터는 자기 카테고리에 맞는 대상에만
# 실행된다 (SAST를 web 대상에 돌리지 않는다). iac는 저장소의 IaC 파일을 보므로 repo,
# cloud는 운영 중인 클라우드 계정 설정을 읽기 전용 API로 보므로 infra(ADR 0004).
CATEGORY_TARGET_TYPES = {
    "sast": {"repo"},
    "sca": {"repo"},
    "secret": {"repo"},
    "iac": {"repo"},
    "dast": {"web"},
    "cloud": {"infra"},
}
# 클라우드 대상 표기: <제공자>:<계정>. 제외는 계정 전체(<제공자>:<계정>)나 리전(<제공자>:<계정>:<리전>).
INFRA_TARGET_RE = re.compile(r"^(aws|gcp|azure):[A-Za-z0-9._-]+$")
INFRA_EXCLUSION_RE = re.compile(r"^(aws|gcp|azure):[A-Za-z0-9._-]+(:[A-Za-z0-9-]+)?$")
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


ZAP_LEVELS = {"3": "error", "2": "warning", "1": "note", "0": "note"}


def zap_to_sarif(raw: Any) -> dict[str, Any]:
    """ZAP JSON 보고서(-J)를 SARIF로 변환한다. 순수 함수.

    경고(alert)의 인스턴스 하나가 결과 하나다. 위치는 요청 URL, 메서드·파라미터는
    properties에 두어 URL 지문(메서드·정규화 경로·파라미터 이름)에 쓰인다.
    """
    results: list[dict[str, Any]] = []
    sites = raw.get("site") if isinstance(raw, dict) else None
    for site in sites if isinstance(sites, list) else []:
        for alert in (site or {}).get("alerts") or []:
            alert = alert or {}
            cwe_id = str(alert.get("cweid") or "").strip()
            cwe = [f"CWE-{cwe_id}"] if cwe_id.isdigit() and int(cwe_id) > 0 else []
            for instance in alert.get("instances") or []:
                instance = instance or {}
                results.append({
                    "ruleId": str(alert.get("pluginid") or ""),
                    "level": ZAP_LEVELS.get(str(alert.get("riskcode")), "note"),
                    "message": {"text": str(alert.get("name") or alert.get("alert") or "")},
                    "properties": {
                        "cwe": cwe,
                        "severity": str(alert.get("riskdesc") or ""),
                        "method": str(instance.get("method") or ""),
                        "param": str(instance.get("param") or ""),
                    },
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": str(instance.get("uri") or "")}}}],
                })
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "zap"}}, "results": results}]}


def _prowler_controls(item: dict[str, Any]) -> list[str]:
    """Prowler가 낸 기준 매핑을 'CIS-1.4: 1.4' → 'CIS-1.4 1.4' 형태의 통제 항목 목록으로."""
    compliance = ((item.get("unmapped") or {}).get("compliance")) or {}
    controls: list[str] = []
    if isinstance(compliance, dict):
        for framework, ids in sorted(compliance.items()):
            for control in ids if isinstance(ids, list) else [ids]:
                controls.append(f"{framework} {control}")
    return controls


def prowler_to_sarif(raw: Any) -> dict[str, Any]:
    """Prowler JSON(OCSF) 출력을 SARIF로 변환한다. 순수 함수.

    실패(FAIL)만 결과가 되고, 통과·수동은 기준별 건수(controlSummary)와 이번 실행이 본
    점검 범위(checksRun, regionsSeen)로 run.properties에 남는다(ADR 0004).
    """
    results: list[dict[str, Any]] = []
    control_results: list[dict[str, Any]] = []
    checks: set[str] = set()
    regions: set[str] = set()
    accounts: set[str] = set()
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status_code") or "").upper()
        check = str((item.get("metadata") or {}).get("event_code") or "")
        cloud = item.get("cloud") or {}
        account = str((cloud.get("account") or {}).get("uid") or "")
        resource = (item.get("resources") or [{}])[0] or {}
        region = str(resource.get("region") or cloud.get("region") or "")
        checks.add(check)
        if region:
            regions.add(region)
        if account:
            accounts.add(account)
        controls = _prowler_controls(item)
        outcome = {"PASS": "pass", "FAIL": "fail"}.get(status, "manual")
        cloud_ref = {"account": account, "region": region, "resource": str(resource.get("uid") or "")}
        for control in controls:
            control_results.append({"framework": control.split(" ", 1)[0], "outcome": outcome, **cloud_ref})
        if status != "FAIL":
            continue
        results.append({
            "ruleId": check,
            "level": "error" if str(item.get("severity") or "").lower() in {"critical", "high"} else "warning",
            "message": {"text": str((item.get("finding_info") or {}).get("title") or check)},
            "properties": {
                "severity": str(item.get("severity") or ""),
                "controls": controls,
                "cloud": {"account": account, "region": region, "resource": str(resource.get("uid") or ""), "check": check},
            },
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": str(resource.get("uid") or f"{account}:{region}")}}}],
        })
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "prowler"}}, "results": results,
        "properties": {"controlResults": control_results, "checksRun": sorted(checks),
                       "regionsSeen": sorted(regions), "accountsSeen": sorted(accounts)},
    }]}


NORMALIZERS = {"sarif": _identity_sarif, "osv-json": osv_to_sarif, "zap-json": zap_to_sarif,
               "prowler-ocsf": prowler_to_sarif}
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


def json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2) + "\n"


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
    # 웹 대상의 요청 상한은 소유자가 동의한 조건이라 의미 필드다. 없는 대상은 예전 지문 그대로.
    targets = sorted(
        (str(t.get("type", "")), str(t.get("value", "")))
        + ((str(t["rateLimit"]),) if t.get("rateLimit") is not None else ())
        # 클라우드 대상의 리전·자격증명 참조도 의미 필드다(ADR 0004). 없는 대상은 예전 지문 그대로.
        + ((json.dumps(sorted(str(r) for r in t["regions"]), ensure_ascii=False),) if t.get("regions") is not None else ())
        + ((json.dumps(t["credential"], ensure_ascii=False, sort_keys=True),) if t.get("credential") is not None else ())
        for t in scope.get("targets", []) if isinstance(t, dict)
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
            if target.get("type") == "infra":
                validate_infra_target(report, index, target)
            rate = target.get("rateLimit")
            if rate is not None:
                if target.get("type") != "web":
                    report.error(f"targets[{index}].rateLimit applies to web targets only")
                elif isinstance(rate, bool) or not isinstance(rate, (int, float)) or rate <= 0:
                    report.error(f"targets[{index}].rateLimit must be a positive number (requests per second)")

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


def validate_infra_target(report: Report, index: int, target: dict[str, Any]) -> None:
    """클라우드 대상: <제공자>:<계정>, 리전 목록, 자격증명 참조(이름 + 읽기 전용 확인)."""
    where = f"targets[{index}]"
    if not INFRA_TARGET_RE.match(str(target.get("value", ""))):
        report.error(f"{where}.value must look like aws:<account> (provider:account)")
    regions = target.get("regions")
    if not isinstance(regions, list) or not regions or any(not str(r).strip() for r in regions):
        report.error(f"{where}.regions must be a non-empty list of region names")
    credential = target.get("credential")
    if not isinstance(credential, dict) or not str(credential.get("profile", "")).strip():
        report.error(f"{where}.credential.profile is required (a profile or role name, never a secret)")
    elif credential.get("readOnlyConfirmed") is not True:
        report.error(f"{where}.credential.readOnlyConfirmed must be true after the user confirms the role is read-only")
    elif set(credential) - {"profile", "readOnlyConfirmed", "notes"}:
        report.error(f"{where}.credential may hold only profile, readOnlyConfirmed and notes; do not store secrets")


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
    validate_web_fields(report, where, adapter)


def validate_web_fields(report: Report, where: str, adapter: dict[str, Any]) -> None:
    """웹 어댑터 선언(범위 제어·요청 상한·커버리지·시간 상한)의 형식을 검사한다."""
    control = adapter.get("scope_control")
    if control is not None:
        if not isinstance(control, dict):
            report.error(f"{where}.scope_control must be an object")
        else:
            if "stays_on_target" in control and not isinstance(control["stays_on_target"], bool):
                report.error(f"{where}.scope_control.stays_on_target must be true or false")
            for key, mark in (("exclude_host", "{host}"), ("exclude_url", "{url}")):
                if key in control and mark not in str(control[key]):
                    report.error(f"{where}.scope_control.{key} must contain {mark}")
    if "rate_limit" in adapter and "{rate}" not in str(adapter["rate_limit"]):
        report.error(f"{where}.rate_limit must contain {{rate}}")
    coverage = adapter.get("coverage")
    if coverage is not None:
        mode = coverage.get("mode") if isinstance(coverage, dict) else None
        if mode not in COVERAGE_MODES:
            report.error(f"{where}.coverage.mode must be one of {sorted(COVERAGE_MODES)}")
        elif mode == "url-list" and not str(coverage.get("file", "")).strip():
            report.error(f"{where}.coverage.file is required for url-list")
    spec = adapter.get("cloud_args")
    if spec is not None:
        if not isinstance(spec, dict):
            report.error(f"{where}.cloud_args must be an object")
        else:
            for key, mark in (("profile", "{profile}"), ("regions", "{regions}"), ("exclude_resource", "{resource}")):
                if key in spec and mark not in str(spec[key]):
                    report.error(f"{where}.cloud_args.{key} must contain {mark}")
    if "output_file" in adapter and (not str(adapter["output_file"]).strip() or "/" in str(adapter["output_file"])
                                     or str(adapter["output_file"]) in {".", ".."}):
        report.error(f"{where}.output_file must be a plain file name inside the output directory")
    mapped = adapter.get("checklist_items")
    if mapped is not None and (not isinstance(mapped, list) or any(not str(x).strip() for x in mapped)):
        report.error(f"{where}.checklist_items must be a list of checklist item ids")
    seconds = adapter.get("max_seconds")
    if seconds is not None and (isinstance(seconds, bool) or not isinstance(seconds, int) or seconds <= 0):
        report.error(f"{where}.max_seconds must be a positive integer")


def targets_for_adapter(adapter: dict[str, Any], scope: dict[str, Any]) -> list[str]:
    """어댑터 카테고리에 맞는 대상 값만 돌려준다. 순수 함수."""
    accepted = CATEGORY_TARGET_TYPES.get(str(adapter.get("category")), set())
    return [
        str(t.get("value", ""))
        for t in scope.get("targets", [])
        if isinstance(t, dict) and t.get("value") and str(t.get("type")) in accepted
    ]


# ---- 웹 스캔 (ADR 0003) ----
WEB_CATEGORIES = {"dast"}
COVERAGE_MODES = {"none", "fixed-probes", "url-list"}
# 스코프에 상한이 없을 때의 보수적 기본값(초당 요청).
DEFAULT_WEB_RPS = 5
DEFAULT_MAX_SECONDS = 600


def is_web_adapter(adapter: dict[str, Any]) -> bool:
    return str(adapter.get("category")) in WEB_CATEGORIES


def web_rate_limit(scope: dict[str, Any], target: str) -> float:
    for entry in scope.get("targets", []):
        if isinstance(entry, dict) and str(entry.get("value")) == target and entry.get("rateLimit") is not None:
            return float(entry["rateLimit"])
    return float(DEFAULT_WEB_RPS)


def exclusions_for_target(target: str, exclusions: list[str]) -> dict[str, list[str]]:
    """웹 대상 안에 걸리는 제외 자산. 순수 함수.

    hosts: 대상 호스트의 하위 도메인 제외, urls: 대상 호스트 안의 URL 제외.
    다른 호스트의 제외나 파일 경로 제외는 이 대상과 무관하다.
    """
    from urllib.parse import urlsplit
    host = (urlsplit(target).hostname or "").lower()
    hosts: list[str] = []
    urls: list[str] = []
    for raw in exclusions:
        excl = str(raw).strip()
        if is_url(excl):
            if (urlsplit(excl).hostname or "").lower() == host:
                urls.append(excl)
        elif "/" not in excl and "." in excl:
            excl_host = excl.lower()
            if excl_host.endswith("." + host):
                hosts.append(excl_host)
    return {"hosts": sorted(hosts), "urls": sorted(urls)}


def _render_tokens(template: str, mark: str, value: str) -> list[str]:
    """템플릿을 먼저 토큰으로 나눈 뒤 값을 넣는다(값이 인자를 늘리거나 셸로 해석되지 않게)."""
    import shlex
    return [token.replace(mark, value) for token in shlex.split(template)]


def web_scope_args(adapter: dict[str, Any], relevant: dict[str, list[str]]) -> tuple[list[str] | None, str]:
    """대상 안의 제외 자산을 스캐너 인자로. 넘길 방법이 없으면 (None, 사유)."""
    control = adapter.get("scope_control") or {}
    tokens: list[str] = []
    for kind, key, mark in (("hosts", "exclude_host", "{host}"), ("urls", "exclude_url", "{url}")):
        for value in relevant[kind]:
            template = control.get(key)
            if not template:
                return None, f"대상 안의 제외 자산({value})을 스캐너에 넘길 방법({key})이 선언되지 않음"
            tokens += _render_tokens(str(template), mark, value)
    return tokens, ""


def web_direct_blockers(adapter: dict[str, Any]) -> list[str]:
    """웹 어댑터를 스킬이 직접 실행하지 못하는 사유(제외 자산과 무관한 것)."""
    reasons = []
    if not (adapter.get("scope_control") or {}).get("stays_on_target"):
        reasons.append("대상 밖으로 나가지 않는다는 선언(scope_control.stays_on_target)이 없음")
    if not adapter.get("rate_limit"):
        reasons.append("요청 상한을 스캐너에 넘길 방법(rate_limit)이 없음")
    return reasons


def web_time_limit(adapter: dict[str, Any], scope: dict[str, Any], now: datetime) -> int:
    """실행 시간 상한(초): 어댑터 상한과 점검 기간 끝까지 남은 시간 중 작은 쪽."""
    limit = int(adapter.get("max_seconds") or DEFAULT_MAX_SECONDS)
    end = parse_day(str((scope.get("window") or {}).get("end", "")))
    if end is not None:
        end_of = end.replace(hour=23, minute=59, second=59) if end.hour == end.minute == 0 else end
        limit = min(limit, int((end_of - now).total_seconds()))
    return limit


def web_run_plan(name: str, adapter: dict[str, Any], scope: dict[str, Any], target: str,
                 extra_args: list[str]) -> dict[str, Any]:
    rate = web_rate_limit(scope, target)
    return {
        "adapter": name, "target": target, "ratePerSecond": rate,
        "exclusions": exclusions_for_target(target, [str(x) for x in scope.get("exclusions", [])]),
        "command": str(adapter.get("command", "")), "extraArgs": extra_args,
        "maxSeconds": int(adapter.get("max_seconds") or DEFAULT_MAX_SECONDS),
        "windowEnd": str((scope.get("window") or {}).get("end", "")),
    }


# ---- 클라우드 설정 점검 (ADR 0004) ----
def is_cloud_adapter(adapter: dict[str, Any]) -> bool:
    return str(adapter.get("category")) == "cloud"


def infra_target(scope: dict[str, Any], value: str) -> dict[str, Any]:
    for entry in scope.get("targets", []):
        if isinstance(entry, dict) and entry.get("type") == "infra" and str(entry.get("value")) == value:
            return entry
    return {}


def cloud_allowed_regions(scope: dict[str, Any], target: str) -> list[str] | None:
    """대상에 선언한 리전에서 제외 리전을 뺀 목록. 계정 전체가 제외면 None."""
    account = target.split(":", 1)[1] if ":" in target else ""
    provider = target.split(":", 1)[0]
    exclusions = [str(x).strip() for x in scope.get("exclusions", [])]
    if f"{provider}:{account}" in exclusions:
        return None
    excluded = {x.split(":")[2] for x in exclusions if INFRA_EXCLUSION_RE.match(x) and x.count(":") == 2
                and x.split(":")[1] == account}
    return [str(r) for r in infra_target(scope, target).get("regions") or [] if str(r) not in excluded]


def cloud_args(adapter: dict[str, Any], scope: dict[str, Any], target: str,
               regions: list[str]) -> tuple[list[str] | None, str]:
    """자격증명 참조 이름과 허용 리전을 스캐너 인자로. 넘길 방법이 없으면 (None, 사유)."""
    spec = adapter.get("cloud_args") or {}
    if not spec.get("regions"):
        return None, "점검할 리전을 스캐너에 넘길 방법(cloud_args.regions)이 없어 범위 밖 리전을 읽을 수 있음"
    tokens: list[str] = []
    profile = str((infra_target(scope, target).get("credential") or {}).get("profile") or "")
    if spec.get("profile"):
        tokens += _render_tokens(str(spec["profile"]), "{profile}", profile)
    import shlex
    for token in shlex.split(str(spec["regions"])):
        tokens += regions if token == "{regions}" else [token.replace("{regions}", ",".join(regions))]
    resources = [str(x) for x in scope.get("exclusions", []) if str(x).startswith("arn:")]
    if resources and spec.get("exclude_resource"):
        for resource in resources:
            tokens += _render_tokens(str(spec["exclude_resource"]), "{resource}", resource)
    return tokens, ""


def cloud_direct_blockers(adapter: dict[str, Any]) -> list[str]:
    if not (adapter.get("cloud_args") or {}).get("profile"):
        return ["자격증명 참조(프로파일)를 스캐너에 넘길 방법(cloud_args.profile)이 없음"]
    return []


def sarif_run_properties(sarif: Any) -> dict[str, Any]:
    """정규화된 SARIF의 run.properties를 합친다(통제 항목 건수·점검 범위)."""
    merged: dict[str, Any] = {"controlResults": [], "checksRun": [], "regionsSeen": [], "accountsSeen": []}
    for run in (sarif.get("runs") if isinstance(sarif, dict) else None) or []:
        props = (run or {}).get("properties") or {}
        merged["controlResults"] += [r for r in props.get("controlResults") or [] if isinstance(r, dict)]
        for key in ("checksRun", "regionsSeen", "accountsSeen"):
            merged[key] = sorted(set(merged[key]) | {str(x) for x in props.get(key) or []})
    return merged


def summarize_controls(results: list[dict[str, Any]], exclusions: list[str]) -> dict[str, dict[str, int]]:
    """통제 항목 결과를 기준별 통과·실패·수동 건수로. 제외 자산의 결과는 세지 않는다(검출과 같은 기준)."""
    summary: dict[str, dict[str, int]] = {}
    for result in results:
        if cloud_excluded(result, exclusions):
            continue
        bucket = summary.setdefault(str(result.get("framework")), {"pass": 0, "fail": 0, "manual": 0})
        outcome = str(result.get("outcome"))
        bucket[outcome if outcome in bucket else "manual"] += 1
    return dict(sorted(summary.items()))


def cloud_scope_violation(props: dict[str, Any], target: str, regions: list[str]) -> str:
    """출력이 대상 계정·허용 리전 밖을 읽었는지. 읽었으면 사유, 아니면 빈 문자열."""
    account = target.split(":", 1)[1] if ":" in target else ""
    others = [a for a in props.get("accountsSeen") or [] if a != account]
    if others:
        return f"대상 계정이 아닌 계정({', '.join(others)})의 결과가 있음"
    outside = [r for r in props.get("regionsSeen") or [] if r not in set(regions) | {"global"}]
    if outside:
        return f"허용하지 않은 리전({', '.join(outside)})의 결과가 있음"
    return ""


def plan_code(plans: list[dict[str, Any]]) -> str:
    """웹 실행 계획의 확인 코드. 계획이 한 글자라도 바뀌면 코드가 바뀐다."""
    encoded = json.dumps(plans, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:12]


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
DISPOSITIONS_FILE = DATA_DIR / "dispositions.json"
DISPOSITION_VALUES = {"unreviewed", "confirmed", "suspected", "false-positive", "out-of-scope", "needs-review"}
STAGE_VALUES = {"unreviewed", "in-review", "reviewed"}
# 근거가 필수인 판정. 결함이라 단정하거나 범위 밖·오탐으로 치우는 결론은 설명이 있어야 한다.
REASON_REQUIRED = {"confirmed", "false-positive", "out-of-scope"}
# 판정 주체. user=사용자가 확인, ai=AI가 근거로 판정(사용자 미확인).
DECIDED_BY_VALUES = {"user", "ai"}
# 위험을 닫는 판정. 확정(reviewed)은 사용자만 한다. AI는 in-review로 제안까지.
USER_ONLY_CLOSING = {"false-positive", "out-of-scope"}
CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)


# CWE 대신 통제 항목·점검 ID로 묶는 카테고리(ADR 0004). 다른 카테고리의 키는 예전 그대로다.
GROUPED_BY_CONTROL = {"iac", "cloud"}


def finding_key(finding: dict[str, Any]) -> str:
    """판정 레코드·묶음의 키: '지문:CWE', CWE가 없는 인프라 검출은 '지문:통제 항목'."""
    return f"{finding.get('fingerprint', '')}:{finding.get('cwe') or finding.get('group') or ''}"


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


_ID_SEGMENT = re.compile(r"^(\d+|[0-9a-fA-F]{16,}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[A-Za-z0-9_-]{24,})$")


def normalize_web_path(url: str) -> str:
    """URL을 '호스트/경로'로 정규화한다. 숫자·식별자 세그먼트는 자리표시자, 쿼리·조각은 뺀다."""
    from urllib.parse import urlsplit
    parts = urlsplit(url)
    segments = []
    for segment in parts.path.split("/"):
        if not segment:
            continue
        segments.append("{n}" if segment.isdigit() else "{id}" if _ID_SEGMENT.match(segment) else segment)
    return "/".join([(parts.hostname or "").lower(), *segments])


def web_params(url: str, extra: str = "") -> list[str]:
    from urllib.parse import parse_qsl, urlsplit
    names = {name for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)}
    if extra.strip():
        names.add(extra.strip())
    return sorted(names)


def fingerprint_for_url(method: str, url: str, params: list[str]) -> str:
    """웹 검출 지문: 메서드·정규화 경로·파라미터 이름. 쿼리 값·토큰·증거 문자열은 넣지 않는다(ADR 0003)."""
    material = f"web|{(method or 'ANY').upper()}|{normalize_web_path(url)}|{','.join(params)}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]

def findings_from_sarif(sarif: Any, fallback_scanner: str, category: str | None = None) -> list[dict[str, Any]]:
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
            location: dict[str, Any] = {"file": file, "line": line, "function": function}
            props = result.get("properties") or {}
            cloud = props.get("cloud") if isinstance(props.get("cloud"), dict) else None
            if cloud:
                # 클라우드 검출: 지문은 리소스(없으면 계정·리전), 위치에 계정·리전·점검 항목(ADR 0004).
                location["cloud"] = {k: str(cloud.get(k) or "") for k in ("account", "region", "resource", "check")}
                fingerprint = fingerprint_for(location["cloud"]["resource"] or file, None, location["cloud"]["check"])
            elif is_url(file):
                # 웹 검출: 쿼리 값·증거가 아니라 메서드·정규화 경로·파라미터 이름으로 묶는다.
                props = result.get("properties") or {}
                method = str(props.get("method") or "").upper()
                params = web_params(file, str(props.get("param") or ""))
                location["web"] = {"method": method, "path": normalize_web_path(file), "params": params}
                fingerprint = fingerprint_for_url(method, file, params)
            else:
                fingerprint = fingerprint_for(file, function, snippet)
            cwe = cwe_from_result(result, rule)
            entry: dict[str, Any] = {"fingerprint": fingerprint, "cwe": cwe}
            if category in GROUPED_BY_CONTROL and not cwe:
                # 인프라·컴플라이언스: CWE 대신 스캐너가 낸 통제 항목, 없으면 스캐너 점검 ID로 묶는다.
                controls = [str(c) for c in props.get("controls") or []]
                entry["group"] = controls[0] if controls else f"check:{rule_id}"
                if controls:
                    entry["controls"] = controls
            out.append({
                **entry,
                "location": location,
                "message": str((result.get("message") or {}).get("text") or ""),
                # properties.severity(예: OSV의 CVSS 점수)를 우선, 없으면 SARIF level.
                "severity": str((result.get("properties") or {}).get("severity") or result.get("level") or ""),
                "sources": [{"scanner": scanner, "ruleId": rule_id, "line": line}],
            })
    return out


def merge_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """묶음 키(지문 + CWE 또는 통제 항목)가 같은 검출을 하나로 묶고 출처를 합친다. 순수 함수."""
    bucket: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for finding in findings:
        key = finding_key(finding)
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


def render_command(command_template: str, target: str, output_path: Path,
                   extra_args: list[str] | tuple[str, ...] = ()) -> list[str]:
    """명령 템플릿을 argv로. 자리표시자는 토큰으로 나눈 뒤 치환한다(주입 방지).

    {output}은 출력 파일 전체 경로, {output_dir}·{output_name}은 컨테이너 마운트용으로
    디렉터리와 파일 이름을 따로 준다. extra_args(범위 제어·요청 상한)는 끝에 붙는다.
    """
    import shlex

    argv: list[str] = []
    for token in shlex.split(command_template):
        token = (token.replace("{target}", target).replace("{output_dir}", str(output_path.parent))
                 .replace("{output_name}", output_path.name).replace("{output}", str(output_path)))
        argv.append(token)
    return argv + list(extra_args)


def execute_adapter(command_template: str, target: str, output_path: Path, timeout: int = 600,
                    extra_args: list[str] | tuple[str, ...] = ()) -> int:
    """어댑터 명령을 shell 없이 실행한다.

    테스트는 실제 스캐너 대신 이 함수를 교체해 픽스처를 쓴다(도구 미실행).
    """
    import subprocess

    argv = render_command(command_template, target, output_path, extra_args)
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
    validate_dispositions_file(report)
    validate_runtime_files(report)
    validate_checklist(report)
    validate_evidence(report)
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
    seen: set[str] = set()
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            report.error(f"findings[{index}] must be an object")
            continue
        fingerprint = str(finding.get("fingerprint", ""))
        if not fingerprint:
            report.error(f"findings[{index}] has no fingerprint")
        key = finding_key(finding)
        if key in seen:
            report.error(f"findings[{index}] duplicates key {key}; merge was not applied")
        seen.add(key)
        location = finding.get("location")
        if not isinstance(location, dict) or not str(location.get("file", "")).strip():
            report.error(f"findings[{index}].location.file is empty")
        sources = finding.get("sources")
        if not isinstance(sources, list) or not sources:
            report.error(f"findings[{index}].sources must be a non-empty list")
    exclusions = _scope_exclusions()
    for index, finding in enumerate(f for f in findings if isinstance(f, dict)):
        location_file = str((finding.get("location") or {}).get("file") or "")
        if exclusions and finding_excluded(finding, exclusions):
            report.error(f"findings[{index}] is in an excluded asset ({location_file}); run scan to rebuild")


def _scope_exclusions() -> list[str]:
    try:
        scope = load_json(SCOPE_FILE)
    except (OSError, json.JSONDecodeError):
        return []
    return [str(x) for x in scope.get("exclusions", [])] if isinstance(scope, dict) else []


HANDOFF_SARIF = DATA_DIR / "handoff.sarif"
EVIDENCE_DIR = ROOT / "evidence"
EVIDENCE_CSV = EVIDENCE_DIR / "findings.csv"
COVER_MD = EVIDENCE_DIR / "cover.md"
GENERATED_MARKER = "<!-- generated by assess_toolkit.py evidence"
EVIDENCE_COLUMNS = (
    "fingerprint", "cwe", "file", "line", "function", "severity",
    "disposition", "stage", "reason", "decidedBy", "handedOff", "scanners",
)


def write_text_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _sorted_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def key(f: dict[str, Any]) -> tuple[str, int, str, str]:
        loc = f.get("location") or {}
        line = loc.get("line")
        return (str(loc.get("file") or ""), line if isinstance(line, int) else 0,
                str(f.get("cwe") or ""), str(f.get("fingerprint") or ""))
    return sorted((f for f in findings if isinstance(f, dict)), key=key)


def render_evidence_csv(findings: list[dict[str, Any]], records: dict[str, Any]) -> str:
    """증적 워크북(CSV). 검출 하나가 한 행. 순수 함수 — 같은 입력이면 같은 출력."""
    import csv
    import io as _io

    buffer = _io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(EVIDENCE_COLUMNS)
    for finding in _sorted_findings(findings):
        record = records.get(finding_key(finding)) or {}
        loc = finding.get("location") or {}
        scanners = sorted({str(s.get("scanner")) for s in finding.get("sources") or [] if isinstance(s, dict)})
        writer.writerow([
            finding.get("fingerprint", ""),
            finding.get("cwe", ""),
            loc.get("file") or "",
            "" if loc.get("line") is None else loc.get("line"),
            loc.get("function") or "",
            finding.get("severity", ""),
            record.get("disposition") or "unreviewed",
            record.get("stage") or "unreviewed",
            " ".join(str(record.get("reason") or "").split()),
            record.get("decidedBy") or "",
            "true" if record.get("handedOff") else "false",
            ";".join(scanners),
        ])
    return buffer.getvalue()


def _count_lines(counts: dict[str, int]) -> list[str]:
    return [f"| {k} | {counts[k]} |" for k in sorted(counts)] or ["| (없음) | 0 |"]


def load_control_summary() -> dict[str, dict[str, int]]:
    """이번 차수 어댑터별 결과에 남은 기준별 통과·실패·수동 건수를 합친다."""
    total: dict[str, dict[str, int]] = {}
    try:
        results = load_scan_results()
    except ValueError:
        return total
    for data in results.values():
        for summary in (data.get("controls") or {}).values():
            for framework, counts in (summary or {}).items():
                bucket = total.setdefault(framework, {"pass": 0, "fail": 0, "manual": 0})
                for key in bucket:
                    bucket[key] += int((counts or {}).get(key) or 0)
    return dict(sorted(total.items()))


def render_cover_md(scope: dict[str, Any], findings: list[dict[str, Any]],
                    records: dict[str, Any], generated_at: str | None,
                    controls: dict[str, dict[str, int]] | None = None,
                    checklist: dict[str, Any] | None = None) -> str:
    """표지 보고서(Markdown). 범위·인가·방법·집계. 숫자는 증적 워크북과 같은 데이터에서
    집계하므로 구조적으로 일치한다. 현재 시각을 넣지 않는다(드리프트 방지)."""
    summary = disposition_summary(findings, records)
    scanners = sorted({str(s.get("scanner")) for f in findings if isinstance(f, dict)
                       for s in f.get("sources") or [] if isinstance(s, dict)})
    window = scope.get("window") or {}
    consent = scope.get("consent") or {}
    lines = [
        "---",
        "type: security-assessment/cover-report",
        "title: 보안 점검 표지 보고서",
        f"timestamp: {generated_at or ''}",
        "---",
        "",
        GENERATED_MARKER + " from data/. 직접 편집하지 말고 데이터를 고친 뒤 evidence를 다시 실행한다. -->",
        "",
        "# 보안 점검 표지 보고서",
        "",
        f"검출 수집 시각: {generated_at or '(미수집)'}",
        "",
        "## 1. 범위",
        "",
        "| 타입 | 대상 |",
        "|---|---|",
    ]
    targets = [t for t in scope.get("targets", []) if isinstance(t, dict)]
    lines += [f"| {t.get('type', '')} | {t.get('value', '')} |" for t in targets] or ["| (없음) | |"]
    lines += [
        "",
        f"- 제외 자산: {', '.join(str(x) for x in scope.get('exclusions', [])) or '(없음)'}",
        f"- 기간: {window.get('start', '')} ~ {window.get('end', '')}",
        f"- 침습도 상한: {scope.get('intrusiveness', '')}",
        "",
        "## 2. 인가",
        "",
        f"- 스코프 상태: {scope.get('status', '')}",
        f"- 인가자: {consent.get('authorizer', '')} ({consent.get('role', '')})",
        f"- 인가 일자: {consent.get('date', '')}",
        f"- 참조: {consent.get('reference', '')}",
        "",
        "> 이 도구는 인가 주장을 기록할 뿐 동의의 진위를 검증하지 않는다.",
        "",
        "## 3. 방법",
        "",
        f"- 사용한 스캐너: {', '.join(scanners) or '(없음)'}",
        "- 검출은 지문+CWE가 같으면 하나로 묶었다. 판정과 확인 단계는 별개 축이다.",
        "",
        "## 4. 결과 집계",
        "",
        f"전체 검출 {summary['total']}건 · sast-remediation으로 넘김 {summary['handedOff']}건",
        "",
        "| 판정 | 건수 |",
        "|---|---|",
        *_count_lines(summary["byDisposition"]),
        "",
        "| 확인 단계 | 건수 |",
        "|---|---|",
        *_count_lines(summary["byStage"]),
        "",
        "| 확정한 주체 (reviewed) | 건수 |",
        "|---|---|",
        *_count_lines(summary["reviewedBy"]),
        "",
        "오탐(false-positive)·범위 밖(out-of-scope) 확정은 사용자만 한다(user). ai는 AI가 근거로 판정한 것이다.",
        "",
        "항목별 근거는 같은 디렉터리의 `findings.csv`(증적 워크북)에 있다.",
        "",
    ]
    if controls:
        lines += [
            "## 5. 기준 대조",
            "",
            "스캐너가 낸 통제 항목 결과의 건수다. 통과 항목은 검출로 만들지 않는다.",
            "",
            "| 기준 | 통과 | 실패 | 수동 |",
            "|---|---|---|---|",
            *[f"| {name} | {c['pass']} | {c['fail']} | {c['manual']} |" for name, c in controls.items()],
            "",
        ]
    if checklist:
        counts = checklist["counts"]
        lines += [
            f"## {6 if controls else 5}. 방법론 체크리스트",
            "",
            f"기준: {checklist['title']} ({checklist['version']}). 고른 항목 {checklist['selected']}개. 시험 방법은 표준 문서를",
            "따랐고, 이 표는 무엇을 점검했는지와 결과의 기록이다. 항목별 근거는 `checklist.csv`에 있다.",
            "",
            "| 상태 | 항목 수 |",
            "|---|---|",
            *[f"| {CHECKLIST_LABEL[key]} | {counts.get(key, 0)} |" for key in CHECKLIST_ORDER],
            "",
        ]
    return "\n".join(lines)


def _evidence_inputs() -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any], str | None]:
    scope = load_json(SCOPE_FILE) if SCOPE_FILE.exists() else {}
    findings_data = load_json(FINDINGS_FILE) if FINDINGS_FILE.exists() else {"findings": []}
    findings = findings_data.get("findings", []) if isinstance(findings_data, dict) else []
    raw_generated = findings_data.get("generatedAt") if isinstance(findings_data, dict) else None
    generated_at = str(raw_generated) if raw_generated else None
    disp = load_json(DISPOSITIONS_FILE) if DISPOSITIONS_FILE.exists() else {"dispositions": {}}
    records = disp.get("dispositions", {}) if isinstance(disp, dict) else {}
    return (scope if isinstance(scope, dict) else {}), findings, records, generated_at


def run_evidence() -> int:
    """증적 워크북(findings.csv)과 표지 보고서(cover.md)를 데이터에서 생성한다."""
    try:
        scope, findings, records, generated_at = _evidence_inputs()
    except (OSError, json.JSONDecodeError) as error:
        print(f"ERROR: cannot read data: {error}")
        return 1
    write_text_atomic(EVIDENCE_CSV, render_evidence_csv(findings, records))
    rows = checklist_rows_or_none()
    write_text_atomic(COVER_MD, render_cover_md(scope, findings, records, generated_at, load_control_summary(),
                                                checklist_summary(rows)))
    if rows is not None:
        write_text_atomic(CHECKLIST_CSV, render_checklist_csv(rows["rows"]))
    summary = disposition_summary(findings, records)
    print(f"증적 생성: 검출 {summary['total']}건 → evidence/findings.csv, evidence/cover.md")
    return 0


def validate_evidence(report: Report) -> None:
    """생성된 증적이 현재 데이터와 어긋나면 에러(표지 숫자↔워크북 불일치 방지)."""
    if not EVIDENCE_CSV.exists() and not COVER_MD.exists():
        return
    try:
        scope, findings, records, generated_at = _evidence_inputs()
    except (OSError, json.JSONDecodeError):
        return  # 데이터 파일 오류는 각자 검사가 지적한다
    if EVIDENCE_CSV.exists():
        if EVIDENCE_CSV.read_text(encoding="utf-8") != render_evidence_csv(findings, records):
            report.error("evidence/findings.csv is out of date with findings/dispositions; run evidence")
    else:
        report.error("evidence/cover.md exists but findings.csv is missing; run evidence")
    if COVER_MD.exists():
        text = COVER_MD.read_text(encoding="utf-8")
        if GENERATED_MARKER not in text:
            report.warn("evidence/cover.md is hand-written; numbers cannot be checked against findings.csv")
        elif text != render_cover_md(scope, findings, records, generated_at, load_control_summary(),
                                     checklist_summary(checklist_rows_or_none())):
            report.error("evidence/cover.md is out of date with data; run evidence")
    else:
        report.error("evidence/findings.csv exists but cover.md is missing; run evidence")
    rows = checklist_rows_or_none()
    if rows is not None and (EVIDENCE_CSV.exists() or CHECKLIST_CSV.exists()):
        if not CHECKLIST_CSV.exists():
            report.error("evidence/checklist.csv is missing; run evidence")
        elif CHECKLIST_CSV.read_text(encoding="utf-8") != render_checklist_csv(rows["rows"]):
            report.error("evidence/checklist.csv is out of date with data/checklist.json; run evidence")


# ---- 방법론 체크리스트 (ADR 0005) ----
# 기준의 항목마다 무엇을 점검했고 결과가 어땠는지, 근거가 어디 있는지를 남기는 장부다.
# 시험 방법은 표준 문서를 따르고, 툴킷은 실행 단계를 담지 않는다.
CHECKLIST_DIR = ROOT / "checklists"
CHECKLIST_FILE = DATA_DIR / "checklist.json"
CHECKLIST_CSV = EVIDENCE_DIR / "checklist.csv"
CHECKLIST_STATUS = {"not-checked", "checked", "issue-found", "not-applicable"}
CHECKLIST_ORDER = ["out-of-scope", "not-checked", "checked", "issue-found", "not-applicable"]
CHECKLIST_LABEL = {"out-of-scope": "범위 밖", "not-checked": "미점검", "checked": "점검함",
                   "issue-found": "결함 발견", "not-applicable": "해당 없음"}
# 확정하는 상태: 사용자가 근거와 함께 기록한다.
CHECKLIST_CONFIRMED = {"checked", "issue-found", "not-applicable"}
CHECKLIST_COLUMNS = ("item", "title", "status", "decidedBy", "reason", "evidence", "suggestedBy", "link")


def load_standard(name: str) -> dict[str, Any]:
    data = load_json(CHECKLIST_DIR / f"{name}.json")
    if not isinstance(data, dict):
        raise ValueError(f"checklists/{name}.json must be an object")
    return data


def validate_standard(report: Report, name: str, data: Any) -> None:
    where = f"checklists/{name}.json"
    if not isinstance(data, dict):
        report.error(f"{where} must be an object")
        return
    for field in ("id", "title", "version", "source"):
        if not str(data.get(field, "")).strip():
            report.error(f"{where}.{field} is empty")
    items = data.get("items")
    if not isinstance(items, list) or not items:
        report.error(f"{where}.items must be a non-empty list")
        return
    seen: set[str] = set()
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            report.error(f"{where}.items[{index}] must be an object")
            continue
        item_id = str(item.get("id", ""))
        if not item_id or item_id in seen:
            report.error(f"{where}.items[{index}].id is empty or duplicated")
        seen.add(item_id)
        if not str(item.get("title", "")).strip():
            report.error(f"{where}.items[{index}].title is empty")
        if item.get("intrusiveness") not in INTRUSIVENESS:
            report.error(f"{where}.items[{index}].intrusiveness must be one of {sorted(INTRUSIVENESS)}")
        types = item.get("targetTypes")
        if not isinstance(types, list) or not types or any(t not in TARGET_TYPES for t in types):
            report.error(f"{where}.items[{index}].targetTypes must list {sorted(TARGET_TYPES)}")
        for forbidden in ("steps", "procedure", "payload", "payloads"):
            if forbidden in item:
                report.error(f"{where}.items[{index}] has '{forbidden}'; the checklist records results only "
                             "and links to the standard for how to test")


def item_out_of_scope(item: dict[str, Any], scope: dict[str, Any]) -> str:
    """항목이 이번 스코프 밖이면 사유, 아니면 빈 문자열. 순수 함수."""
    need = INTRUSIVENESS_RANK.get(str(item.get("intrusiveness")), 99)
    cap = INTRUSIVENESS_RANK.get(str(scope.get("intrusiveness")), -1)
    if need > cap:
        return f"필요 침습도({item.get('intrusiveness')})가 스코프 상한({scope.get('intrusiveness')})을 넘음"
    types = {str(t.get("type")) for t in scope.get("targets", []) if isinstance(t, dict)}
    if not types & set(item.get("targetTypes") or []):
        return f"스코프에 맞는 대상({', '.join(item.get('targetTypes') or [])})이 없음"
    return ""


def checklist_rows(standard: dict[str, Any], records: dict[str, Any], scope: dict[str, Any],
                   adapters: list[tuple[str, Any]], scan_results: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """고른 항목마다 상태·근거·스캔 제안을 계산한다. 순수 함수.

    스캔 제안: 어댑터가 checklist_items로 그 항목을 가리키고 이번 차수에 실행 결과가 있으면
    "스캔으로 점검됨"을 제안할 뿐, 점검함으로 확정하지 않는다.
    """
    items = {str(i.get("id")): i for i in standard.get("items") or [] if isinstance(i, dict)}
    rows: list[dict[str, Any]] = []
    for item_id, record in records.items():
        item = items.get(item_id) or {}
        record = record if isinstance(record, dict) else {}
        reason_out = item_out_of_scope(item, scope) if item else "기준 파일에 없는 항목"
        suggested = sorted(
            name for name, adapter in adapters
            if isinstance(adapter, dict) and item_id in (adapter.get("checklist_items") or [])
            and name in scan_results and (scan_results[name].get("targets") or [])
        )
        rows.append({
            "item": item_id, "title": str(item.get("title") or ""), "link": str(item.get("link") or ""),
            "status": "out-of-scope" if reason_out else str(record.get("status") or "not-checked"),
            "outOfScope": reason_out, "decidedBy": str(record.get("decidedBy") or ""),
            "reason": " ".join(str(record.get("reason") or "").split()),
            "evidence": [str(e) for e in record.get("evidence") or []], "suggestedBy": suggested,
        })
    return rows


def checklist_rows_or_none() -> dict[str, Any] | None:
    """data/checklist.json이 있으면 기준·행을, 없으면 None(체크리스트를 쓰지 않는 점검)."""
    if not CHECKLIST_FILE.exists():
        return None
    try:
        data = load_json(CHECKLIST_FILE)
        standard = load_standard(str(data.get("standard")))
        scope = load_json(SCOPE_FILE) if SCOPE_FILE.exists() else {}
        results = load_scan_results()
    except (OSError, ValueError, json.JSONDecodeError, AttributeError):
        return None
    rows = checklist_rows(standard, data.get("items") or {}, scope if isinstance(scope, dict) else {},
                         load_adapters(), results)
    return {"standard": standard, "rows": rows}


def checklist_summary(view: dict[str, Any] | None) -> dict[str, Any] | None:
    if view is None:
        return None
    counts: dict[str, int] = {}
    for row in view["rows"]:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    standard = view["standard"]
    return {"title": standard.get("title"), "version": standard.get("version"),
            "selected": len(view["rows"]), "counts": counts}


def render_checklist_csv(rows: list[dict[str, Any]]) -> str:
    import csv
    import io as _io
    buffer = _io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(CHECKLIST_COLUMNS)
    for row in sorted(rows, key=lambda r: r["item"]):
        writer.writerow([row["item"], row["title"], row["status"], row["decidedBy"],
                         row["reason"] or row["outOfScope"], ";".join(row["evidence"]),
                         ";".join(row["suggestedBy"]), row["link"]])
    return buffer.getvalue()


def validate_checklist(report: Report) -> None:
    if CHECKLIST_DIR.is_dir():
        for path in sorted(CHECKLIST_DIR.glob("*.json")):
            try:
                validate_standard(report, path.stem, load_json(path))
            except (OSError, json.JSONDecodeError) as error:
                report.error(f"cannot read checklists/{path.name}: {error}")
    if not CHECKLIST_FILE.exists():
        return
    try:
        data = load_json(CHECKLIST_FILE)
    except (OSError, json.JSONDecodeError) as error:
        report.error(f"cannot read data/checklist.json: {error} (likely half-written)")
        return
    if not isinstance(data, dict) or not isinstance(data.get("items"), dict):
        report.error("data/checklist.json must be an object with an items object")
        return
    name = str(data.get("standard") or "")
    if not (CHECKLIST_DIR / f"{name}.json").exists():
        report.error(f"data/checklist.json names standard '{name}' but checklists/{name}.json does not exist")
        return
    try:
        standard = load_standard(name)
    except (OSError, ValueError, json.JSONDecodeError):
        return
    scope = load_json(SCOPE_FILE) if SCOPE_FILE.exists() else {}
    known = {str(i.get("id")): i for i in standard.get("items") or [] if isinstance(i, dict)}
    for item_id, record in data["items"].items():
        where = f"checklist item {item_id}"
        if item_id not in known:
            report.error(f"{where} is not in checklists/{name}.json")
            continue
        if not isinstance(record, dict):
            report.error(f"{where} must be an object")
            continue
        status = record.get("status", "not-checked")
        if status not in CHECKLIST_STATUS:
            report.error(f"{where}.status must be one of {sorted(CHECKLIST_STATUS)}")
            continue
        outside = item_out_of_scope(known[item_id], scope if isinstance(scope, dict) else {})
        if outside and status != "not-checked":
            report.error(f"{where} is out of scope ({outside}) but has a result '{status}'")
        if status in CHECKLIST_CONFIRMED:
            if record.get("decidedBy") != "user":
                report.error(f"{where} is '{status}'; only the user confirms checklist results (decidedBy user)")
            if not str(record.get("reason", "")).strip():
                report.error(f"{where} is '{status}' but has no reason")
        if status == "issue-found" and not record.get("evidence"):
            report.error(f"{where} is 'issue-found' but names no evidence (finding key or note path)")


def run_checklist() -> int:
    """고른 항목의 상태·스캔 제안·건수를 JSON으로 보여 준다. 어떤 시험도 실행하지 않는다."""
    view = checklist_rows_or_none()
    if view is None:
        print("data/checklist.json이 없거나 기준 파일을 읽을 수 없습니다. examples/checklist.json 형식으로 만드세요.")
        return 1
    summary = checklist_summary(view) or {}
    print(json_text({**summary, "items": view["rows"]}), end="")
    return 0


def is_code_level(finding: dict[str, Any]) -> bool:
    """코드 레벨 검출인지. sast-remediation에 넘길 수 있는 소스 위치가 있어야 한다.

    웹(DAST) 검출의 위치는 URL이라 코드 결함이 아니다 — 넘기지 않는다.
    """
    location = finding.get("location") or {}
    if location.get("cloud"):
        return False  # 클라우드 설정 결함은 고칠 파일이 없다 — 증적에만 남긴다(ADR 0004)
    file = str(location.get("file") or "")
    return bool(file) and not file.startswith(("http://", "https://"))


def build_handoff_sarif(findings: list[dict[str, Any]], records: dict[str, Any]) -> dict[str, Any]:
    """confirmed 코드 결함을 sast-remediation이 읽을 SARIF로 만든다. 순수 함수.

    판정 근거를 메시지에 담고, cwe·지문·출처를 properties에 보존한다.
    """
    results: list[dict[str, Any]] = []
    for finding in findings:
        record = records.get(finding_key(finding)) or {}
        if record.get("disposition") != "confirmed" or not is_code_level(finding):
            continue
        location = finding.get("location") or {}
        reason = str(record.get("reason") or "")
        cwe = str(finding.get("cwe") or "")
        rule_id = cwe or (finding.get("sources") or [{}])[0].get("ruleId") or ""
        region: dict[str, Any] = {}
        if location.get("line") is not None:
            region["startLine"] = location.get("line")
        physical: dict[str, Any] = {"artifactLocation": {"uri": str(location.get("file") or "")}}
        if region:
            physical["region"] = region
        results.append({
            "ruleId": str(rule_id),
            "level": "error",
            "message": {"text": (str(finding.get("message") or "") + (f" — confirmed: {reason}" if reason else "")).strip()},
            "properties": {
                "cwe": cwe,
                "fingerprint": finding.get("fingerprint"),
                "sources": finding.get("sources"),
                "security-assessment-disposition": "confirmed",
            },
            "locations": [{"physicalLocation": physical}],
        })
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{"tool": {"driver": {"name": "security-assessment", "informationUri": "https://github.com/seo0tak/agent-skills"}}, "results": results}],
    }


def run_bridge(dry_run: bool, include_all: bool) -> int:
    """confirmed 코드 결함을 SARIF로 내보내고 handedOff로 표시한다.

    기본은 아직 넘기지 않은(handedOff != true) 것만. --all은 전부 다시 내보낸다.
    --dry-run은 건수만 보고하고 파일·판정을 쓰지 않는다.
    """
    findings_data = load_json(FINDINGS_FILE) if FINDINGS_FILE.exists() else {"findings": []}
    findings = findings_data.get("findings", []) if isinstance(findings_data, dict) else []
    if not DISPOSITIONS_FILE.exists():
        print("data/dispositions.json이 없습니다. 먼저 판정을 기록하세요.")
        return 1
    disp_data = load_json(DISPOSITIONS_FILE)
    records = disp_data.get("dispositions", {}) if isinstance(disp_data, dict) else {}

    selectable = []
    for finding in findings:
        key = finding_key(finding)
        record = records.get(key) or {}
        if record.get("disposition") != "confirmed" or not is_code_level(finding):
            continue
        if not include_all and record.get("handedOff"):
            continue
        selectable.append((key, finding))

    if not selectable:
        print("넘길 confirmed 코드 결함이 없습니다 (이미 넘겼거나 해당 없음).")
        return 0

    sarif = build_handoff_sarif([f for _, f in selectable], records)
    if dry_run:
        print(f"[dry-run] 넘길 결함 {len(selectable)}건. 파일·판정을 쓰지 않았습니다.")
        return 0
    write_json_atomic(HANDOFF_SARIF, sarif)
    now = now_utc().strftime("%Y-%m-%dT%H:%M:%SZ")
    for key, _ in selectable:
        records[key]["handedOff"] = True
        records[key]["updatedAt"] = now
    disp_data["dispositions"] = records
    disp_data["updatedAt"] = now
    write_json_atomic(DISPOSITIONS_FILE, disp_data)
    try:
        shown = HANDOFF_SARIF.relative_to(ROOT)
    except ValueError:
        shown = HANDOFF_SARIF
    print(f"넘김: confirmed 코드 결함 {len(selectable)}건 → {shown}")
    print("이 SARIF를 sast-remediation 프로젝트의 input/에 넣어 조치를 이어가세요.")
    return 0


def load_finding_keys() -> set[str]:
    if not FINDINGS_FILE.exists():
        return set()
    try:
        data = load_json(FINDINGS_FILE)
    except (OSError, json.JSONDecodeError):
        return set()
    if not isinstance(data, dict):
        return set()
    return {finding_key(f) for f in data.get("findings", []) if isinstance(f, dict)}


def validate_dispositions_file(report: Report) -> None:
    if not DISPOSITIONS_FILE.exists():
        return
    try:
        data = load_json(DISPOSITIONS_FILE)
    except (OSError, json.JSONDecodeError) as error:
        report.error(f"cannot read data/dispositions.json: {error} (likely half-written)")
        return
    if not isinstance(data, dict):
        report.error("dispositions file must be an object")
        return
    if data.get("schemaVersion") != SCHEMA_VERSION:
        report.error(f"dispositions schemaVersion must be {SCHEMA_VERSION!r}")
    records = data.get("dispositions")
    if not isinstance(records, dict):
        report.error("dispositions.dispositions must be an object")
        return
    finding_keys = load_finding_keys() | archived_keys()
    for key, record in records.items():
        where = f"disposition {key}"
        if not isinstance(record, dict):
            report.error(f"{where} must be an object")
            continue
        if finding_keys and key not in finding_keys:
            report.error(f"{where} references no finding (not in findings.json or any archived round)")
        disposition = record.get("disposition")
        stage = record.get("stage")
        if disposition not in DISPOSITION_VALUES:
            report.error(f"{where}.disposition must be one of {sorted(DISPOSITION_VALUES)}")
        if stage not in STAGE_VALUES:
            report.error(f"{where}.stage must be one of {sorted(STAGE_VALUES)}")
        if disposition in REASON_REQUIRED and not str(record.get("reason", "")).strip():
            report.error(f"{where} is '{disposition}' but has no reason")
        if record.get("handedOff") and disposition != "confirmed":
            report.error(f"{where} is handed off but disposition is '{disposition}', not 'confirmed'")
        # 리뷰를 끝냈다면(reviewed) 판정이 unreviewed로 남아 있으면 안 된다.
        if stage == "reviewed" and disposition == "unreviewed":
            report.error(f"{where} stage is 'reviewed' but disposition is still 'unreviewed'")
        decided_by = record.get("decidedBy")
        if decided_by is not None and decided_by not in DECIDED_BY_VALUES:
            report.error(f"{where}.decidedBy must be one of {sorted(DECIDED_BY_VALUES)}")
        if stage == "reviewed" and decided_by is None:
            report.warn(f"{where} is reviewed but has no decidedBy; record who decided (user or ai)")
        if stage == "reviewed" and disposition in USER_ONLY_CLOSING and decided_by == "ai":
            report.error(f"{where} closes a finding as '{disposition}' with decidedBy 'ai'; "
                         "only the user can confirm it (keep it in-review until then)")


def disposition_summary(findings: list[dict[str, Any]], records: dict[str, Any]) -> dict[str, Any]:
    """판정·확인 단계 집계. 레코드 없는 검출은 unreviewed로 센다. 순수 함수."""
    by_disposition: dict[str, int] = {}
    by_stage: dict[str, int] = {}
    reviewed_by: dict[str, int] = {}
    handed_off = 0
    for finding in findings:
        record = records.get(finding_key(finding)) or {}
        disposition = str(record.get("disposition") or "unreviewed")
        stage = str(record.get("stage") or "unreviewed")
        by_disposition[disposition] = by_disposition.get(disposition, 0) + 1
        by_stage[stage] = by_stage.get(stage, 0) + 1
        if stage == "reviewed":
            who = str(record.get("decidedBy") or "unrecorded")
            reviewed_by[who] = reviewed_by.get(who, 0) + 1
        if record.get("handedOff"):
            handed_off += 1
    return {"total": len(findings), "byDisposition": by_disposition, "byStage": by_stage,
            "reviewedBy": reviewed_by, "handedOff": handed_off}


def run_dispositions() -> int:
    findings_data = load_json(FINDINGS_FILE) if FINDINGS_FILE.exists() else {"findings": []}
    findings = findings_data.get("findings", []) if isinstance(findings_data, dict) else []
    records_data = load_json(DISPOSITIONS_FILE) if DISPOSITIONS_FILE.exists() else {"dispositions": {}}
    records = records_data.get("dispositions", {}) if isinstance(records_data, dict) else {}
    summary = disposition_summary(findings, records)
    try:
        previous = latest_round()
        scan_results = load_scan_results()
    except (ValueError, OSError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}")
        return 1
    if previous is not None:
        adapters_run = {name for name in scan_results if name != LEGACY_SCAN}
        coverage = {name: data.get("coverage") or {} for name, data in scan_results.items()}
        resolution = round_resolution(previous.get("findings", []), findings, adapters_run, coverage)
        summary["sincePreviousRound"] = {
            "round": previous.get("round"),
            "resolved": resolution["resolved"],
            "notRechecked": resolution["notRechecked"],
        }
    print(json_text(summary), end="")
    return 0


LEGACY_SCAN = "_legacy"


def scans_dir() -> Path:
    """어댑터별 결과 위치. findings.json 옆에 둔다(같은 툴킷 데이터 안)."""
    return FINDINGS_FILE.parent / "scans"


def rounds_dir() -> Path:
    """닫힌 차수의 검출 보관 위치."""
    return FINDINGS_FILE.parent / "rounds"


def is_url(value: str) -> bool:
    return value.startswith(("http://", "https://"))


def is_excluded(location_file: str, exclusions: list[str]) -> bool:
    """검출 위치가 제외 자산에 속하는지. 순수 함수.

    URL 검출은 URL 제외(경계 있는 접두사)나 호스트 제외(같거나 하위 도메인)와 비교하고,
    파일 검출은 URL이 아닌 제외와 경로 경계 접두사로 비교한다.
    """
    from urllib.parse import urlparse

    value = str(location_file or "").strip()
    if not value:
        return False
    if is_url(value):
        host = (urlparse(value).hostname or "").lower()
        for raw in exclusions:
            excl = str(raw).strip()
            if not excl:
                continue
            if is_url(excl):
                base = excl.rstrip("/")
                if value == base or value.startswith(base + "/") or value.startswith(base + "?") or value.startswith(base + "#"):
                    return True
            elif "/" not in excl and "." in excl:
                excl_host = excl.lower()
                if host == excl_host or host.endswith("." + excl_host):
                    return True
        return False
    path = value.removeprefix("./").rstrip("/")
    for raw in exclusions:
        excl = str(raw).strip()
        if not excl or is_url(excl):
            continue
        base = excl.removeprefix("./").rstrip("/")
        if base and (path == base or path.startswith(base + "/")):
            return True
    return False


def cloud_excluded(cloud: dict[str, Any], exclusions: list[str]) -> bool:
    """클라우드 검출이 제외된 계정·리전·리소스에 속하는지. 순수 함수.

    제외 표기: <제공자>:<계정>(계정 전체), <제공자>:<계정>:<리전>, 그리고 리소스 ID 접두사(arn:... 등).
    """
    account, region, resource = (str(cloud.get(k) or "") for k in ("account", "region", "resource"))
    for raw in exclusions:
        excl = str(raw).strip()
        if INFRA_EXCLUSION_RE.match(excl):
            parts = excl.split(":")
            if parts[1] == account and (len(parts) == 2 or parts[2] == region):
                return True
        elif resource and excl and not is_url(excl) and resource.startswith(excl) and ":" in excl:
            return True
    return False


def finding_excluded(finding: dict[str, Any], exclusions: list[str]) -> bool:
    location = finding.get("location") or {}
    if location.get("cloud"):
        return cloud_excluded(location["cloud"], exclusions)
    return is_excluded(str(location.get("file") or ""), exclusions)


def filter_excluded(findings: list[dict[str, Any]], exclusions: list[str]) -> tuple[list[dict[str, Any]], int]:
    kept = [f for f in findings if not finding_excluded(f, exclusions)]
    return kept, len(findings) - len(kept)


def load_scan_results() -> dict[str, dict[str, Any]]:
    """data/scans/*.json을 어댑터 이름별로 읽는다.

    반쪽 파일을 건너뛰면 그 어댑터의 결과가 빠진 채 검출이 다시 만들어지므로,
    읽을 수 없는 파일이 있으면 파일 이름과 함께 ValueError를 낸다.
    """
    directory = scans_dir()
    results: dict[str, dict[str, Any]] = {}
    if not directory.is_dir():
        return results
    for path in sorted(directory.glob("*.json")):
        try:
            data = load_json(path)
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError(
                f"cannot read data/scans/{path.name}: {error} (likely half-written); "
                f"re-run adapter '{path.stem}' with scan, or remove the file to drop its results"
            ) from error
        if isinstance(data, dict):
            results[path.stem] = data
    return results


def adapters_of(finding: dict[str, Any]) -> set[str]:
    return {str(s.get("adapter")) for s in finding.get("sources") or [] if isinstance(s, dict) and s.get("adapter")}


def cloud_rechecked(finding: dict[str, Any], coverage: dict[str, dict[str, Any]]) -> bool:
    """클라우드 검출을 이번 차수에 다시 봤는지: 같은 어댑터·대상이 그 리전과 점검 항목을 돌렸어야 한다."""
    cloud = (finding.get("location") or {}).get("cloud") or {}
    sources = [s for s in finding.get("sources") or [] if isinstance(s, dict) and s.get("adapter")]
    if not sources:
        return False
    for source in sources:
        seen = (coverage.get(str(source["adapter"])) or {}).get(str(source.get("target") or ""))
        if not seen or seen.get("mode") != "cloud":
            return False
        region = str(cloud.get("region") or "")
        if region not in {"", "global"} and region not in set(seen.get("regions") or []):
            return False
        if str(cloud.get("check") or "") not in set(seen.get("checks") or []):
            return False
    return True


def web_rechecked(finding: dict[str, Any], coverage: dict[str, dict[str, Any]]) -> bool:
    """웹 검출을 이번 차수에 실제로 다시 봤는지. 출처의 어댑터·대상마다 커버리지가 그 경로를 덮어야 한다."""
    path = str(((finding.get("location") or {}).get("web") or {}).get("path") or "")
    sources = [s for s in finding.get("sources") or [] if isinstance(s, dict) and s.get("adapter")]
    if not path or not sources:
        return False
    for source in sources:
        seen = (coverage.get(str(source["adapter"])) or {}).get(str(source.get("target") or ""))
        if not seen or seen.get("mode") == "none":
            return False
        if seen.get("mode") == "url-list" and path not in set(seen.get("paths") or []):
            return False
    return True


def round_resolution(previous: list[dict[str, Any]], current: list[dict[str, Any]],
                     adapters_run: set[str],
                     coverage: dict[str, dict[str, dict[str, Any]]] | None = None) -> dict[str, list[str]]:
    """직전 차수 대비 사라진 검출을 분류한다. 순수 함수.

    사라진 검출은 그 검출을 찾았던 어댑터가 이번 차수에 모두 다시 돌았을 때만 해소로 본다.
    다시 돌지 않았으면 사라진 것이 아니라 확인하지 않은 것이다. 웹 검출은 크롤링 범위가
    실행마다 달라 커버리지가 그 경로를 덮었을 때만 해소다(ADR 0003).
    """
    current_keys = {finding_key(f) for f in current}
    resolved: list[str] = []
    not_rechecked: list[str] = []
    for finding in previous:
        key = finding_key(finding)
        if key in current_keys:
            continue
        sources = adapters_of(finding)
        location = finding.get("location") or {}
        if location.get("cloud"):
            seen_again = cloud_rechecked(finding, coverage or {})
        elif is_url(str(location.get("file") or "")):
            seen_again = web_rechecked(finding, coverage or {})
        else:
            seen_again = True
        if sources and sources <= adapters_run and seen_again:
            resolved.append(key)
        else:
            not_rechecked.append(key)
    return {"resolved": sorted(resolved), "notRechecked": sorted(not_rechecked)}


def validate_runtime_files(report: Report) -> None:
    """어댑터별 결과와 보관 차수 파일이 읽히는지 확인하고, 반쪽 파일을 지목한다."""
    for directory, pattern in ((scans_dir(), "*.json"), (rounds_dir(), "round-*.json")):
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob(pattern)):
            try:
                load_json(path)
            except (OSError, json.JSONDecodeError) as error:
                report.error(f"cannot read data/{directory.name}/{path.name}: {error} (likely half-written)")


def latest_round() -> dict[str, Any] | None:
    directory = rounds_dir()
    if not directory.is_dir():
        return None
    files = sorted(directory.glob("round-*.json"))
    if not files:
        return None
    data = load_json(files[-1])
    return data if isinstance(data, dict) else None


def archived_keys() -> set[str]:
    """보관된 차수의 검출 키. 읽을 수 없는 파일은 validate_runtime_files가 따로 지목한다."""
    directory = rounds_dir()
    keys: set[str] = set()
    if directory.is_dir():
        for path in directory.glob("round-*.json"):
            try:
                data = load_json(path)
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(data, dict):
                keys |= {finding_key(f) for f in data.get("findings", []) if isinstance(f, dict)}
    return keys


def rebuild_findings(scope: dict[str, Any]) -> tuple[int, int]:
    """어댑터별 결과를 합쳐 findings.json을 다시 만든다. (검출 수, 제외된 수)."""
    collected: list[dict[str, Any]] = []
    for data in load_scan_results().values():
        collected += [f for f in data.get("findings", []) if isinstance(f, dict)]
    merged = merge_findings(collected)
    kept, excluded = filter_excluded(merged, [str(x) for x in scope.get("exclusions", [])])
    write_json_atomic(FINDINGS_FILE, {
        "schemaVersion": SCHEMA_VERSION,
        "generatedAt": now_utc().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "findings": kept,
    })
    return len(kept), excluded


def preserve_legacy_findings() -> None:
    """어댑터별 저장 이전에 만든 findings.json을 한 번만 보존용 결과로 옮긴다."""
    directory = scans_dir()
    if directory.is_dir() and any(directory.glob("*.json")):
        return
    if not FINDINGS_FILE.exists():
        return
    data = load_json(FINDINGS_FILE)
    findings = data.get("findings", []) if isinstance(data, dict) else []
    if not findings:
        return
    directory.mkdir(parents=True, exist_ok=True)
    write_json_atomic(directory / f"{LEGACY_SCAN}.json", {
        "schemaVersion": SCHEMA_VERSION, "adapter": LEGACY_SCAN, "ranAt": None,
        "targets": [], "findings": findings,
    })


def run_new_round() -> int:
    """현재 차수의 검출을 보관하고 새 차수를 연다. 판정은 키로 이어지므로 그대로 둔다."""
    if not FINDINGS_FILE.exists():
        print("보관할 검출이 없습니다. 먼저 scan을 실행하세요.")
        return 1
    current = load_json(FINDINGS_FILE)
    findings = current.get("findings", []) if isinstance(current, dict) else []
    directory = rounds_dir()
    directory.mkdir(parents=True, exist_ok=True)
    number = len(list(directory.glob("round-*.json"))) + 1
    try:
        adapters_run = sorted(name for name in load_scan_results() if name != LEGACY_SCAN)
    except ValueError as error:
        print(f"ERROR: {error}")
        return 1
    write_json_atomic(directory / f"round-{number:03d}.json", {
        "schemaVersion": SCHEMA_VERSION, "round": number,
        "closedAt": now_utc().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "adaptersRun": adapters_run, "findings": findings,
    })
    for path in scans_dir().glob("*.json") if scans_dir().is_dir() else []:
        path.unlink()
    FINDINGS_FILE.unlink()
    print(f"{number}차 점검을 닫았습니다: 검출 {len(findings)}건을 data/rounds/round-{number:03d}.json에 보관.")
    print("새 차수에서 scan을 실행하면 직전 차수 대비 해소 여부를 dispositions로 볼 수 있습니다.")
    return 0


def tag_sources(items: list[dict[str, Any]], adapter: str, target: str, collected_by: str) -> None:
    """출처에 어댑터(차수 간 해소 판단)·대상(대상별 교체)·수집 주체(skill|operator)를 남긴다."""
    for item in items:
        for source in item["sources"]:
            source["adapter"] = adapter
            source["target"] = target
            source["collectedBy"] = collected_by


def replace_target_findings(existing: dict[str, Any] | None, target: str,
                            new_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """한 어댑터 결과에서 한 대상의 검출만 새것으로 바꾼다. 순수 함수.

    대상 표시가 없는 예전 검출은 그 어댑터가 이 대상 하나만 돌았을 때만 이 대상의 것으로 본다.
    """
    if not existing:
        return list(new_items)
    only_this = [str(t) for t in existing.get("targets") or []] == [target]
    kept = []
    for finding in existing.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        sources = [s for s in finding.get("sources") or [] if isinstance(s, dict)]
        marked = {s.get("target") for s in sources if s.get("target")}
        if marked == {target} or (not marked and only_this):
            continue
        kept.append(finding)
    return kept + list(new_items)


def run_ingest(adapter_name: str | None, file: str | None, target: str | None,
               coverage_file: str | None = None) -> int:
    """운영자가 돌린 어댑터 출력을 들여온다. scan과 같은 정규화·저장·합침을 거친다.

    게이트 READY가 전제다. 스코프 상한을 넘는(forbidden) 어댑터의 출력은 받지 않는다.
    같은 어댑터·같은 대상의 이전 결과만 바뀌고, 출력 파일의 이름과 SHA-256을 남긴다.
    """
    if not adapter_name or not file:
        print("ERROR: ingest에는 --adapter와 --file이 필요합니다.")
        return 1
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
        print("INGEST: BLOCKED (gate not ready)")
        for blocker in blockers:
            print(f"- {blocker}")
        return 1
    adapters = dict(load_adapters())
    adapter = adapters.get(adapter_name)
    if adapter is None:
        print(f"ERROR: 선언된 어댑터가 아닙니다: {adapter_name} (있는 것: {', '.join(sorted(adapters)) or '없음'})")
        return 1
    if not isinstance(adapter, dict) or "__error__" in adapter:
        print(f"ERROR: {adapter_name} 선언 오류 (validate로 확인)")
        return 1
    decision, reason = execution_decision(adapter, scope, False)
    if decision == "forbidden":
        print(f"INGEST: 거부 — {reason}. 스코프 상한을 넘는 어댑터의 결과는 들여오지 않습니다.")
        return 1
    targets = targets_for_adapter(adapter, scope)
    if target is None:
        if len(targets) != 1:
            print(f"ERROR: --target이 필요합니다. 이 어댑터의 대상: {', '.join(targets) or '(없음)'}")
            return 1
        target = targets[0]
    elif target not in targets:
        print(f"ERROR: {target}은(는) 이 어댑터의 스코프 대상이 아닙니다. 대상: {', '.join(targets) or '(없음)'}")
        return 1
    web = is_web_adapter(adapter)
    cloud_regions: list[str] = []
    if is_cloud_adapter(adapter):
        allowed = cloud_allowed_regions(scope, target)
        if not allowed:
            print(f"INGEST: 거부 — {target}의 계정 전체 또는 모든 리전이 제외 자산입니다.")
            return 1
        cloud_regions = allowed
    if web:
        exclusions = [str(x) for x in scope.get("exclusions", [])]
        if is_excluded(target, exclusions):
            print(f"INGEST: 거부 — {target}은(는) 제외 자산입니다.")
            return 1
        _args, why = web_scope_args(adapter, exclusions_for_target(target, exclusions))
        if _args is None:
            print(f"INGEST: 거부 — {why}. 스캐너가 제외 자산을 지켰는지 알 수 없어 들여오지 않습니다.")
            return 1
    path = Path(file)
    try:
        raw_bytes = path.read_bytes()
        raw = json.loads(raw_bytes.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        print(f"ERROR: 출력 파일을 JSON으로 읽을 수 없습니다: {file} ({error})")
        return 1
    try:
        sarif = normalize_to_sarif(str(adapter.get("output_format", "")), raw)
    except ValueError as error:
        print(f"ERROR: {error}")
        return 1
    try:
        existing = load_scan_results().get(adapter_name)  # 반쪽 파일이 있으면 쓰기 전에 멈춘다
    except ValueError as error:
        print(f"ERROR: {error}")
        return 1
    preserve_legacy_findings()
    items = findings_from_sarif(sarif, adapter_name, str(adapter.get("category")))
    props = sarif_run_properties(sarif)
    if is_cloud_adapter(adapter):
        violation = cloud_scope_violation(props, target, cloud_regions)
        if violation:
            print(f"INGEST: 거부 — {violation}. 스캐너가 계정·리전 범위를 지키지 않아 들여오지 않습니다.")
            return 1
    tag_sources(items, adapter_name, target, "operator")
    now = now_utc().strftime("%Y-%m-%dT%H:%M:%SZ")
    ingested = [e for e in (existing or {}).get("ingested") or [] if isinstance(e, dict) and e.get("target") != target]
    coverage = (existing or {}).get("coverage") or {}
    if is_cloud_adapter(adapter):
        coverage = {**coverage, target: {"mode": "cloud", "regions": sorted(set(props["regionsSeen"]) & set(cloud_regions)),
                                         "checks": props["checksRun"]}}
    controls = {k: v for k, v in ((existing or {}).get("controls") or {}).items() if k != target}
    summary = summarize_controls(props["controlResults"], [str(x) for x in scope.get("exclusions", [])])
    if summary:
        controls[target] = summary
    if web:
        coverage = {k: v for k, v in coverage.items() if k != target}
        mode = str((adapter.get("coverage") or {}).get("mode") or "none")
        if mode == "fixed-probes":
            coverage[target] = {"mode": mode}
        elif mode == "url-list" and coverage_file:
            try:
                lines = Path(coverage_file).read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError as error:
                print(f"ERROR: 커버리지 파일을 읽을 수 없습니다: {coverage_file} ({error})")
                return 1
            coverage[target] = {"mode": mode, "paths": sorted({normalize_web_path(u.strip()) for u in lines if u.strip()})}
        else:
            coverage[target] = {"mode": "none"}
    ingested.append({"target": target, "file": path.name,
                     "sha256": hashlib.sha256(raw_bytes).hexdigest(), "ingestedAt": now})
    scans_dir().mkdir(parents=True, exist_ok=True)
    write_json_atomic(scans_dir() / f"{adapter_name}.json", {
        "schemaVersion": SCHEMA_VERSION, "adapter": adapter_name, "ranAt": now,
        "targets": sorted({*[str(t) for t in (existing or {}).get("targets") or []], target}),
        "findings": replace_target_findings(existing, target, items),
        "ingested": ingested,
        **({"coverage": coverage} if coverage else {}),
        **({"controls": controls} if controls else {}),
    })
    total, excluded = rebuild_findings(scope)
    note = f", 제외 자산 {excluded}건 제외" if excluded else ""
    print(f"INGEST: {adapter_name} @ {target} — 운영자 출력 {len(items)}건 → 검출 {total}건{note}. data/findings.json")
    return 0


def collect_coverage(adapter: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    """웹 실행의 커버리지. fixed-probes는 같은 탐침을 매번 대상 전체에, url-list는 방문 URL 파일."""
    coverage = adapter.get("coverage") or {}
    mode = str(coverage.get("mode") or "none")
    if mode == "fixed-probes":
        return {"mode": mode}
    if mode == "url-list":
        path = output_dir / str(coverage.get("file", ""))
        if path.is_file():
            urls = [line.strip() for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
            return {"mode": mode, "paths": sorted({normalize_web_path(u) for u in urls})}
    return {"mode": "none"}


def run_scan(direct: bool, confirm: str | None = None) -> int:
    """실행 판정이 'run'인 어댑터만 스킬이 돌리고, 어댑터별 결과를 저장한 뒤 합쳐 findings를 만든다.

    게이트 READY가 전제. operator/forbidden 어댑터는 실행하지 않고 안내만 한다. 웹 어댑터는
    제외 자산을 스캐너에 넘길 수 있어야 하고, 실행 계획을 보여 준 뒤 그 계획의 확인 코드가
    --confirm으로 왔을 때만 돈다(ADR 0003). 실행된 어댑터의 결과만 바뀐다.
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
    import tempfile as _tempfile
    try:
        load_scan_results()  # 반쪽 파일이 있으면 아무것도 실행하기 전에 멈춘다
    except ValueError as error:
        print(f"ERROR: {error}")
        return 1
    exclusions = [str(x) for x in scope.get("exclusions", [])]
    now = now_utc()
    # 1단계: 어댑터·대상별로 무엇을 할지 정한다. jobs는 (이름, 어댑터, 대상, 추가 인자, 웹 계획 또는 None)
    jobs: list[tuple[str, dict[str, Any], str, list[str], dict[str, Any] | None]] = []
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
        web = is_web_adapter(adapter)
        cloud = is_cloud_adapter(adapter)
        target_args: list[tuple[str, list[str]]] = []
        for target in targets:
            if cloud:
                regions = cloud_allowed_regions(scope, target)
                if regions is None or not regions:
                    print(f"- {name} @ {target}: 계정 전체 또는 모든 리전이 제외 자산이라 건너뜀")
                    continue
                args, why = cloud_args(adapter, scope, target, regions)
                if args is None:
                    print(f"- {name} @ {target}: 거부 — {why}. 실행도 들여오기도 하지 않습니다.")
                    continue
                target_args.append((target, args))
                continue
            if not web:
                target_args.append((target, []))
                continue
            if is_excluded(target, exclusions):
                print(f"- {name} @ {target}: 대상 전체가 제외 자산이라 건너뜀")
                continue
            args, why = web_scope_args(adapter, exclusions_for_target(target, exclusions))
            if args is None:
                print(f"- {name} @ {target}: 거부 — {why}. 실행도 들여오기도 하지 않습니다.")
                continue
            rate = adapter.get("rate_limit")
            if rate:
                args += _render_tokens(str(rate), "{rate}", f"{web_rate_limit(scope, target):g}")
            target_args.append((target, args))
        if web and decision == "run" and web_direct_blockers(adapter):
            decision, reason = "operator", "; ".join(web_direct_blockers(adapter))
        if cloud and decision == "run" and cloud_direct_blockers(adapter):
            decision, reason = "operator", "; ".join(cloud_direct_blockers(adapter))
        if decision == "operator":
            print(f"- {name}: operator — {reason}")
            for target, args in target_args:
                rendered = " ".join(render_command(str(adapter.get("command", "")), target, Path(f"{name}.out"), args))
                print(f"    운영자 실행: {rendered}")
                print(f"    들여오기: python3 tools/assess_toolkit.py ingest --adapter {name} --file <출력 파일> --target {target}")
            continue
        for target, args in target_args:
            plan = web_run_plan(name, adapter, scope, target, args) if web else None
            jobs.append((name, adapter, target, args, plan))
    # 2단계: 웹 실행은 계획 전체의 확인 코드가 맞을 때만
    plans = [plan for *_, plan in jobs if plan is not None]
    web_confirmed = bool(plans) and confirm == plan_code(plans)
    if plans and not web_confirmed:
        print("WEB: 아래 웹 실행은 사용자 확인이 필요합니다. 확인되면 같은 명령에 --confirm을 붙여 다시 실행합니다.")
        for plan in plans:
            exc = plan["exclusions"]
            print(f"  - {plan['adapter']} @ {plan['target']}: 초당 {plan['ratePerSecond']:g}건 이하, "
                  f"최대 {plan['maxSeconds']}초(기간 끝 {plan['windowEnd']} 전까지), "
                  f"제외 호스트 {', '.join(exc['hosts']) or '없음'} · 제외 URL {', '.join(exc['urls']) or '없음'}")
        print(f"  확인 코드: {plan_code(plans)}  →  scan --direct --confirm {plan_code(plans)}")
        if confirm:
            print("  (받은 확인 코드가 현재 계획과 다릅니다. 계획이 바뀌었으면 다시 확인받으세요.)")
    preserve_legacy_findings()  # 어댑터별 저장 이전 결과를 첫 쓰기 전에 보존
    results: dict[str, dict[str, Any]] = {}
    for name, adapter, target, args, plan in jobs:
        if plan is not None and not web_confirmed:
            continue
        timeout = DEFAULT_MAX_SECONDS
        if plan is not None:
            timeout = web_time_limit(adapter, scope, now)
            if timeout <= 0:
                print(f"- {name} @ {target}: 점검 기간이 끝나 실행하지 않음")
                continue
        entry = results.setdefault(name, {"findings": [], "targets": [], "coverage": {}})
        with _tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / f"{name}.out"
            try:
                code = execute_adapter(str(adapter.get("command", "")), target, output, timeout=timeout, extra_args=args)
            except Exception as error:  # noqa: BLE001 — 도구 부재·실행 오류·시간 초과를 안내로
                print(f"- {name} @ {target}: 실행 실패 ({error}); availability로 설치 확인")
                continue
            # 출력 파일 이름을 스스로 정하는 도구는 어댑터가 output_file로 그 이름을 알려 준다.
            produced = output.parent / str(adapter["output_file"]) if adapter.get("output_file") else output
            if not produced.exists():
                print(f"- {name} @ {target}: 출력 파일 없음 (종료코드 {code})")
                continue
            try:
                raw = load_json(produced)
            except json.JSONDecodeError:
                print(f"- {name} @ {target}: 출력이 JSON이 아님")
                continue
            try:
                sarif = normalize_to_sarif(str(adapter.get("output_format", "")), raw)
            except ValueError as error:
                print(f"- {name} @ {target}: {error}")
                continue
            items = findings_from_sarif(sarif, name, str(adapter.get("category")))
            props = sarif_run_properties(sarif)
            if is_cloud_adapter(adapter):
                regions = cloud_allowed_regions(scope, target) or []
                violation = cloud_scope_violation(props, target, regions)
                if violation:
                    print(f"- {name} @ {target}: 결과를 버림 — {violation}. 스캐너 설정을 확인하세요.")
                    continue
                entry["coverage"][target] = {"mode": "cloud", "regions": regions, "checks": props["checksRun"]}
            summary = summarize_controls(props["controlResults"], exclusions)
            if summary:
                entry.setdefault("controls", {})[target] = summary
            tag_sources(items, name, target, "skill")
            entry["findings"] += items
            entry["targets"].append(target)
            if plan is not None:
                entry["coverage"][target] = collect_coverage(adapter, Path(tmp))
            print(f"- {name} @ {target}: run — 검출 {len(items)}건")
    ran: list[str] = []
    for name, entry in results.items():
        if not entry["targets"]:
            print(f"- {name}: 성공한 실행이 없어 이전 결과를 유지합니다")
            continue
        scans_dir().mkdir(parents=True, exist_ok=True)
        record = {
            "schemaVersion": SCHEMA_VERSION, "adapter": name,
            "ranAt": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "targets": entry["targets"], "findings": entry["findings"],
        }
        if entry["coverage"]:
            record["coverage"] = entry["coverage"]
        if entry.get("controls"):
            record["controls"] = entry["controls"]
        write_json_atomic(scans_dir() / f"{name}.json", record)
        ran.append(name)
    if not ran:
        print("SCAN: 실행된 어댑터가 없어 검출을 바꾸지 않았습니다.")
        return 0
    total, excluded = rebuild_findings(scope)
    note = f", 제외 자산 {excluded}건 제외" if excluded else ""
    print(f"SCAN: 실행 {', '.join(ran)} → 검출 {total}건{note}. data/findings.json")
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
        if is_cloud_adapter(adapter) and decision == "run" and cloud_direct_blockers(adapter):
            decision, reason = "operator", "; ".join(cloud_direct_blockers(adapter))
        if is_web_adapter(adapter) and decision == "run" and web_direct_blockers(adapter):
            decision, reason = "operator", "; ".join(web_direct_blockers(adapter))
        elif is_web_adapter(adapter) and decision == "run":
            reason += " (웹: 실행 전 계획 확인 필요)"
        print(f"- {name} [{adapter.get('category')}/{adapter.get('intrusiveness')}] → {decision}: {reason}")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="security-assessment: authorization gate, scanning, dispositions, handoff and evidence.")
    parser.add_argument("command", choices=("validate", "authorize", "gate", "adapters", "scan", "ingest", "dispositions", "checklist", "bridge", "evidence", "new-round"))
    parser.add_argument("--adapter", help="ingest: 운영자가 돌린 어댑터 이름")
    parser.add_argument("--file", help="ingest: 운영자가 넘긴 출력 파일")
    parser.add_argument("--target", help="ingest: 출력이 가리키는 스코프 대상(어댑터 대상이 하나면 생략)")
    parser.add_argument("--confirm", help="scan: 사용자가 확인한 웹 실행 계획의 확인 코드")
    parser.add_argument("--coverage", help="ingest: 웹 스캐너가 방문한 URL 목록 파일(url-list 커버리지)")
    parser.add_argument("--strict", action="store_true", help="treat a not-ready gate as a validation error")
    parser.add_argument("--direct", action="store_true", help="adapters: 사용자가 직접 실행을 명시했다고 본다")
    parser.add_argument("--dry-run", action="store_true", help="bridge: 파일·판정을 쓰지 않고 건수만 보고")
    parser.add_argument("--all", action="store_true", dest="all_findings", help="bridge: 이미 넘긴 것도 다시 내보낸다")
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
        return run_scan(args.direct, args.confirm)
    if args.command == "ingest":
        return run_ingest(args.adapter, args.file, args.target, args.coverage)
    if args.command == "dispositions":
        return run_dispositions()
    if args.command == "checklist":
        return run_checklist()
    if args.command == "bridge":
        return run_bridge(args.dry_run, args.all_findings)
    if args.command == "evidence":
        return run_evidence()
    if args.command == "new-round":
        return run_new_round()
    return run_gate()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        sys.exit(0)
