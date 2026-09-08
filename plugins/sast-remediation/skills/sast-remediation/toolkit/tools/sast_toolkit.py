#!/usr/bin/env python3
"""Synchronize and validate the universal SAST remediation toolkit."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import zipfile
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
GUIDE_DIR = ROOT / "security-guides"
RESULT_DIR = ROOT / "security-results"
INPUT_DIR = ROOT / "input"
PROJECT_DIR = ROOT / "project"

WORKFLOW_VALUES = {
    "todo",
    "in-progress",
    "analyzed",
    "change-complete",
    "verified",
    "deferred",
}
CONCLUSION_VALUES = {
    "unreviewed",
    "fix",
    "false-positive",
    "operations",
    "exception",
    "needs-review",
}
MAPPING_VALUES = {
    "unreviewed",
    "exact",
    "relocated",
    "changed",
    "not-found",
    "generated-or-external",
}
SEVERITY_VALUES = {
    "critical",
    "very-high",
    "high",
    "medium",
    "low",
    "info",
    "unknown",
}
VERIFICATION_VALUES = {
    "not-run",
    "passed",
    "failed",
    "partial",
    "manual-required",
}
INPUT_VALIDATION_VALUES = {
    "unreviewed",
    "mechanical-ready",
    "ready",
    "blocked",
}
CHECK_VALUES = {"pass", "fail", "manual"}
SPREADSHEET_SUFFIXES = {".xls", ".xlsx", ".xlsm", ".csv", ".tsv"}
SOURCE_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".go",
    ".groovy",
    ".h",
    ".hpp",
    ".html",
    ".java",
    ".js",
    ".jsp",
    ".jsx",
    ".kt",
    ".kts",
    ".m",
    ".mm",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".scala",
    ".sql",
    ".svelte",
    ".swift",
    ".ts",
    ".tsx",
    ".vue",
}
PROJECT_MARKERS = {
    "build.gradle",
    "build.gradle.kts",
    "cargo.toml",
    "cmakelists.txt",
    "composer.json",
    "dockerfile",
    "gemfile",
    "go.mod",
    "makefile",
    "package.json",
    "pom.xml",
    "pyproject.toml",
    "requirements.txt",
    "settings.gradle",
    "settings.gradle.kts",
}
SKIP_PROJECT_DIRS = {
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "target",
    "vendor",
}

FINGERPRINT_REQUIRED_MAPPINGS = {"exact", "relocated", "changed"}

# 스키마 파일과 이 검증기의 enum 정의가 어긋나지 않도록 교차 검증한다.
# (schema path, JSON pointer segments, validator value-set name)
SCHEMA_ENUM_CHECKS = (
    (
        "schemas/progress.schema.json",
        ("properties", "items", "additionalProperties", "properties", "workflowStatus", "enum"),
        "WORKFLOW_VALUES",
    ),
    (
        "schemas/progress.schema.json",
        ("properties", "items", "additionalProperties", "properties", "conclusion", "enum"),
        "CONCLUSION_VALUES",
    ),
    (
        "schemas/result.schema.json",
        ("properties", "workflowStatus", "enum"),
        "WORKFLOW_VALUES",
    ),
    (
        "schemas/result.schema.json",
        ("properties", "conclusion", "enum"),
        "CONCLUSION_VALUES",
    ),
    (
        "schemas/result.schema.json",
        ("properties", "verification", "properties", "status", "enum"),
        "VERIFICATION_VALUES",
    ),
    (
        "schemas/findings.schema.json",
        ("items", "properties", "sourceMapping", "properties", "status", "enum"),
        "MAPPING_VALUES",
    ),
    (
        "schemas/findings.schema.json",
        ("items", "properties", "suggestedConclusion", "enum"),
        "CONCLUSION_VALUES",
    ),
    (
        "schemas/findings.schema.json",
        ("$defs", "severity", "properties", "level", "enum"),
        "SEVERITY_VALUES",
    ),
    (
        "schemas/input-validation.schema.json",
        ("properties", "status", "enum"),
        "INPUT_VALIDATION_VALUES",
    ),
    (
        "schemas/input-validation.schema.json",
        ("properties", "checks", "items", "properties", "status", "enum"),
        "CHECK_VALUES",
    ),
)

DATA_MIRRORS = {
    "input-validation": "inputValidation",
    "project-profile": "projectProfile",
    "findings": "findings",
    "checker-guides": "checkerGuides",
    "progress": "progress",
}

REQUIRED_FILES = (
    "README.md",
    "USAGE.md",
    "USAGE.html",
    "SECURITY_CHECKLIST.html",
    "SECURITY_SAST_WORKFLOW.md",
    "SECURITY_POLICY_BASELINE.md",
    "SECURITY_GRILL_GUIDE.md",
    "SECURITY_TEST_GUIDE.md",
    "assets/checklist.css",
    "assets/checklist.js",
    "data/input-validation.json",
    "data/project-profile.json",
    "data/findings.json",
    "data/checker-guides.json",
    "data/progress.json",
    "schemas/input-validation.schema.json",
    "schemas/project-profile.schema.json",
    "schemas/findings.schema.json",
    "schemas/checker-guides.schema.json",
    "schemas/item-guide.schema.json",
    "schemas/result.schema.json",
    "schemas/progress.schema.json",
)


class ValidationReport:
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
        if not self.errors:
            print(f"OK: validation completed with {len(self.warnings)} warning(s)")
        else:
            print(
                f"FAILED: {len(self.errors)} error(s), "
                f"{len(self.warnings)} warning(s)"
            )


class DashboardParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: set[str] = set()
        self.assets: set[str] = set()

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        values = dict(attrs)
        element_id = values.get("id")
        if element_id:
            self.ids.add(element_id)
        if tag == "script" and values.get("src"):
            self.assets.add(str(values["src"]))
        if tag == "link" and values.get("href"):
            self.assets.add(str(values["href"]))


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2) + "\n"


def data_mirror_text(property_name: str, value: Any) -> str:
    return (
        "window.SAST_TOOLKIT_DATA = window.SAST_TOOLKIT_DATA || {};\n"
        f"window.SAST_TOOLKIT_DATA.{property_name} = "
        f"{json.dumps(value, ensure_ascii=False, indent=2)};\n"
    )


def item_mirror_text(namespace: str, finding_id: str, value: Any) -> str:
    return (
        f"window.{namespace} = window.{namespace} || {{}};\n"
        f"window.{namespace}[{json.dumps(finding_id, ensure_ascii=False)}] = "
        f"{json.dumps(value, ensure_ascii=False, indent=2)};\n"
    )


def index_mirror_text(namespace: str, values: dict[str, Any]) -> str:
    return (
        f"window.{namespace} = window.{namespace} || {{}};\n"
        f"Object.assign(window.{namespace}, "
        f"{json.dumps(values, ensure_ascii=False, indent=2)});\n"
    )


def iter_record_json(directory: Path) -> Iterable[Path]:
    for path in sorted(directory.glob("*.json")):
        if path.name != "index.json":
            yield path


def sync_data() -> None:
    for filename, property_name in DATA_MIRRORS.items():
        json_path = DATA_DIR / f"{filename}.json"
        value = load_json(json_path)
        (DATA_DIR / f"{filename}.js").write_text(
            data_mirror_text(property_name, value), encoding="utf-8"
        )


def sync_records(directory: Path, namespace: str) -> None:
    values: dict[str, Any] = {}
    for json_path in iter_record_json(directory):
        value = load_json(json_path)
        finding_id = str(value.get("id", json_path.stem))
        values[finding_id] = value
        json_path.with_suffix(".js").write_text(
            item_mirror_text(namespace, finding_id, value), encoding="utf-8"
        )
    (directory / "index.json").write_text(json_text(values), encoding="utf-8")
    (directory / "index.js").write_text(
        index_mirror_text(namespace, values), encoding="utf-8"
    )


def sync_all() -> None:
    sync_data()
    sync_records(GUIDE_DIR, "SAST_ITEM_GUIDES")
    sync_records(RESULT_DIR, "SAST_ITEM_RESULTS")
    print("Synchronized dashboard data and item indexes.")


def initialize(project_root: Path) -> int:
    if run_gate(project_root) != 0:
        print("Initialization was not started because the input gate is blocked.")
        return 1
    template_pairs = (
        ("INPUT_VALIDATION.template.md", "INPUT_VALIDATION.md"),
        ("PROJECT_ANALYSIS.template.md", "PROJECT_ANALYSIS.md"),
        ("PROJECT_SECURITY_POLICY.template.md", "PROJECT_SECURITY_POLICY.md"),
        ("DECISION_LOG.template.md", "DECISION_LOG.md"),
        ("WORK_GROUPS.template.md", "WORK_GROUPS.md"),
    )
    created: list[str] = []
    for source_name, target_name in template_pairs:
        source = PROJECT_DIR / source_name
        target = PROJECT_DIR / target_name
        if not target.exists():
            shutil.copyfile(source, target)
            created.append(str(target.relative_to(ROOT)))
    sync_all()
    if created:
        print("Created project records:")
        for path in created:
            print(f"- {path}")
    else:
        print("Project records already exist; no templates were overwritten.")
    return 0


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def input_files() -> tuple[list[Path], list[Path]]:
    if not INPUT_DIR.is_dir():
        return [], []
    pdf_files = [
        path
        for path in INPUT_DIR.iterdir()
        if path.is_file() and path.suffix.lower() == ".pdf"
    ]
    spreadsheet_files = [
        path
        for path in INPUT_DIR.iterdir()
        if path.is_file() and path.suffix.lower() in SPREADSHEET_SUFFIXES
    ]
    return sorted(pdf_files), sorted(spreadsheet_files)


def display_path(path: Path, base: Path = ROOT) -> str:
    try:
        return path.resolve().relative_to(base.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def inspect_pdf(path: Path) -> dict[str, Any]:
    try:
        size = path.stat().st_size
    except OSError as error:
        return {
            "path": display_path(path),
            "size": 0,
            "format": "pdf",
            "formatValid": False,
            "evidence": f"PDF를 읽을 수 없습니다: {error}",
        }
    valid = False
    evidence = "PDF 파일 시그니처를 확인할 수 없습니다."
    try:
        with path.open("rb") as handle:
            header = handle.read(5)
        valid = size > 5 and header == b"%PDF-"
        evidence = (
            "PDF 파일 시그니처 확인"
            if valid
            else "확장자는 PDF이지만 PDF 파일 시그니처가 아닙니다."
        )
    except OSError as error:
        evidence = f"PDF를 읽을 수 없습니다: {error}"
    return {
        "path": display_path(path),
        "size": size,
        "format": "pdf",
        "formatValid": valid,
        "evidence": evidence,
    }


def inspect_spreadsheet(path: Path) -> dict[str, Any]:
    suffix = path.suffix.lower().lstrip(".")
    try:
        size = path.stat().st_size
    except OSError as error:
        return {
            "path": display_path(path),
            "size": 0,
            "format": suffix,
            "formatValid": False,
            "evidence": f"스프레드시트를 읽을 수 없습니다: {error}",
        }
    valid = False
    evidence = "스프레드시트 형식을 확인할 수 없습니다."
    try:
        if path.suffix.lower() in {".xlsx", ".xlsm"}:
            if zipfile.is_zipfile(path):
                with zipfile.ZipFile(path) as workbook:
                    names = set(workbook.namelist())
                valid = (
                    "[Content_Types].xml" in names
                    and "xl/workbook.xml" in names
                )
            evidence = (
                "스프레드시트 컨테이너와 워크북 확인"
                if valid
                else "확장자와 실제 스프레드시트 구조가 일치하지 않습니다."
            )
        elif path.suffix.lower() == ".xls":
            with path.open("rb") as handle:
                header = handle.read(8)
            valid = size >= 8 and header == bytes.fromhex(
                "D0CF11E0A1B11AE1"
            )
            evidence = (
                "바이너리 스프레드시트 시그니처 확인"
                if valid
                else "확장자와 실제 바이너리 스프레드시트 형식이 일치하지 않습니다."
            )
        else:
            with path.open("rb") as handle:
                sample = handle.read(131072)
            decoded = None
            for encoding in ("utf-8-sig", "cp949"):
                try:
                    decoded = sample.decode(encoding)
                    break
                except UnicodeDecodeError:
                    continue
            valid = decoded is not None and len(
                [line for line in decoded.splitlines() if line.strip()]
            ) >= 2
            evidence = (
                "구분자 텍스트 헤더와 데이터 행 확인"
                if valid
                else "읽을 수 있는 헤더와 데이터 행을 확인하지 못했습니다."
            )
    except (OSError, zipfile.BadZipFile) as error:
        evidence = f"스프레드시트를 읽을 수 없습니다: {error}"
    return {
        "path": display_path(path),
        "size": size,
        "format": suffix,
        "formatValid": valid,
        "evidence": evidence,
    }


def discover_project_evidence(project_root: Path) -> tuple[list[str], list[str]]:
    source_files: list[str] = []
    marker_files: list[str] = []
    toolkit_root = ROOT.resolve()
    for current, directory_names, file_names in os.walk(project_root):
        current_path = Path(current)
        kept_directories: list[str] = []
        for directory_name in directory_names:
            candidate = (current_path / directory_name).resolve()
            if (
                candidate == toolkit_root
                or directory_name in SKIP_PROJECT_DIRS
                or directory_name.startswith(".")
            ):
                continue
            kept_directories.append(directory_name)
        directory_names[:] = kept_directories

        for file_name in file_names:
            path = current_path / file_name
            relative = display_path(path, project_root)
            lower_name = file_name.lower()
            if (
                lower_name in PROJECT_MARKERS
                or path.suffix.lower() in {".sln", ".csproj", ".fsproj"}
            ) and len(marker_files) < 12:
                marker_files.append(relative)
            if path.suffix.lower() in SOURCE_SUFFIXES and len(source_files) < 20:
                source_files.append(relative)
        if len(source_files) >= 20 and len(marker_files) >= 12:
            directory_names[:] = []
    return marker_files, source_files


def check_record(code: str, status: str, summary: str, evidence: list[str]) -> dict[str, Any]:
    return {
        "code": code,
        "status": status,
        "summary": summary,
        "evidence": evidence,
    }


def build_preflight_record(project_root: Path) -> dict[str, Any]:
    blockers: list[str] = []
    checks: list[dict[str, Any]] = []
    marker_files: list[str] = []
    source_files: list[str] = []

    if not project_root.is_dir():
        blockers.append("현재 프로젝트 루트를 찾을 수 없습니다.")
        checks.append(
            check_record(
                "PROJECT_ROOT",
                "fail",
                "현재 프로젝트 루트를 찾을 수 없습니다.",
                [str(project_root)],
            )
        )
    else:
        checks.append(
            check_record(
                "PROJECT_ROOT",
                "pass",
                "현재 프로젝트 루트를 확인했습니다.",
                [str(project_root)],
            )
        )
        marker_files, source_files = discover_project_evidence(project_root)
        if source_files:
            checks.append(
                check_record(
                    "SOURCE_PRESENT",
                    "pass",
                    "툴킷 외부에서 프로젝트 소스를 확인했습니다.",
                    source_files,
                )
            )
        else:
            blockers.append("툴킷 외부에서 프로젝트 소스를 찾지 못했습니다.")
            checks.append(
                check_record(
                    "SOURCE_PRESENT",
                    "fail",
                    "툴킷 외부에서 프로젝트 소스를 찾지 못했습니다.",
                    marker_files,
                )
            )

    pdf_files, spreadsheet_files = input_files()
    count_ok = len(pdf_files) == 1 and len(spreadsheet_files) == 1
    count_evidence = [display_path(path) for path in pdf_files + spreadsheet_files]
    checks.append(
        check_record(
            "INPUT_COUNT",
            "pass" if count_ok else "fail",
            (
                "PDF와 스프레드시트가 각각 하나입니다."
                if count_ok
                else f"PDF {len(pdf_files)}개, 스프레드시트 {len(spreadsheet_files)}개를 확인했습니다."
            ),
            count_evidence,
        )
    )
    if len(pdf_files) != 1:
        blockers.append(f"PDF가 정확히 하나여야 합니다. 현재 {len(pdf_files)}개입니다.")
    if len(spreadsheet_files) != 1:
        blockers.append(
            "스프레드시트가 정확히 하나여야 합니다. "
            f"현재 {len(spreadsheet_files)}개입니다."
        )

    pdf_info = inspect_pdf(pdf_files[0]) if len(pdf_files) == 1 else None
    sheet_info = (
        inspect_spreadsheet(spreadsheet_files[0])
        if len(spreadsheet_files) == 1
        else None
    )
    if pdf_info:
        checks.append(
            check_record(
                "PDF_FORMAT",
                "pass" if pdf_info["formatValid"] else "fail",
                pdf_info["evidence"],
                [pdf_info["path"], f"{pdf_info['size']} bytes"],
            )
        )
        if not pdf_info["formatValid"]:
            blockers.append("PDF 파일 형식이 유효하지 않습니다.")
    if sheet_info:
        checks.append(
            check_record(
                "SPREADSHEET_FORMAT",
                "pass" if sheet_info["formatValid"] else "fail",
                sheet_info["evidence"],
                [sheet_info["path"], f"{sheet_info['size']} bytes"],
            )
        )
        if not sheet_info["formatValid"]:
            blockers.append("스프레드시트 파일 형식이 유효하지 않습니다.")

    if not blockers:
        checks.append(
            check_record(
                "REPORT_CONTENT_READABLE",
                "manual",
                "PDF 가이드와 스프레드시트 검출 목록을 실제로 읽을 수 있는지 확인해야 합니다.",
                [],
            )
        )
        checks.append(
            check_record(
                "SEMANTIC_MATCH",
                "manual",
                "현재 소스와 두 보고서의 프로젝트 및 검사 차수 대조가 필요합니다.",
                [],
            )
        )

    return {
        "schemaVersion": "1.0",
        "status": "blocked" if blockers else "mechanical-ready",
        "checkedAt": utc_now(),
        "project": {
            "root": display_path(project_root),
            "identity": project_root.name if source_files else "",
            "identityEvidence": marker_files + source_files,
        },
        "inputs": {"pdf": pdf_info, "spreadsheet": sheet_info},
        "checks": checks,
        "matching": {
            "sameProject": None,
            "sameRun": None,
            "findingCountConsistent": None,
            "sourceScopeCompatible": None,
            "reason": "",
        },
        "blockers": blockers,
        "notes": [],
    }


def run_preflight(project_root: Path) -> int:
    target = PROJECT_DIR / "INPUT_VALIDATION.md"
    template = PROJECT_DIR / "INPUT_VALIDATION.template.md"
    if not target.exists():
        shutil.copyfile(template, target)
    record = build_preflight_record(project_root)
    (DATA_DIR / "input-validation.json").write_text(
        json_text(record), encoding="utf-8"
    )
    sync_data()
    print(f"PREFLIGHT: {record['status'].upper()}")
    print(f"Project candidate: {record['project']['identity'] or 'not detected'}")
    for input_type in ("pdf", "spreadsheet"):
        input_value = record["inputs"][input_type]
        print(
            f"{input_type}: "
            f"{input_value['path'] if input_value else 'not uniquely identified'}"
        )
    for blocker in record["blockers"]:
        print(f"BLOCKER: {blocker}")
    if not record["blockers"]:
        print("NEXT: compare project and analysis metadata, then run the gate command.")
    return 1 if record["blockers"] else 0


def require_mapping(report: ValidationReport, value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        report.error(f"{name} must be an object")
        return {}
    return value


def require_list(report: ValidationReport, value: Any, name: str) -> list[Any]:
    if not isinstance(value, list):
        report.error(f"{name} must be an array")
        return []
    return value


def validate_input_file_record(
    report: ValidationReport, value: Any, name: str, required: bool
) -> dict[str, Any]:
    if value is None:
        if required:
            report.error(f"{name} is not identified")
        return {}
    input_file = require_mapping(report, value, name)
    if not str(input_file.get("path", "")).strip():
        report.error(f"{name}.path is empty")
    if not isinstance(input_file.get("size"), int) or input_file.get("size", 0) < 0:
        report.error(f"{name}.size must be a non-negative integer")
    if not str(input_file.get("format", "")).strip():
        report.error(f"{name}.format is empty")
    if not isinstance(input_file.get("formatValid"), bool):
        report.error(f"{name}.formatValid must be a boolean")
    if "evidence" not in input_file:
        report.error(f"{name}.evidence is required")
    return input_file


def validate_input_validation(
    report: ValidationReport, value: Any, strict: bool
) -> dict[str, Any]:
    record = require_mapping(report, value, "input validation")
    if record.get("schemaVersion") != "1.0":
        report.error("input validation schemaVersion must be 1.0")
    status = record.get("status")
    if status not in INPUT_VALIDATION_VALUES:
        report.error(f"input validation has invalid status: {status}")
    if strict and status != "ready":
        report.error("input readiness gate is not READY")

    project = require_mapping(report, record.get("project"), "input validation project")
    require_list(
        report,
        project.get("identityEvidence"),
        "input validation project.identityEvidence",
    )
    if status == "ready" and not str(project.get("identity", "")).strip():
        report.error("ready input validation has no project identity")

    inputs = require_mapping(report, record.get("inputs"), "input validation inputs")
    inputs_required = strict or status in {"mechanical-ready", "ready"}
    pdf = validate_input_file_record(
        report, inputs.get("pdf"), "input validation inputs.pdf", inputs_required
    )
    spreadsheet = validate_input_file_record(
        report,
        inputs.get("spreadsheet"),
        "input validation inputs.spreadsheet",
        inputs_required,
    )
    if status == "ready":
        if pdf and pdf.get("formatValid") is not True:
            report.error("ready input validation has an invalid PDF")
        if spreadsheet and spreadsheet.get("formatValid") is not True:
            report.error("ready input validation has an invalid spreadsheet")

    checks = require_list(report, record.get("checks"), "input validation checks")
    check_statuses: dict[str, str] = {}
    for index, raw in enumerate(checks):
        check = require_mapping(report, raw, f"input validation checks[{index}]")
        code = str(check.get("code", "")).strip()
        if not code:
            report.error(f"input validation checks[{index}].code is empty")
        if check.get("status") not in CHECK_VALUES:
            report.error(
                f"input validation check {code} has invalid status: "
                f"{check.get('status')}"
            )
        if "summary" not in check:
            report.error(f"input validation check {code} has no summary")
        require_list(
            report,
            check.get("evidence"),
            f"input validation check {code}.evidence",
        )
        check_statuses[code] = str(check.get("status", ""))

    matching = require_mapping(
        report, record.get("matching"), "input validation matching"
    )
    match_fields = (
        "sameProject",
        "sameRun",
        "findingCountConsistent",
        "sourceScopeCompatible",
    )
    for field in match_fields:
        match_value = matching.get(field)
        if match_value is not True and match_value is not False and match_value is not None:
            report.error(f"input validation matching.{field} must be boolean or null")
    if "reason" not in matching:
        report.error("input validation matching.reason is required")

    blockers = require_list(report, record.get("blockers"), "input validation blockers")
    require_list(report, record.get("notes"), "input validation notes")
    if status == "ready":
        for field in match_fields:
            if matching.get(field) is not True:
                report.error(f"ready input validation has not confirmed matching.{field}")
        if blockers:
            report.error("ready input validation still contains blockers")
        if check_statuses.get("SEMANTIC_MATCH") != "pass":
            report.error("ready input validation has no passed SEMANTIC_MATCH check")
        if check_statuses.get("REPORT_CONTENT_READABLE") != "pass":
            report.error(
                "ready input validation has no passed REPORT_CONTENT_READABLE check"
            )
        if not str(matching.get("reason", "")).strip():
            report.error("ready input validation has no matching reason")
    if status == "blocked" and not blockers:
        report.error("blocked input validation has no blocker reason")
    return record


def validate_required_files(report: ValidationReport) -> None:
    for relative in REQUIRED_FILES:
        if not (ROOT / relative).is_file():
            report.error(f"missing required file: {relative}")


def validate_dashboard(report: ValidationReport) -> None:
    html_path = ROOT / "SECURITY_CHECKLIST.html"
    script_path = ROOT / "assets/checklist.js"
    try:
        html_text = html_path.read_text(encoding="utf-8")
        script_text = script_path.read_text(encoding="utf-8")
    except OSError as error:
        report.error(f"cannot inspect dashboard: {error}")
        return

    parser = DashboardParser()
    parser.feed(html_text)
    referenced_ids = set(re.findall(r'byId\("([^"]+)"\)', script_text))
    for element_id in sorted(referenced_ids.difference(parser.ids)):
        report.error(f"dashboard script references missing element id: {element_id}")
    for asset in sorted(parser.assets):
        clean_asset = asset.split("?", 1)[0]
        if clean_asset.startswith(("http://", "https://", "//")):
            report.error(f"dashboard must not depend on remote asset: {asset}")
        elif not (ROOT / clean_asset).is_file():
            report.error(f"dashboard references missing asset: {asset}")
    if 'id="findings-data"' in html_text:
        report.error("dashboard embeds project findings instead of loading data/findings.js")


def validate_inputs(report: ValidationReport, strict: bool) -> None:
    pdf_files, sheet_files = input_files()
    if len(pdf_files) != 1:
        message = f"input must contain exactly one PDF; found {len(pdf_files)}"
        report.error(message) if strict else report.warn(message)
    if len(sheet_files) != 1:
        message = f"input must contain exactly one spreadsheet; found {len(sheet_files)}"
        report.error(message) if strict else report.warn(message)
    if len(pdf_files) == 1 and not inspect_pdf(pdf_files[0])["formatValid"]:
        message = "input PDF format is invalid"
        report.error(message) if strict else report.warn(message)
    if len(sheet_files) == 1 and not inspect_spreadsheet(sheet_files[0])["formatValid"]:
        message = "input spreadsheet format is invalid"
        report.error(message) if strict else report.warn(message)


def validate_profile(
    report: ValidationReport,
    profile: Any,
    findings: list[Any],
    strict: bool,
    input_validation: dict[str, Any],
) -> str:
    profile_map = require_mapping(report, profile, "project profile")
    if profile_map.get("schemaVersion") != "1.0":
        report.error("project profile schemaVersion must be 1.0")
    workspace_id = str(profile_map.get("workspaceId", ""))
    if strict and (not workspace_id or workspace_id == "uninitialized"):
        report.error("project profile workspaceId is not initialized")
    if strict and not str(profile_map.get("projectName", "")).strip():
        report.error("project profile projectName is empty")
    report_meta = require_mapping(report, profile_map.get("report"), "project profile report")
    finding_count = report_meta.get("findingCount")
    if isinstance(finding_count, int) and finding_count != len(findings):
        report.error(
            f"project profile findingCount is {finding_count}, "
            f"but findings.json contains {len(findings)} item(s)"
        )
    if strict and report_meta.get("inputsMatch") is not True:
        report.error("project profile does not confirm that PDF and spreadsheet match")
    if strict:
        validated_inputs = input_validation.get("inputs", {})
        for profile_field, input_type in (
            ("pdf", "pdf"),
            ("spreadsheet", "spreadsheet"),
        ):
            input_record = validated_inputs.get(input_type)
            if isinstance(input_record, dict) and report_meta.get(
                profile_field
            ) != input_record.get("path"):
                report.error(
                    f"project profile {profile_field} does not match the gated input"
                )
    for field in ("technology", "paths", "validation"):
        require_mapping(report, profile_map.get(field), f"project profile {field}")
    require_list(report, profile_map.get("modules"), "project profile modules")
    require_list(report, profile_map.get("constraints"), "project profile constraints")
    return workspace_id


def validate_severity(report: ValidationReport, value: Any, context: str) -> None:
    severity = require_mapping(report, value, context)
    if severity.get("level") not in SEVERITY_VALUES:
        report.error(f"{context}.level has invalid value: {severity.get('level')}")
    if not isinstance(severity.get("rank"), int):
        report.error(f"{context}.rank must be an integer")
    if "label" not in severity:
        report.error(f"{context}.label is required")


def validate_findings(report: ValidationReport, findings: Any) -> tuple[list[Any], set[str]]:
    finding_list = require_list(report, findings, "findings")
    ids: set[str] = set()
    sequences: set[int] = set()
    for index, raw in enumerate(finding_list):
        item = require_mapping(report, raw, f"findings[{index}]")
        finding_id = str(item.get("id", ""))
        if not finding_id:
            report.error(f"findings[{index}].id is empty")
        elif finding_id in ids:
            report.error(f"duplicate finding id: {finding_id}")
        ids.add(finding_id)
        sequence = item.get("sequence")
        if not isinstance(sequence, int) or sequence < 1:
            report.error(f"finding {finding_id} has invalid sequence")
        elif sequence in sequences:
            report.error(f"duplicate finding sequence: {sequence}")
        sequences.add(sequence)
        validate_severity(report, item.get("risk"), f"finding {finding_id}.risk")
        validate_severity(report, item.get("impact"), f"finding {finding_id}.impact")
        checker = require_mapping(report, item.get("checker"), f"finding {finding_id}.checker")
        if not str(checker.get("code", "")).strip():
            report.error(f"finding {finding_id} checker code is empty")
        location = require_mapping(report, item.get("location"), f"finding {finding_id}.location")
        if not str(location.get("reportedFile", "")).strip():
            report.error(f"finding {finding_id} reportedFile is empty")
        source_mapping = require_mapping(
            report, item.get("sourceMapping"), f"finding {finding_id}.sourceMapping"
        )
        mapping_status = source_mapping.get("status")
        if mapping_status not in MAPPING_VALUES:
            report.error(
                f"finding {finding_id} has invalid source mapping: "
                f"{mapping_status}"
            )
        if mapping_status in FINGERPRINT_REQUIRED_MAPPINGS and not str(
            source_mapping.get("fingerprint", "")
        ).strip():
            report.error(
                f"finding {finding_id} is mapped as {mapping_status} "
                "but sourceMapping.fingerprint is empty; "
                "fingerprints are required for cross-round carry-over"
            )
        if item.get("suggestedConclusion") not in CONCLUSION_VALUES:
            report.error(
                f"finding {finding_id} has invalid suggestedConclusion: "
                f"{item.get('suggestedConclusion')}"
            )
        require_mapping(report, item.get("report"), f"finding {finding_id}.report")
        require_mapping(report, item.get("grouping"), f"finding {finding_id}.grouping")
    return finding_list, ids


def validate_checker_guides(report: ValidationReport, guides: Any, findings: list[Any]) -> None:
    guide_map = require_mapping(report, guides, "checker guides")
    used_codes = {str(item.get("checker", {}).get("code", "")) for item in findings}
    for key, raw in guide_map.items():
        guide = require_mapping(report, raw, f"checker guide {key}")
        if guide.get("code") != key:
            report.error(f"checker guide key {key} does not match its code")
        for field in ("name", "description", "reportGuidance", "reviewNotes"):
            if field not in guide:
                report.error(f"checker guide {key} is missing {field}")
        require_list(report, guide.get("cwe"), f"checker guide {key}.cwe")
        require_list(
            report,
            guide.get("verificationFocus"),
            f"checker guide {key}.verificationFocus",
        )
    missing = sorted(code for code in used_codes if code and code not in guide_map)
    for code in missing:
        report.warn(f"finding checker has no PDF guide record: {code}")


def validate_progress(
    report: ValidationReport,
    progress: Any,
    finding_ids: set[str],
    workspace_id: str,
    strict: bool,
) -> None:
    progress_map = require_mapping(report, progress, "progress")
    if progress_map.get("schemaVersion") != "1.0":
        report.error("progress schemaVersion must be 1.0")
    progress_workspace = str(progress_map.get("workspaceId", ""))
    if workspace_id and progress_workspace != workspace_id:
        report.error("progress workspaceId does not match project profile")
    items = require_mapping(report, progress_map.get("items"), "progress items")
    for finding_id, raw in items.items():
        if finding_id not in finding_ids:
            report.error(f"progress contains unknown finding id: {finding_id}")
        item = require_mapping(report, raw, f"progress item {finding_id}")
        if item.get("workflowStatus") not in WORKFLOW_VALUES:
            report.error(f"progress item {finding_id} has invalid workflowStatus")
        if item.get("conclusion") not in CONCLUSION_VALUES:
            report.error(f"progress item {finding_id} has invalid conclusion")
        if "note" not in item:
            report.error(f"progress item {finding_id} is missing note")
    if strict:
        missing = sorted(finding_ids.difference(items.keys()))
        for finding_id in missing:
            report.warn(f"progress has no explicit entry for finding: {finding_id}")


def validate_record_files(
    report: ValidationReport,
    directory: Path,
    finding_ids: set[str],
    record_type: str,
) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for path in iter_record_json(directory):
        try:
            value = load_json(path)
        except (OSError, json.JSONDecodeError) as error:
            report.error(f"cannot read {path.relative_to(ROOT)}: {error}")
            continue
        item = require_mapping(report, value, str(path.relative_to(ROOT)))
        finding_id = str(item.get("id", ""))
        if not finding_id:
            report.error(f"{path.relative_to(ROOT)} has no id")
            continue
        if finding_id != path.stem:
            report.error(f"{path.relative_to(ROOT)} id does not match filename")
        if finding_id not in finding_ids:
            report.error(f"{path.relative_to(ROOT)} references unknown finding id")
        if finding_id in values:
            report.error(f"duplicate {record_type} record for {finding_id}")
        values[finding_id] = item
        if record_type == "result":
            workflow = item.get("workflowStatus")
            conclusion = item.get("conclusion")
            if workflow not in WORKFLOW_VALUES:
                report.error(f"result {finding_id} has invalid workflowStatus")
            if conclusion not in CONCLUSION_VALUES:
                report.error(f"result {finding_id} has invalid conclusion")
            verification = require_mapping(
                report, item.get("verification"), f"result {finding_id}.verification"
            )
            if verification.get("status") not in VERIFICATION_VALUES:
                report.error(f"result {finding_id} has invalid verification status")
            if workflow == "verified" and verification.get("status") != "passed":
                report.error(
                    f"result {finding_id} is verified without passed verification"
                )
            if conclusion != "unreviewed" and not str(item.get("reason", "")).strip():
                report.error(f"result {finding_id} conclusion has no reason")
            if conclusion in {"false-positive", "exception", "operations"} and not str(
                item.get("evidenceNote", "")
            ).strip():
                report.error(f"result {finding_id} has no evidence note")
        else:
            if item.get("sourceMapping") not in MAPPING_VALUES:
                report.error(f"item guide {finding_id} has invalid sourceMapping")
            for field in ("steps", "checkpoints", "impact", "testPlan", "policyQuestions"):
                require_list(report, item.get(field), f"item guide {finding_id}.{field}")
    return values


def validate_mirrors(report: ValidationReport, guide_values: dict[str, Any], result_values: dict[str, Any]) -> None:
    for filename, property_name in DATA_MIRRORS.items():
        json_path = DATA_DIR / f"{filename}.json"
        js_path = DATA_DIR / f"{filename}.js"
        try:
            expected = data_mirror_text(property_name, load_json(json_path))
            actual = js_path.read_text(encoding="utf-8")
            if actual != expected:
                report.error(f"JavaScript mirror is stale: {js_path.relative_to(ROOT)}")
        except OSError as error:
            report.error(f"cannot verify mirror {js_path.relative_to(ROOT)}: {error}")

    for directory, namespace, values in (
        (GUIDE_DIR, "SAST_ITEM_GUIDES", guide_values),
        (RESULT_DIR, "SAST_ITEM_RESULTS", result_values),
    ):
        index_json = directory / "index.json"
        index_js = directory / "index.js"
        if not index_json.exists():
            report.error(f"missing generated index: {index_json.relative_to(ROOT)}")
        elif load_json(index_json) != values:
            report.error(f"generated index is stale: {index_json.relative_to(ROOT)}")
        expected_index = index_mirror_text(namespace, values)
        if not index_js.exists() or index_js.read_text(encoding="utf-8") != expected_index:
            report.error(f"generated index is stale: {index_js.relative_to(ROOT)}")
        for finding_id, value in values.items():
            mirror = directory / f"{finding_id}.js"
            expected = item_mirror_text(namespace, finding_id, value)
            if not mirror.exists() or mirror.read_text(encoding="utf-8") != expected:
                report.error(f"record mirror is stale: {mirror.relative_to(ROOT)}")


def compare_current_preflight(
    report: ValidationReport,
    recorded: dict[str, Any],
    mechanical: dict[str, Any],
) -> None:
    current_project = mechanical.get("project", {})
    recorded_project = recorded.get("project", {})
    if recorded_project.get("root") != current_project.get("root"):
        report.error("input validation project root differs from current project root")
    current_inputs = mechanical.get("inputs", {})
    recorded_inputs = recorded.get("inputs", {})
    for input_type in ("pdf", "spreadsheet"):
        current = current_inputs.get(input_type)
        recorded_input = recorded_inputs.get(input_type)
        if not current or not isinstance(recorded_input, dict):
            continue
        for field in ("path", "size", "format", "formatValid"):
            if recorded_input.get(field) != current.get(field):
                report.error(
                    f"recorded {input_type}.{field} differs from the current input"
                )


def run_gate(project_root: Path) -> int:
    report = ValidationReport()
    mechanical = build_preflight_record(project_root)
    for blocker in mechanical["blockers"]:
        report.error(f"mechanical preflight failed: {blocker}")
    try:
        record = load_json(DATA_DIR / "input-validation.json")
        validated = validate_input_validation(report, record, True)
        compare_current_preflight(report, validated, mechanical)
        sync_data()
    except (OSError, json.JSONDecodeError) as error:
        report.error(f"cannot load input readiness record: {error}")
    report.print()
    if report.errors:
        print("GATE: BLOCKED")
        return 1
    print("GATE: READY")
    return 0


def validate_schema_enums(report: ValidationReport) -> None:
    value_sets = {
        "WORKFLOW_VALUES": WORKFLOW_VALUES,
        "CONCLUSION_VALUES": CONCLUSION_VALUES,
        "MAPPING_VALUES": MAPPING_VALUES,
        "SEVERITY_VALUES": SEVERITY_VALUES,
        "VERIFICATION_VALUES": VERIFICATION_VALUES,
        "INPUT_VALIDATION_VALUES": INPUT_VALIDATION_VALUES,
        "CHECK_VALUES": CHECK_VALUES,
    }
    for relative, pointer, set_name in SCHEMA_ENUM_CHECKS:
        path = ROOT / relative
        try:
            node: Any = load_json(path)
        except (OSError, json.JSONDecodeError) as error:
            report.error(f"cannot read schema {relative}: {error}")
            continue
        for segment in pointer:
            if not isinstance(node, dict) or segment not in node:
                report.error(
                    f"schema {relative} is missing enum at /{'/'.join(pointer)}"
                )
                node = None
                break
            node = node[segment]
        if node is None:
            continue
        if not isinstance(node, list) or set(node) != value_sets[set_name]:
            report.error(
                f"schema {relative} enum at /{'/'.join(pointer)} "
                f"does not match validator {set_name}"
            )


def validate_progress_result_consistency(
    report: ValidationReport,
    progress: Any,
    result_values: dict[str, Any],
) -> None:
    progress_map = require_mapping(report, progress, "progress")
    items = progress_map.get("items")
    if not isinstance(items, dict):
        return
    for finding_id, result in result_values.items():
        progress_item = items.get(finding_id)
        if not isinstance(progress_item, dict):
            report.error(
                f"result exists for {finding_id} but progress has no entry"
            )
            continue
        for field in ("workflowStatus", "conclusion"):
            if progress_item.get(field) != result.get(field):
                report.error(
                    f"progress and result disagree on {finding_id}.{field}: "
                    f"progress={progress_item.get(field)}, "
                    f"result={result.get(field)}; "
                    "security-results is canonical, update data/progress.json"
                )


def validate_all(strict: bool, project_root: Path) -> int:
    report = ValidationReport()
    validate_required_files(report)
    validate_schema_enums(report)
    validate_dashboard(report)
    validate_inputs(report, strict)
    try:
        input_validation = load_json(DATA_DIR / "input-validation.json")
        validated_input = validate_input_validation(report, input_validation, strict)
        if strict:
            mechanical = build_preflight_record(project_root)
            for blocker in mechanical["blockers"]:
                report.error(f"mechanical preflight failed: {blocker}")
            compare_current_preflight(report, validated_input, mechanical)
        findings_raw = load_json(DATA_DIR / "findings.json")
        findings, finding_ids = validate_findings(report, findings_raw)
        profile = load_json(DATA_DIR / "project-profile.json")
        workspace_id = validate_profile(
            report, profile, findings, strict, validated_input
        )
        guides = load_json(DATA_DIR / "checker-guides.json")
        validate_checker_guides(report, guides, findings)
        progress = load_json(DATA_DIR / "progress.json")
        validate_progress(report, progress, finding_ids, workspace_id, strict)
        guide_values = validate_record_files(
            report, GUIDE_DIR, finding_ids, "guide"
        )
        result_values = validate_record_files(
            report, RESULT_DIR, finding_ids, "result"
        )
        validate_progress_result_consistency(report, progress, result_values)
        validate_mirrors(report, guide_values, result_values)
    except (OSError, json.JSONDecodeError) as error:
        report.error(f"cannot load toolkit data: {error}")
    report.print()
    return 1 if report.errors else 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check inputs, initialize, synchronize, and validate SAST toolkit data."
    )
    parser.add_argument(
        "command", choices=("preflight", "gate", "init", "sync", "validate")
    )
    parser.add_argument(
        "--project-root",
        help="Project root to inspect. Defaults to the toolkit parent directory.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat uninitialized project inputs and metadata as errors.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    project_root = (
        Path(args.project_root).expanduser().resolve()
        if args.project_root
        else ROOT.parent.resolve()
    )
    if args.command == "preflight":
        return run_preflight(project_root)
    if args.command == "gate":
        return run_gate(project_root)
    if args.command == "init":
        return initialize(project_root)
    if args.command == "sync":
        sync_all()
        return 0
    return validate_all(args.strict, project_root)


if __name__ == "__main__":
    sys.exit(main())
