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
SARIF_SUFFIXES = {".sarif"}
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

# 산출물 스키마 버전. breaking 변경 시 여기 한 곳만 올리면 검증기 전체가
# 따라간다. schemas/*.json의 const 값과 반드시 같아야 한다.
# (docs/VERSIONING.md 참조)
SCHEMA_VERSION = "1.0"

# checker-guides.json은 code -> guide 맵이라 최상위에 schemaVersion을 둘
# 자리가 없다. 필드를 넣으려면 {schemaVersion, guides} 로 감싸야 하고
# 이는 breaking 변경이므로 다음 메이저로 미룬다.

# 스키마 파일의 schemaVersion const가 위 상수와 어긋나지 않도록 교차
# 검증한다. (schema path, JSON pointer segments)
# checker-guides.schema.json은 schemaVersion을 갖지 않아 제외한다.
SCHEMA_VERSION_CHECKS = (
    ("schemas/findings.schema.json", ("items", "properties", "schemaVersion", "const")),
    ("schemas/input-validation.schema.json", ("properties", "schemaVersion", "const")),
    ("schemas/item-guide.schema.json", ("properties", "schemaVersion", "const")),
    ("schemas/progress.schema.json", ("properties", "schemaVersion", "const")),
    ("schemas/project-profile.schema.json", ("properties", "schemaVersion", "const")),
    ("schemas/result.schema.json", ("properties", "schemaVersion", "const")),
)

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
    "templates/evidence-columns.md",
    "docs/HOW_IT_WORKS.md",
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

    def schema_version(self, value: Any, context: str, level: str) -> None:
        """산출물의 schemaVersion을 확인한다.

        level="error"는 초기화 시점부터 필드가 보장된 단일 파일 산출물,
        level="warn"은 구버전 산출물이 남아 있을 수 있는 레코드류에 쓴다.
        경고 단계는 다음 메이저에서 에러로 올린다 (docs/VERSIONING.md).
        """
        found = value.get("schemaVersion") if isinstance(value, dict) else None
        if found == SCHEMA_VERSION:
            return
        detail = "is missing" if found is None else f"is {found!r}"
        message = (
            f"{context} schemaVersion {detail}; expected {SCHEMA_VERSION!r}"
        )
        if level == "error":
            self.error(message)
        else:
            self.warn(f"{message} (migration may be needed)")

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


def write_text_atomic(path: Path, content: str) -> None:
    """중단 시 반쪽 파일이 남지 않도록 임시 파일에 쓴 뒤 교체한다."""
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    os.replace(tmp, path)


def load_json_or_exit(path: Path) -> Any:
    try:
        return load_json(path)
    except (OSError, json.JSONDecodeError) as error:
        print(f"SYNC ERROR: cannot read {display_path(path)}: {error}")
        print(
            "The file is likely half-written from an interrupted session. "
            "Restore or rewrite this file, then run sync again. "
            "If it is data/progress.json, it can be rebuilt from "
            "security-results/."
        )
        raise SystemExit(1)


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
        value = load_json_or_exit(json_path)
        write_text_atomic(
            DATA_DIR / f"{filename}.js", data_mirror_text(property_name, value)
        )


def sync_records(directory: Path, namespace: str) -> None:
    values: dict[str, Any] = {}
    for json_path in iter_record_json(directory):
        value = load_json_or_exit(json_path)
        finding_id = str(value.get("id", json_path.stem))
        values[finding_id] = value
        write_text_atomic(
            json_path.with_suffix(".js"),
            item_mirror_text(namespace, finding_id, value),
        )
    write_text_atomic(directory / "index.json", json_text(values))
    write_text_atomic(directory / "index.js", index_mirror_text(namespace, values))


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


def candidate_files(base: Path) -> tuple[list[Path], list[Path], list[Path]]:
    if not base.is_dir():
        return [], [], []
    pdf_files = [
        path
        for path in base.iterdir()
        if path.is_file() and path.suffix.lower() == ".pdf"
    ]
    spreadsheet_files = [
        path
        for path in base.iterdir()
        if path.is_file() and path.suffix.lower() in SPREADSHEET_SUFFIXES
    ]
    sarif_files = [
        path
        for path in base.iterdir()
        if path.is_file() and path.suffix.lower() in SARIF_SUFFIXES
    ]
    return sorted(pdf_files), sorted(spreadsheet_files), sorted(sarif_files)


def discover_input_sets() -> dict[str, tuple[list[Path], list[Path], list[Path]]]:
    """input/의 하위 폴더 중 후보 파일이 있는 것을 리포트 세트로 본다."""
    sets: dict[str, tuple[list[Path], list[Path], list[Path]]] = {}
    if not INPUT_DIR.is_dir():
        return sets
    for entry in sorted(INPUT_DIR.iterdir()):
        if entry.is_dir():
            files = candidate_files(entry)
            if any(files):
                sets[entry.name] = files
    return sets


def resolve_input_set(
    input_set: str | None,
) -> tuple[str | None, tuple[list[Path], list[Path], list[Path]], list[str]]:
    """활성 세트 선택. 반환: (세트명 또는 None=루트, 파일들, 차단 사유들)"""
    root_files = candidate_files(INPUT_DIR)
    sets = discover_input_sets()
    if input_set:
        if input_set not in sets:
            return input_set, ([], [], []), [
                f"입력 세트 '{input_set}' 폴더가 input/ 아래에 없거나 비어 있습니다. "
                f"사용 가능한 세트: {', '.join(sets) if sets else '없음'}"
            ]
        return input_set, sets[input_set], []
    if any(root_files):
        if sets:
            return None, root_files, [
                "input/ 루트 파일과 세트 폴더가 혼재합니다. 루트 파일을 세트 폴더로 "
                f"옮기거나 하나만 남기세요. 세트: {', '.join(sets)}"
            ]
        return None, root_files, []
    if len(sets) == 1:
        name = next(iter(sets))
        return name, sets[name], []
    if len(sets) > 1:
        return None, ([], [], []), [
            "입력 세트가 여러 개입니다. --input-set <이름>으로 이번 차수에 사용할 "
            f"세트를 지정하세요. 세트: {', '.join(sets)}"
        ]
    return None, ([], [], []), []


def input_files(
    input_set: str | None = None,
) -> tuple[list[Path], list[Path], list[Path]]:
    _, files, _ = resolve_input_set(input_set)
    return files


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


def inspect_sarif(path: Path) -> dict[str, Any]:
    try:
        size = path.stat().st_size
    except OSError as error:
        return {
            "path": display_path(path),
            "size": 0,
            "format": "sarif",
            "formatValid": False,
            "evidence": f"SARIF를 읽을 수 없습니다: {error}",
        }
    valid = False
    evidence = "SARIF 구조를 확인할 수 없습니다."
    try:
        record = json.loads(path.read_text(encoding="utf-8-sig"))
        valid = (
            isinstance(record, dict)
            and isinstance(record.get("version"), str)
            and isinstance(record.get("runs"), list)
            and len(record["runs"]) > 0
        )
        evidence = (
            f"SARIF version {record.get('version')} / runs {len(record.get('runs', []))}개 확인"
            if valid
            else "확장자는 .sarif이지만 version 또는 runs 구조가 없습니다."
        )
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as error:
        evidence = f"SARIF를 파싱할 수 없습니다: {error}"
    return {
        "path": display_path(path),
        "size": size,
        "format": "sarif",
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


def build_preflight_record(project_root: Path, input_set: str | None = None) -> dict[str, Any]:
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

    selected_set, (pdf_files, spreadsheet_files, sarif_files), set_blockers = (
        resolve_input_set(input_set)
    )
    for blocker in set_blockers:
        blockers.append(blocker)
        checks.append(check_record("INPUT_SET", "fail", blocker, []))
    if selected_set and not set_blockers:
        checks.append(
            check_record(
                "INPUT_SET",
                "pass",
                f"입력 세트 '{selected_set}'을 사용합니다.",
                [f"input/{selected_set}/"],
            )
        )
    # 입력 모드: vendor(PDF 1개 이상 + 스프레드시트 1) 또는 sarif(SARIF 1, PDF 선택)
    # PDF 다건은 벤더가 대용량 보고서를 _01, _02로 분할 내보내는 경우이며,
    # 같은 분석 차수인지는 의미 대조 단계에서 분석 ID로 확인한다.
    vendor_mode = len(spreadsheet_files) == 1 and len(sarif_files) == 0
    sarif_mode = len(sarif_files) == 1 and len(spreadsheet_files) == 0
    count_ok = (
        (vendor_mode and len(pdf_files) >= 1)
        or (sarif_mode and len(pdf_files) <= 1)
    )
    count_evidence = [
        display_path(path) for path in pdf_files + spreadsheet_files + sarif_files
    ]
    checks.append(
        check_record(
            "INPUT_COUNT",
            "pass" if count_ok else "fail",
            (
                (
                    f"PDF {len(pdf_files)}개와 스프레드시트 하나입니다."
                    if vendor_mode
                    else "SARIF 하나를 확인했습니다."
                )
                if count_ok
                else (
                    f"PDF {len(pdf_files)}개, 스프레드시트 {len(spreadsheet_files)}개, "
                    f"SARIF {len(sarif_files)}개를 확인했습니다."
                )
            ),
            count_evidence,
        )
    )
    if not count_ok:
        blockers.append(
            "입력은 'PDF 1개 이상 + 스프레드시트 1개' 또는 'SARIF 1개(PDF 선택)' 조합이어야 합니다. "
            f"현재 PDF {len(pdf_files)}개, 스프레드시트 {len(spreadsheet_files)}개, "
            f"SARIF {len(sarif_files)}개입니다."
        )

    pdf_info = None
    if pdf_files:
        pdf_reports = [inspect_pdf(path) for path in pdf_files]
        pdf_info = dict(pdf_reports[0])
        pdf_info["size"] = sum(item["size"] for item in pdf_reports)
        pdf_info["formatValid"] = all(item["formatValid"] for item in pdf_reports)
        if len(pdf_reports) > 1:
            pdf_info["evidence"] = (
                f"분할 PDF {len(pdf_reports)}개(크기 합계 기준). "
                + "; ".join(item["evidence"] for item in pdf_reports[:3])
            )
    sheet_info = (
        inspect_spreadsheet(spreadsheet_files[0])
        if len(spreadsheet_files) == 1
        else None
    )
    sarif_info = inspect_sarif(sarif_files[0]) if len(sarif_files) == 1 else None
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
    if sarif_info:
        checks.append(
            check_record(
                "SARIF_FORMAT",
                "pass" if sarif_info["formatValid"] else "fail",
                sarif_info["evidence"],
                [sarif_info["path"], f"{sarif_info['size']} bytes"],
            )
        )
        if not sarif_info["formatValid"]:
            blockers.append("SARIF 파일 형식이 유효하지 않습니다.")

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
        "inputs": {
            "set": selected_set,
            "pdf": pdf_info,
            "spreadsheet": sheet_info,
            "sarif": sarif_info,
        },
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


def run_preflight(project_root: Path, input_set: str | None = None) -> int:
    target = PROJECT_DIR / "INPUT_VALIDATION.md"
    template = PROJECT_DIR / "INPUT_VALIDATION.template.md"
    if not target.exists():
        shutil.copyfile(template, target)
    record = build_preflight_record(project_root, input_set)
    write_text_atomic(DATA_DIR / "input-validation.json", json_text(record))
    sync_data()
    print(f"PREFLIGHT: {record['status'].upper()}")
    print(f"Project candidate: {record['project']['identity'] or 'not detected'}")
    for input_type in ("pdf", "spreadsheet", "sarif"):
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
    report.schema_version(record, "input validation", "error")
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
    sarif = validate_input_file_record(
        report, inputs.get("sarif"), "input validation inputs.sarif", False
    )
    sarif_present = bool(sarif)
    if sarif_present:
        # SARIF 모드: 스프레드시트는 없어야 하고 PDF는 선택
        inputs_required = False
        if inputs.get("spreadsheet") is not None:
            report.error(
                "input validation cannot combine sarif and spreadsheet inputs"
            )
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
    recorded_set = None
    try:
        recorded_set = (
            load_json(DATA_DIR / "input-validation.json")
            .get("inputs", {})
            .get("set")
        )
    except (OSError, json.JSONDecodeError, AttributeError):
        recorded_set = None
    pdf_files, sheet_files, sarif_files = input_files(recorded_set)
    vendor_mode = len(sheet_files) == 1 and len(sarif_files) == 0
    sarif_mode = len(sarif_files) == 1 and len(sheet_files) == 0
    count_ok = (
        (vendor_mode and len(pdf_files) >= 1)
        or (sarif_mode and len(pdf_files) <= 1)
    )
    if not count_ok:
        message = (
            "input must be one or more PDFs plus one spreadsheet, "
            "or exactly one SARIF (PDF optional); found "
            f"{len(pdf_files)} PDF, {len(sheet_files)} spreadsheet, "
            f"{len(sarif_files)} SARIF"
        )
        report.error(message) if strict else report.warn(message)
    for pdf_path in pdf_files:
        if not inspect_pdf(pdf_path)["formatValid"]:
            message = f"input PDF format is invalid: {display_path(pdf_path)}"
            report.error(message) if strict else report.warn(message)
    if len(sheet_files) == 1 and not inspect_spreadsheet(sheet_files[0])["formatValid"]:
        message = "input spreadsheet format is invalid"
        report.error(message) if strict else report.warn(message)
    if len(sarif_files) == 1 and not inspect_sarif(sarif_files[0])["formatValid"]:
        message = "input SARIF format is invalid"
        report.error(message) if strict else report.warn(message)


def validate_profile(
    report: ValidationReport,
    profile: Any,
    findings: list[Any],
    strict: bool,
    input_validation: dict[str, Any],
) -> str:
    profile_map = require_mapping(report, profile, "project profile")
    report.schema_version(profile_map, "project profile", "error")
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
        report.error(
            "project profile does not confirm that the gated inputs match "
            "the current source"
        )
    if strict:
        validated_inputs = input_validation.get("inputs", {})
        for profile_field, input_type in (
            ("pdf", "pdf"),
            ("spreadsheet", "spreadsheet"),
            ("sarif", "sarif"),
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
        report.schema_version(item, f"findings[{index}]", "warn")
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
    report.schema_version(progress_map, "progress", "error")
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
        report.schema_version(
            item, f"{record_type} record {finding_id}", "warn"
        )
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
            if workflow == "verified" and not str(
                verification.get("method", "")
            ).strip():
                report.warn(
                    f"result {finding_id} is verified but verification.method "
                    "is empty; record which means (build/lint/unit-test/...) "
                    "was used"
                )
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
    if recorded_inputs.get("set") != current_inputs.get("set"):
        report.error(
            "input validation set differs from the current input set "
            f"(recorded={recorded_inputs.get('set')}, current={current_inputs.get('set')})"
        )
    for input_type in ("pdf", "spreadsheet", "sarif"):
        current = current_inputs.get(input_type)
        recorded_input = recorded_inputs.get(input_type)
        recorded_present = isinstance(recorded_input, dict) and bool(recorded_input)
        if bool(current) != recorded_present:
            report.error(
                f"recorded {input_type} presence differs from the current input "
                f"(recorded={'present' if recorded_present else 'absent'}, "
                f"current={'present' if current else 'absent'})"
            )
            continue
        if not current:
            continue
        for field in ("path", "size", "format", "formatValid"):
            if recorded_input.get(field) != current.get(field):
                report.error(
                    f"recorded {input_type}.{field} differs from the current input"
                )


def run_gate(project_root: Path) -> int:
    report = ValidationReport()
    recorded_set = None
    try:
        recorded_set = (
            load_json(DATA_DIR / "input-validation.json")
            .get("inputs", {})
            .get("set")
        )
    except (OSError, json.JSONDecodeError, AttributeError):
        recorded_set = None
    mechanical = build_preflight_record(project_root, recorded_set)
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


def validate_schema_versions(report: ValidationReport) -> None:
    """스키마 파일의 schemaVersion const와 SCHEMA_VERSION 상수를 대조한다.

    breaking 변경 때 한쪽만 올리면 정상 산출물이 전부 불일치로 잡히므로,
    문서 지침 대신 여기서 기계적으로 막는다 (docs/VERSIONING.md).
    """
    for relative, pointer in SCHEMA_VERSION_CHECKS:
        path = ROOT / relative
        try:
            node: Any = load_json(path)
        except (OSError, json.JSONDecodeError) as error:
            report.error(f"cannot read schema {relative}: {error}")
            continue
        for segment in pointer:
            if not isinstance(node, dict) or segment not in node:
                report.error(
                    f"schema {relative} is missing schemaVersion const at "
                    f"/{'/'.join(pointer)}"
                )
                node = None
                break
            node = node[segment]
        if node is None:
            continue
        if node != SCHEMA_VERSION:
            report.error(
                f"schema {relative} schemaVersion const is {node!r} but "
                f"validator SCHEMA_VERSION is {SCHEMA_VERSION!r}"
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
    validate_schema_versions(report)
    validate_dashboard(report)
    validate_inputs(report, strict)
    def load_data(relative: str) -> Any:
        try:
            return load_json(DATA_DIR / relative)
        except (OSError, json.JSONDecodeError) as error:
            report.error(
                f"cannot read data/{relative}: {error} "
                "(likely half-written from an interrupted session)"
            )
            return None

    try:
        input_validation = load_data("input-validation.json")
        validated_input = (
            validate_input_validation(report, input_validation, strict)
            if input_validation is not None
            else {}
        )
        if strict:
            mechanical = build_preflight_record(
                project_root,
                validated_input.get("inputs", {}).get("set"),
            )
            for blocker in mechanical["blockers"]:
                report.error(f"mechanical preflight failed: {blocker}")
            compare_current_preflight(report, validated_input, mechanical)
        findings_raw = load_data("findings.json")
        findings, finding_ids = (
            validate_findings(report, findings_raw)
            if findings_raw is not None
            else ([], set())
        )
        profile = load_data("project-profile.json")
        workspace_id = (
            validate_profile(report, profile, findings, strict, validated_input)
            if profile is not None
            else ""
        )
        guides = load_data("checker-guides.json")
        if guides is not None:
            validate_checker_guides(report, guides, findings)
        progress = load_data("progress.json")
        if progress is not None:
            validate_progress(report, progress, finding_ids, workspace_id, strict)
        guide_values = validate_record_files(
            report, GUIDE_DIR, finding_ids, "guide"
        )
        result_values = validate_record_files(
            report, RESULT_DIR, finding_ids, "result"
        )
        if progress is not None:
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
        "--input-set",
        help="Report set folder under input/ to use when multiple sets exist.",
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
        return run_preflight(project_root, args.input_set)
    if args.command == "gate":
        return run_gate(project_root)
    if args.command == "init":
        return initialize(project_root)
    if args.command == "sync":
        sync_all()
        return 0
    return validate_all(args.strict, project_root)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        sys.exit(0)
