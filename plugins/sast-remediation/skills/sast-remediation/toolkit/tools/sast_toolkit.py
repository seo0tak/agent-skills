#!/usr/bin/env python3
"""Synchronize and validate the universal SAST remediation toolkit."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import zipfile
from datetime import datetime, timezone
from functools import lru_cache
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterable

try:
    from .sast_io import writer_lock, write_text_atomic
except ImportError:
    from sast_io import writer_lock, write_text_atomic


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
RESULT_REQUIRED_WORKFLOWS = {"change-complete", "verified"}

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
    ("schemas/decisions.schema.json", ("properties", "schemaVersion", "const")),
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
    (
        "schemas/decisions.schema.json",
        ("properties", "decisions", "items", "properties", "decidedBy", "enum"),
        "DECIDED_BY_VALUES",
    ),
)

DATA_MIRRORS = {
    "input-validation": "inputValidation",
    "project-profile": "projectProfile",
    "findings": "findings",
    "checker-guides": "checkerGuides",
    "progress": "progress",
}

# 결정 로그. 정본은 data/decisions.json이고 project/DECISION_LOG.md는
# sync가 생성하는 읽기용 미러다 (JSON=기록, md=미러). 1.8.0 이전 프로젝트의
# 손으로 쓴 DECISION_LOG.md는 덮어쓰지 않고 마이그레이션을 안내한다.
DECISIONS_FILE = DATA_DIR / "decisions.json"
DECISIONS_MIRROR = DATA_DIR / "decisions.js"
DECISION_LOG_FILE = PROJECT_DIR / "DECISION_LOG.md"
GENERATED_MARKER = "<!-- generated by sast_toolkit.py sync"
DECIDED_BY_VALUES = {"user", "baseline-default", "choice-irrelevant", "deferred"}
DECIDED_BY_LABELS = {
    "user": "사용자 확인",
    "baseline-default": "기본안 적용(미확인)",
    "choice-irrelevant": "선택 무관",
    "deferred": "보류",
}

# USAGE.html도 같은 원리로 USAGE.md에서 생성한다.
USAGE_MD = ROOT / "USAGE.md"
USAGE_HTML = ROOT / "USAGE.html"
USAGE_CSS = "assets/usage.css"  # 생성 시 USAGE.html에 인라인되는 스타일 원본

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
    "assets/usage.css",
    "tools/sast_io.py",
    "tools/sast_state.py",
    "tools/usage_renderer.py",
    "schemas/decisions.schema.json",
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


def load_json_or_exit(path: Path) -> Any:
    try:
        return load_json(path)
    except (OSError, json.JSONDecodeError) as error:
        print(f"SYNC ERROR: cannot read {display_path(path)}: {error}")
        print(
            "The file may be incomplete or malformed. Preserve the original and "
            "inspect the reported error before restoring or rewriting it, then run sync again. "
            "For data/progress.json, preview tools/sast_state.py recover-progress "
            "before applying recovery; results alone cannot restore provisional notes."
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


def flat_text(value: Any) -> str:
    """md 목록 항목 한 줄에 넣기 위해 줄바꿈을 공백으로 접는다."""
    if isinstance(value, list):
        return "; ".join(flat_text(item) for item in value if str(item).strip())
    return " ".join(str(value or "").split())


def render_decision_log(record: dict[str, Any]) -> str:
    """정책 결정 데이터를 날짜별로 묶어 최신 기록부터 Markdown으로 표시한다."""
    decisions = [d for d in (record.get("decisions") or []) if isinstance(d, dict)]
    decisions.sort(
        key=lambda d: (str(d.get("decidedAt", "")), str(d.get("id", ""))),
        reverse=True,
    )
    lines = [
        "---",
        "type: sast/decision-log",
        "title: 정책 결정 기록",
        "description: 정책 질문과 답, 결정 주체, 근거, 관찰 방법과 재검토 조건의 시간순 기록",
        f"timestamp: {record.get('updatedAt') or ''}",
        "tags: [sast, decisions]",
        "---",
        "",
        GENERATED_MARKER + " from data/decisions.json. 직접 편집하지 말고 "
        "data/decisions.json을 고친 뒤 sync를 실행한다. -->",
        "",
        "# 정책 결정 기록",
        "",
        "정본은 `data/decisions.json`입니다. 이 문서는 `sync`가 생성하며 최신 결정부터 표시합니다.",
        "",
        "`결정 주체`가 \"기본안 적용(미확인)\"인 항목에는 관찰 방법과 재검토 조건을 "
        "기록해야 합니다. `validate`는 필요한 기록을 검사하며, 실제 관찰 방법의 동작이나 "
        "사용자 승인을 인증하지는 않습니다.",
        "",
    ]
    if not decisions:
        lines += ["아직 기록된 결정이 없습니다.", ""]
    current_date = None
    for d in decisions:
        date = str(d.get("decidedAt", ""))[:10] or "날짜 없음"
        if date != current_date:
            lines += [f"## {date}", ""]
            current_date = date
        lines += [f"### {flat_text(d.get('id'))} — {flat_text(d.get('topic'))}", ""]
        by = str(d.get("decidedBy", ""))
        rows = (
            ("결정 주체", DECIDED_BY_LABELS.get(by, by)),
            ("질문", flat_text(d.get("question"))),
            ("추천안", flat_text(d.get("recommendation"))),
            ("결정 내용", flat_text(d.get("decision"))),
            ("적용 범위", flat_text(d.get("scope"))),
            ("근거", flat_text(d.get("rationale"))),
            ("확인한 소스·명세·증거", flat_text(d.get("evidence"))),
            ("영향받는 체커", ", ".join(str(c) for c in d.get("checkers") or [])),
            ("관련 검출", ", ".join(str(c) for c in d.get("findingIds") or [])),
            ("확인 담당자", flat_text(d.get("answerableBy"))),
            ("예외", flat_text(d.get("exceptions"))),
            ("관찰 방법", flat_text(d.get("observation"))),
            ("재검토 조건", flat_text(d.get("reviewTrigger"))),
        )
        for label, value in rows:
            if value:
                lines.append(f"- {label}: {value}")
        lines.append("")
    return "\n".join(lines)


def sync_decisions() -> None:
    if not DECISIONS_FILE.exists():
        print(
            "Note: data/decisions.json not found; DECISION_LOG.md was not "
            "regenerated. Run `init` to create it."
        )
        return
    record = load_json_or_exit(DECISIONS_FILE)
    write_text_atomic(DECISIONS_MIRROR, data_mirror_text("decisions", record))
    if DECISION_LOG_FILE.exists():
        existing = DECISION_LOG_FILE.read_text(encoding="utf-8")
        if GENERATED_MARKER not in existing:
            print(
                "Note: project/DECISION_LOG.md is hand-written and was left "
                "untouched. Back up the original, verify each entry's provenance, "
                "then migrate it into data/decisions.json. Move the old Markdown out "
                "of this generated path before sync (docs/VERSIONING.md)."
            )
            return
    write_text_atomic(DECISION_LOG_FILE, render_decision_log(record))


# ---- USAGE.md → USAGE.html (최소 마크다운 렌더러, 표준 라이브러리만) ----

def html_escape(text: str) -> str:
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    )


def render_inline(text: str) -> str:
    try:
        from .usage_renderer import render_inline as render
    except ImportError:
        from usage_renderer import render_inline as render
    return render(text)


def render_usage_html(markdown: str) -> str:
    try:
        from .usage_renderer import render_usage_html as render
    except ImportError:
        from usage_renderer import render_usage_html as render
    css_path = ROOT / USAGE_CSS
    css = css_path.read_text(encoding="utf-8") if css_path.exists() else ""
    return render(markdown, css=css, generated_marker=GENERATED_MARKER)


def sync_usage() -> None:
    if not USAGE_MD.exists():
        return
    write_text_atomic(
        USAGE_HTML, render_usage_html(USAGE_MD.read_text(encoding="utf-8"))
    )


def sync_all(project_root: Path | None = None) -> None:
    check_state_before_use(project_root or ROOT.parent.resolve())
    sync_data()
    sync_decisions()
    sync_usage()
    sync_records(GUIDE_DIR, "SAST_ITEM_GUIDES")
    sync_records(RESULT_DIR, "SAST_ITEM_RESULTS")
    print("Synchronized dashboard data, decision log, usage page, and item indexes.")


def initialize(project_root: Path) -> int:
    if run_gate(project_root) != 0:
        print("Initialization was not started because the input gate is blocked.")
        return 1
    template_pairs = (
        ("INPUT_VALIDATION.template.md", "INPUT_VALIDATION.md"),
        ("PROJECT_ANALYSIS.template.md", "PROJECT_ANALYSIS.md"),
        ("PROJECT_SECURITY_POLICY.template.md", "PROJECT_SECURITY_POLICY.md"),
        ("WORK_GROUPS.template.md", "WORK_GROUPS.md"),
    )
    created: list[str] = []
    if not DECISIONS_FILE.exists():
        try:
            workspace_id = str(load_json(DATA_DIR / "project-profile.json").get("workspaceId", ""))
        except (OSError, json.JSONDecodeError):
            workspace_id = ""
        write_text_atomic(
            DECISIONS_FILE,
            json_text(
                {
                    "schemaVersion": SCHEMA_VERSION,
                    "workspaceId": workspace_id,
                    "updatedAt": None,
                    "decisions": [],
                }
            ),
        )
        created.append(str(DECISIONS_FILE.relative_to(ROOT)))
    for source_name, target_name in template_pairs:
        source = PROJECT_DIR / source_name
        target = PROJECT_DIR / target_name
        if not target.exists():
            shutil.copyfile(source, target)
            created.append(str(target.relative_to(ROOT)))
    sync_all(project_root)
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
    if input_set is not None and not isinstance(input_set, str):
        return None, ([], [], []), ["input validation inputs.set must be string or null"]
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


def input_manifest(paths: Iterable[Path]) -> list[dict[str, Any]]:
    """Bind approval to every complete input, including every split PDF."""
    manifest: list[dict[str, Any]] = []
    for path in sorted(paths):
        digest = hashlib.sha256()
        size = 0
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
                size += len(chunk)
        manifest.append({"path": display_path(path), "size": size, "sha256": digest.hexdigest()})
    return manifest


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

    manifest: list[dict[str, Any]] = []
    try:
        manifest = input_manifest(pdf_files + spreadsheet_files + sarif_files)
    except OSError as error:
        blockers.append(f"입력 파일의 SHA-256 manifest를 만들 수 없습니다: {error}")
        checks.append(check_record("INPUT_MANIFEST", "fail", blockers[-1], []))

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
                "선택한 입력 자료의 검출 목록과 제공된 가이드 내용을 실제로 읽을 수 있는지 확인해야 합니다.",
                [],
            )
        )
        checks.append(
            check_record(
                "SEMANTIC_MATCH",
                "manual",
                "현재 소스와 선택한 입력 자료가 같은 프로젝트·검사 차수에 해당하는지 대조해야 합니다.",
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
            "manifest": manifest,
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


@lru_cache(maxsize=None)
def load_schema(name: str) -> dict[str, Any]:
    return load_json(ROOT / "schemas" / name)


def validate_schema_contract(
    report: ValidationReport,
    value: Any,
    schema_name: str,
    context: str,
    *,
    record_version: bool = False,
) -> bool:
    """Validate the local schemas' structural contract without dependencies.

    Supports the keywords used by bundled schemas; this is not a general JSON
    Schema engine. schemaVersion is checked separately so legacy record versions
    keep their documented warning policy. date-time remains a format annotation.
    """
    before = len(report.errors)
    try:
        root_schema = load_schema(schema_name)
    except (OSError, json.JSONDecodeError) as error:
        report.error(f"cannot read schema {schema_name}: {error}")
        return False

    def matches_type(item: Any, kind: str) -> bool:
        return {
            "object": isinstance(item, dict),
            "array": isinstance(item, list),
            "string": isinstance(item, str),
            "integer": isinstance(item, int) and not isinstance(item, bool),
            "number": isinstance(item, (int, float)) and not isinstance(item, bool),
            "boolean": isinstance(item, bool),
            "null": item is None,
        }.get(kind, False)

    def walk(item: Any, schema: dict[str, Any], name: str) -> None:
        if "$ref" in schema:
            reference = schema["$ref"]
            if not isinstance(reference, str) or not reference.startswith("#/"):
                report.error(f"unsupported schema reference: {reference!r}")
                return
            target = root_schema
            for segment in reference[2:].split("/"):
                target = target.get(segment.replace("~1", "/").replace("~0", "~"), {})
            if not target:
                report.error(f"unresolved schema reference: {reference}")
                return
            walk(item, target, name)
        kinds = schema.get("type")
        if kinds is not None:
            allowed = kinds if isinstance(kinds, list) else [kinds]
            if not any(matches_type(item, kind) for kind in allowed):
                report.error(f"{name} must be {' or '.join(allowed)}")
                return
        if "enum" in schema and item not in schema["enum"]:
            report.error(f"{name} has invalid {name.rsplit('.', 1)[-1]}: {item!r}")
        if "const" in schema and item != schema["const"]:
            report.error(f"{name} must equal {schema['const']!r}")
        if isinstance(item, dict):
            for field in schema.get("required", []):
                if field == "schemaVersion" and record_version:
                    continue
                if field not in item:
                    report.error(f"{name}.{field} is required")
            properties = schema.get("properties", {})
            additional = schema.get("additionalProperties", True)
            for field, child in item.items():
                if field in properties:
                    if field != "schemaVersion":
                        walk(child, properties[field], f"{name}.{field}")
                elif isinstance(additional, dict):
                    walk(child, additional, f"{name}.{field}")
                elif additional is False:
                    report.error(f"{name}.{field} is not allowed by {schema_name}")
        elif isinstance(item, list):
            if "items" in schema:
                for index, child in enumerate(item):
                    walk(child, schema["items"], f"{name}[{index}]")
            if schema.get("uniqueItems"):
                encoded = [json.dumps(child, sort_keys=True) for child in item]
                if len(encoded) != len(set(encoded)):
                    report.error(f"{name} must contain unique items")
            if len(item) < schema.get("minItems", 0):
                report.error(f"{name} has fewer than {schema['minItems']} items")
        elif isinstance(item, str):
            if len(item) < schema.get("minLength", 0):
                report.error(f"{name} must have at least {schema['minLength']} characters")
            if "pattern" in schema and not re.search(schema["pattern"], item):
                report.error(f"{name} does not match {schema['pattern']!r}")
        elif isinstance(item, (int, float)) and not isinstance(item, bool):
            if "minimum" in schema and item < schema["minimum"]:
                report.error(f"{name} must be at least {schema['minimum']}")
            if "maximum" in schema and item > schema["maximum"]:
                report.error(f"{name} must be at most {schema['maximum']}")

    walk(value, root_schema, context)
    return len(report.errors) == before


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
    if not validate_schema_contract(report, value, "input-validation.schema.json", "input validation"):
        return {}
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
        if not inputs.get("manifest"):
            report.error(
                "ready input validation has no SHA-256 manifest; rerun preflight, "
                "compare report/source semantics, and approve again"
            )
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
    if not validate_schema_contract(report, profile, "project-profile.schema.json", "project profile"):
        return ""
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
    for index, item in enumerate(finding_list):
        report.schema_version(item, f"findings[{index}]", "warn")
    if not validate_schema_contract(report, findings, "findings.schema.json", "findings", record_version=True):
        return [], set()
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
    if not validate_schema_contract(report, guides, "checker-guides.schema.json", "checker guides"):
        return
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
    if not validate_schema_contract(report, progress, "progress.schema.json", "progress"):
        return
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
        schema_name = "result.schema.json" if record_type == "result" else "item-guide.schema.json"
        if not validate_schema_contract(
            report, item, schema_name, f"{record_type} record {finding_id}", record_version=True
        ):
            continue
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
            if not item.get("groupGuideRef", "").strip():
                for field in ("steps", "checkpoints", "impact", "testPlan", "policyQuestions"):
                    require_list(report, item.get(field), f"item guide {finding_id}.{field}")
    return values


def validate_guide_references(report: ValidationReport, guides: dict[str, Any]) -> None:
    """Resolve lightweight guide chains and reject dangling or cyclic refs."""
    completed: set[str] = set()
    for finding_id in guides:
        chain: set[str] = set()
        current = finding_id
        while current not in completed:
            if current in chain:
                report.error(f"item guide {finding_id}.groupGuideRef has a reference cycle at {current}")
                break
            chain.add(current)
            reference = guides[current].get("groupGuideRef")
            if not isinstance(reference, str) or not reference.strip():
                break
            if reference not in guides:
                report.error(f"item guide {current}.groupGuideRef references missing guide {reference}")
                break
            current = reference
        completed.update(chain)


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
    if not recorded_inputs.get("manifest"):
        report.error(
            "input approval has no SHA-256 manifest; rerun preflight, "
            "compare report/source semantics, and approve again"
        )
    elif recorded_inputs["manifest"] != current_inputs.get("manifest"):
        report.error(
            "recorded input manifest differs from current files (paths, sizes, or SHA-256); "
            "rerun preflight and semantic approval"
        )
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
        # Gate answers input readiness; damaged progress is checked/recovered by
        # the next state step and must not prevent reaching that step.
        write_text_atomic(DATA_DIR / "input-validation.js", data_mirror_text("inputValidation", record))
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
        "DECIDED_BY_VALUES": DECIDED_BY_VALUES,
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


def validate_decisions(
    report: ValidationReport,
    workspace_id: str,
    finding_ids: set[str],
) -> None:
    """미확인 기본안과 확인된 정책 결정을 구분할 기록을 검사한다.

    '기본안 적용(미확인)' 결정에는 관찰 방법과 재검토 조건의 기록이 필요하다.
    필드 검사는 실제 관찰 방법의 동작이나 사용자 권한을 인증하지 않는다.
    관련 원리는 docs/HOW_IT_WORKS.md의 정책 확인 절을 참고한다.
    """
    if not DECISIONS_FILE.exists():
        report.warn(
            "data/decisions.json is missing; run `init` to create it. "
            "Decisions written only into project/DECISION_LOG.md cannot be validated"
        )
        return
    try:
        value = load_json(DECISIONS_FILE)
    except (OSError, json.JSONDecodeError) as error:
        report.error(
            f"cannot read data/decisions.json: {error} "
            "(the file may be incomplete or malformed; preserve it before recovery)"
        )
        return
    record = require_mapping(report, value, "decisions")
    report.schema_version(record, "decisions", "error")
    if not validate_schema_contract(report, value, "decisions.schema.json", "decisions"):
        return
    record_workspace = str(record.get("workspaceId", ""))
    if workspace_id and record_workspace != workspace_id:
        report.error("decisions workspaceId does not match project profile")
    items = require_list(report, record.get("decisions"), "decisions.decisions")
    seen: set[str] = set()
    for index, raw in enumerate(items):
        item = require_mapping(report, raw, f"decisions[{index}]")
        decision_id = str(item.get("id", "")).strip()
        context = f"decision {decision_id or f'#{index}'}"
        if not decision_id:
            report.error(f"decisions[{index}] has no id")
        elif decision_id in seen:
            report.error(f"duplicate decision id: {decision_id}")
        seen.add(decision_id)
        if not str(item.get("decidedAt", "")).strip():
            report.error(f"{context} has no decidedAt")
        decided_by = item.get("decidedBy")
        if decided_by not in DECIDED_BY_VALUES:
            report.error(
                f"{context} has invalid decidedBy: {decided_by!r}; "
                f"expected one of {sorted(DECIDED_BY_VALUES)}"
            )
        for field in ("topic", "question", "decision", "scope", "rationale"):
            if not str(item.get(field, "")).strip():
                report.error(f"{context} has empty {field}")
        require_list(report, item.get("checkers"), f"{context}.checkers")
        require_list(report, item.get("evidence"), f"{context}.evidence")
        for finding_id in item.get("findingIds") or []:
            if str(finding_id) not in finding_ids:
                report.error(f"{context} references unknown finding id {finding_id}")
        observation = item.get("observation", "").strip()
        trigger = item.get("reviewTrigger", "").strip()
        if decided_by == "baseline-default":
            if not observation:
                report.error(
                    f"{context} was applied unconfirmed (baseline-default) but has no "
                    "observation; record the observation method, its location, "
                    "and where its results will be checked"
                )
            if not trigger:
                report.error(
                    f"{context} was applied unconfirmed (baseline-default) but has no "
                    "reviewTrigger; record an actionable review condition, for example: "
                    "if a matching WARN event occurs within 2 weeks, ask the policy owner "
                    "to review the event and confirm the policy"
                )
        elif decided_by == "deferred" and not trigger:
            report.error(
                f"{context} is deferred but has no reviewTrigger (who or what unblocks it)"
            )
    # 미러와 생성 md의 드리프트
    if not DECISIONS_MIRROR.exists():
        report.error("data/decisions.js mirror is missing; run sync")
    elif DECISIONS_MIRROR.read_text(encoding="utf-8") != data_mirror_text("decisions", value):
        report.error("data/decisions.js mirror is out of date; run sync")
    if DECISION_LOG_FILE.exists():
        existing = DECISION_LOG_FILE.read_text(encoding="utf-8")
        if GENERATED_MARKER not in existing:
            report.warn(
                "project/DECISION_LOG.md is hand-written (pre-1.9 format); back up the "
                "original, verify provenance, migrate entries into data/decisions.json, "
                "and move the old Markdown out of this generated path before sync "
                "(docs/VERSIONING.md)"
            )
        elif existing != render_decision_log(record):
            report.error("project/DECISION_LOG.md is out of date; run sync")
    else:
        report.error("project/DECISION_LOG.md is missing; run sync")


def validate_usage_html(report: ValidationReport) -> None:
    try:
        markdown = USAGE_MD.read_text(encoding="utf-8")
        html = USAGE_HTML.read_text(encoding="utf-8")
    except OSError:
        return  # 필수 파일 검사가 이미 지적한다
    if GENERATED_MARKER not in html:
        report.warn("USAGE.html is hand-written (pre-1.9); run sync to regenerate it from USAGE.md")
    elif html != render_usage_html(markdown):
        report.error("USAGE.html is out of date with USAGE.md; run sync")


def validate_progress_result_consistency(
    report: ValidationReport,
    progress: Any,
    result_values: dict[str, Any],
) -> None:
    progress_map = require_mapping(report, progress, "progress")
    items = progress_map.get("items")
    if not isinstance(items, dict):
        return
    for finding_id, progress_item in items.items():
        if not isinstance(progress_item, dict):
            continue
        workflow = progress_item.get("workflowStatus")
        conclusion = progress_item.get("conclusion")
        requires_result = (
            isinstance(workflow, str) and workflow in RESULT_REQUIRED_WORKFLOWS
        ) or (isinstance(conclusion, str) and conclusion not in {"unreviewed", "needs-review"})
        if requires_result and finding_id not in result_values:
            report.error(
                f"progress item {finding_id} has no result for {workflow}/{conclusion}; "
                "security-results is canonical, restore or record the result before marking completion"
            )
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


def validate_resume_state(report: ValidationReport, project_root: Path,
                          results: dict[str, Any]) -> None:
    """Old records stay readable; existing source bindings fail closed."""
    needs_workspace = (DATA_DIR / "resume-state.json").exists() or any(
        isinstance(value.get("verification"), dict) and "sourceSnapshot" in value["verification"]
        for value in results.values()
    )
    workspace = None
    if needs_workspace:
        try:
            try:
                from .sast_state import Workspace
            except ImportError:
                from sast_state import Workspace
            workspace = Workspace(ROOT, project_root)
            workspace.state()
        except (OSError, ValueError, TypeError) as error:
            report.error(f"resume state: {error}")
            return
    for finding_id, value in results.items():
        verification = value.get("verification")
        if not isinstance(verification, dict):
            continue
        if "sourceSnapshot" not in verification:
            if value.get("workflowStatus") == "verified" or verification.get("status") == "passed":
                report.warn(f"result {finding_id} verification is unbound; capture a source snapshot and reverify before trusting legacy evidence")
        elif workspace is not None:
            status = workspace.verification_status(finding_id, value)
            if status["status"] != "fresh":
                report.error(f"result {finding_id} verification is {status['status']}: {status.get('reason', '')}")


def check_state_before_use(project_root: Path) -> None:
    """Read inputs before publishing mirrors or querying a damaged/stale state."""
    report = ValidationReport()
    try:
        try:
            from .sast_state import safe_record
        except ImportError:
            from sast_state import safe_record
        # Read all mirror inputs first so a malformed late record cannot leave
        # newly published early mirrors beside an old result index.
        for name in DATA_MIRRORS:
            load_json_or_exit(safe_record(ROOT, f"data/{name}.json"))
        records = {}
        for directory in (GUIDE_DIR, RESULT_DIR):
            safe_record(ROOT, str(directory.relative_to(ROOT)))
            for path in iter_record_json(directory):
                value = load_json_or_exit(safe_record(ROOT, str(path.relative_to(ROOT))))
                if not isinstance(value, dict):
                    raise ValueError(f"record must be an object: {path.name}")
                if directory == RESULT_DIR:
                    records[path.stem] = value
        profile = load_json(DATA_DIR / "project-profile.json")
        progress = load_json(DATA_DIR / "progress.json")
        findings = load_json(DATA_DIR / "findings.json")
        if not isinstance(profile, dict) or not isinstance(findings, list):
            raise ValueError("profile must be an object and findings a list")
        finding_ids = {item.get("id") for item in findings if isinstance(item, dict)}
        validate_progress(report, progress, finding_ids, str(profile.get("workspaceId", "")), False)
        validate_progress_result_consistency(report, progress, records)
        validate_resume_state(report, project_root, records)
    except (OSError, ValueError, TypeError) as error:
        report.error(f"state cannot be used: {error}")
    for message in report.errors:
        print(f"ERROR: {message}", file=sys.stderr)
    for message in report.warnings:
        print(f"WARN: {message}", file=sys.stderr)
    if report.errors:
        raise SystemExit(1)


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
                "(the file may be incomplete or malformed; preserve it before recovery)"
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
        validate_guide_references(report, guide_values)
        result_values = validate_record_files(
            report, RESULT_DIR, finding_ids, "result"
        )
        validate_resume_state(report, project_root, result_values)
        if progress is not None:
            validate_progress_result_consistency(report, progress, result_values)
        validate_mirrors(report, guide_values, result_values)
        validate_decisions(report, workspace_id, finding_ids)
        validate_usage_html(report)
    except (OSError, json.JSONDecodeError) as error:
        report.error(f"cannot load toolkit data: {error}")
    report.print()
    return 1 if report.errors else 0


def dotted_get(value: Any, path: str) -> Any:
    for segment in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(segment)
    return value


def run_query(args: argparse.Namespace) -> int:
    """findings.json 전체를 AI가 읽지 않고 필요한 항목만 잘라 준다.

    progress의 상태를 항목에 합쳐서 돌려주므로 '이 그룹의 미완료 항목'
    같은 조회가 파일 두 개를 읽지 않고 끝난다. 결과는 JSON 배열(stdout).
    """
    findings = load_json_or_exit(DATA_DIR / "findings.json")
    progress_items = load_json_or_exit(DATA_DIR / "progress.json").get("items", {})
    if not isinstance(findings, list) or not isinstance(progress_items, dict):
        print("findings.json must be a list and progress.json items a mapping", file=sys.stderr)
        return 1
    wanted_ids = (
        {piece.strip() for piece in args.ids.split(",") if piece.strip()}
        if args.ids
        else None
    )
    rows: list[dict[str, Any]] = []
    for item in findings:
        if not isinstance(item, dict):
            continue
        finding_id = str(item.get("id", ""))
        progress = progress_items.get(finding_id) or {}
        status = progress.get("workflowStatus") or "todo"
        conclusion = progress.get("conclusion") or "unreviewed"
        mapping = item.get("sourceMapping") or {}
        location = item.get("location") or {}
        current_file = str(mapping.get("currentFile") or location.get("reportedFile") or "")
        if wanted_ids is not None and finding_id not in wanted_ids:
            continue
        if args.group and (item.get("grouping") or {}).get("workGroup") != args.group:
            continue
        if args.status and status != args.status:
            continue
        if args.conclusion and conclusion != args.conclusion:
            continue
        if args.risk and (item.get("risk") or {}).get("level") != args.risk:
            continue
        if args.checker and (item.get("checker") or {}).get("code") != args.checker:
            continue
        if args.file and args.file not in current_file:
            continue
        row = dict(item)
        row["progress"] = {
            "workflowStatus": status,
            "conclusion": conclusion,
            "updatedAt": progress.get("updatedAt"),
        }
        row["hasGuide"] = (GUIDE_DIR / f"{finding_id}.json").is_file()
        row["hasResult"] = (RESULT_DIR / f"{finding_id}.json").is_file()
        rows.append(row)
    if args.summary:
        summary: dict[str, dict[str, int]] = {
            "workflowStatus": {},
            "conclusion": {},
            "risk": {},
            "workGroup": {},
        }
        for row in rows:
            for key, value in (
                ("workflowStatus", row["progress"]["workflowStatus"]),
                ("conclusion", row["progress"]["conclusion"]),
                ("risk", (row.get("risk") or {}).get("level")),
                ("workGroup", (row.get("grouping") or {}).get("workGroup")),
            ):
                bucket = summary[key]
                bucket[str(value)] = bucket.get(str(value), 0) + 1
        print(json_text({"total": len(rows), "by": summary}), end="")
        return 0
    if args.limit is not None:
        rows = rows[: args.limit]
    if args.fields:
        fields = [f.strip() for f in args.fields.split(",") if f.strip()]
        rows = [
            {field: dotted_get(row, field) for field in fields}
            for row in rows
        ]
    print(json_text(rows), end="")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check inputs, initialize, synchronize, and validate SAST toolkit data."
    )
    parser.add_argument(
        "command", choices=("preflight", "gate", "init", "sync", "validate", "query")
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
    query = parser.add_argument_group(
        "query", "Slice findings joined with progress (avoid reading findings.json whole)."
    )
    query.add_argument("--group", help="grouping.workGroup to match (e.g. WG-003).")
    query.add_argument("--ids", help="Comma-separated finding ids.")
    query.add_argument("--status", help="progress workflowStatus to match (todo when absent).")
    query.add_argument("--conclusion", help="progress conclusion to match (unreviewed when absent).")
    query.add_argument("--risk", help="risk.level to match (critical/very-high/high/medium/low).")
    query.add_argument("--checker", help="checker.code to match.")
    query.add_argument("--file", help="Substring of the current (or reported) file path.")
    query.add_argument("--limit", type=int, help="Return at most N items.")
    query.add_argument(
        "--fields",
        help="Comma-separated dotted fields to keep, e.g. id,risk.level,checker.code,location,progress.",
    )
    query.add_argument(
        "--summary",
        action="store_true",
        help="Print counts by status/conclusion/risk/workGroup instead of items.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    project_root = (
        Path(args.project_root).expanduser().resolve()
        if args.project_root
        else ROOT.parent.resolve()
    )
    if args.command in {"preflight", "gate", "init", "sync"}:
        with writer_lock(ROOT):
            if args.command == "gate":
                return run_gate(project_root)
            if args.command == "preflight":
                return run_preflight(project_root, args.input_set)
            if args.command == "init":
                return initialize(project_root)
            sync_all(project_root)
            return 0
    if args.command == "query":
        check_state_before_use(project_root)
        return run_query(args)
    return validate_all(args.strict, project_root)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        sys.exit(0)
