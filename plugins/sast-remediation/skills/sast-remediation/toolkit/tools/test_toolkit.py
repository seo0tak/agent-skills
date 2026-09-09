"""툴킷 자체 회귀 테스트 — 표준 라이브러리 unittest만 사용한다.

실행: 툴킷 디렉터리에서 `python3 -m unittest tools.test_toolkit -v`
(또는 `python3 tools/test_toolkit.py`).

각 테스트는 툴킷을 임시 디렉터리에 복사한 뒤 파일을 고의로 망가뜨리고
validate/sync/query를 서브프로세스로 실행해 출력과 종료코드를 확인한다.
사람이 손으로 하던 오류 주입(반쪽 JSON, schemaVersion 불일치, 미러
드리프트, 결정 로그 감사 장치 누락)을 코드로 고정한 것이다.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLKIT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {"input", "__pycache__", ".git"}


def copy_toolkit(target: Path) -> None:
    def ignore(_dir: str, names: list[str]) -> set[str]:
        return {n for n in names if n in SKIP_DIRS or n.endswith(".pyc")}

    shutil.copytree(TOOLKIT, target, ignore=ignore, dirs_exist_ok=True)
    (target / "input").mkdir(exist_ok=True)


def read_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


class ToolkitCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "sast-remediation-toolkit"
        copy_toolkit(self.root)
        self.data = self.root / "data"
        self.project = self.root / "project"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def run_tool(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "tools/sast_toolkit.py", *args],
            cwd=self.root,
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )

    def validate(self) -> tuple[int, str]:
        proc = self.run_tool("validate")
        return proc.returncode, proc.stdout + proc.stderr

    def assert_error(self, output: str, needle: str) -> None:
        self.assertIn("ERROR:", output, output)
        self.assertIn(needle, output, output)

    def assert_warn(self, output: str, needle: str) -> None:
        self.assertIn("WARN:", output, output)
        self.assertIn(needle, output, output)

    def load_examples(self) -> None:
        """예시 데이터를 실제 데이터로 올려 항목이 있는 상태를 만든다."""
        for name in ("findings", "progress", "project-profile", "checker-guides"):
            shutil.copyfile(self.root / "examples" / f"{name}.json", self.data / f"{name}.json")
        shutil.copyfile(self.root / "examples" / "decisions.json", self.data / "decisions.json")
        shutil.copyfile(
            self.root / "examples" / "result.json", self.root / "security-results" / "SAMPLE-001.json"
        )
        shutil.copyfile(
            self.root / "examples" / "item-guide.json", self.root / "security-guides" / "SAMPLE-001.json"
        )
        self.assertEqual(self.run_tool("sync").returncode, 0)

    def ready_inputs(self, vendor: bool = False) -> None:
        """합성 입력을 승인한다. 의미 판독 정확도가 아닌 승인 이후 불변조건용."""
        self.load_examples()
        (self.root.parent / "application.py").write_text("value = 1\n", encoding="utf-8")
        if vendor:
            (self.root / "input/report-01.pdf").write_bytes(b"%PDF-1.7\nfirst\n%%EOF\n")
            (self.root / "input/report-02.pdf").write_bytes(b"%PDF-1.7\nother\n%%EOF\n")
            (self.root / "input/report.csv").write_text("id,rule\n1,RULE-A\n", encoding="utf-8")
        else:
            write_json(self.root / "input/report.sarif", {
                "version": "2.1.0", "runs": [{
                    "tool": {"driver": {"name": "ScannerA"}},
                    "results": [{"ruleId": "RULE-A", "message": {"text": "finding"}}],
                }],
            })
        proc = self.run_tool("preflight")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        record = read_json(self.data / "input-validation.json")
        record["status"] = "ready"
        for check in record["checks"]:
            check["status"] = "pass"
        for field in record["matching"]:
            record["matching"][field] = True if field != "reason" else "Synthetic input fixture confirmed."
        write_json(self.data / "input-validation.json", record)
        profile = read_json(self.data / "project-profile.json")
        for kind in ("pdf", "spreadsheet", "sarif"):
            profile["report"][kind] = (record["inputs"].get(kind) or {}).get("path", "")
        write_json(self.data / "project-profile.json", profile)
        self.assertEqual(self.run_tool("sync").returncode, 0)
        proc = self.run_tool("validate", "--strict")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)


class InputManifestTests(ToolkitCase):
    def test_example_input_record_matches_current_contract(self) -> None:
        self.load_examples()
        shutil.copyfile(self.root / "examples/input-validation.json", self.data / "input-validation.json")
        self.run_tool("sync")
        code, out = self.validate()
        self.assertEqual(code, 0, out)

    def test_unchanged_approved_inputs_remain_ready(self) -> None:
        self.ready_inputs()
        proc = self.run_tool("gate")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("GATE: READY", proc.stdout)

    def test_same_size_sarif_replacement_invalidates_approval(self) -> None:
        self.ready_inputs()
        path = self.root / "input/report.sarif"
        previous = path.read_text(encoding="utf-8")
        path.write_text(previous.replace("ScannerA", "ScannerB"), encoding="utf-8")
        for args in (("gate",), ("validate", "--strict")):
            with self.subTest(command=args):
                proc = self.run_tool(*args)
                self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
                self.assertIn("manifest", proc.stdout)

    def test_same_size_spreadsheet_change_invalidates_approval(self) -> None:
        self.ready_inputs(vendor=True)
        (self.root / "input/report.csv").write_text("id,rule\n1,RULE-B\n", encoding="utf-8")
        proc = self.run_tool("gate")
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("manifest", proc.stdout)

    def test_manifest_covers_every_split_pdf_and_the_sheet(self) -> None:
        self.ready_inputs(vendor=True)
        record = read_json(self.data / "input-validation.json")
        expected = [
            {"path": f"input/{path.name}", "size": path.stat().st_size,
             "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            for path in sorted((self.root / "input").iterdir()) if path.suffix in {".pdf", ".csv"}
        ]
        self.assertEqual(record["inputs"].get("manifest"), expected)

    def test_nonfirst_pdf_rename_invalidates_approval(self) -> None:
        self.ready_inputs(vendor=True)
        (self.root / "input/report-02.pdf").rename(self.root / "input/report-03.pdf")
        proc = self.run_tool("gate")
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("manifest", proc.stdout)

    def test_nonfirst_pdf_content_change_invalidates_approval(self) -> None:
        self.ready_inputs(vendor=True)
        (self.root / "input/report-02.pdf").write_bytes(b"%PDF-1.7\nTHIRD\n%%EOF\n")
        proc = self.run_tool("gate")
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)

    def test_legacy_approval_requires_preflight_and_semantic_reapproval(self) -> None:
        self.ready_inputs()
        record = read_json(self.data / "input-validation.json")
        record["inputs"].pop("manifest", None)
        write_json(self.data / "input-validation.json", record)
        proc = self.run_tool("gate")
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("preflight", proc.stdout)
        self.assertEqual(self.run_tool("preflight").returncode, 0)
        self.assertEqual(self.run_tool("gate").returncode, 1)
        refreshed = read_json(self.data / "input-validation.json")
        self.assertIsNone(refreshed["matching"]["sameProject"])


class CanonicalResultTests(ToolkitCase):
    def test_completed_progress_requires_result_in_both_validation_modes(self) -> None:
        self.ready_inputs()
        (self.root / "security-results/SAMPLE-001.json").unlink()
        # A missing canonical result must not be republished as completed progress.
        sync = self.run_tool("sync")
        self.assertEqual(sync.returncode, 1, sync.stdout + sync.stderr)
        self.assertIn("no result", sync.stdout + sync.stderr)
        for args in (("validate",), ("validate", "--strict")):
            with self.subTest(command=args):
                proc = self.run_tool(*args)
                self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
                self.assertIn("SAMPLE-001", proc.stdout)
                self.assertIn("no result", proc.stdout)

    def test_result_required_states_and_conclusions(self) -> None:
        self.load_examples()
        (self.root / "security-results/SAMPLE-001.json").unlink()
        progress = read_json(self.data / "progress.json")
        for workflow, conclusion in (("analyzed", "fix"), ("change-complete", "unreviewed"),
                                     ("verified", "fix"), ("deferred", "exception"),
                                     ("todo", "false-positive")):
            with self.subTest(workflow=workflow, conclusion=conclusion):
                progress["items"]["SAMPLE-001"].update(workflowStatus=workflow, conclusion=conclusion)
                write_json(self.data / "progress.json", progress)
                self.run_tool("sync")
                code, out = self.validate()
                self.assertEqual(code, 1, out)
                self.assertIn("no result", out)

    def test_initial_or_parked_provisional_progress_needs_no_result(self) -> None:
        self.load_examples()
        (self.root / "security-results/SAMPLE-001.json").unlink()
        progress = read_json(self.data / "progress.json")
        for workflow, conclusion in (("todo", "unreviewed"), ("in-progress", "unreviewed"),
                                     ("analyzed", "needs-review"), ("deferred", "unreviewed"),
                                     ("deferred", "needs-review")):
            with self.subTest(workflow=workflow, conclusion=conclusion):
                progress["items"]["SAMPLE-001"].update(workflowStatus=workflow, conclusion=conclusion)
                write_json(self.data / "progress.json", progress)
                self.run_tool("sync")
                code, out = self.validate()
                self.assertEqual(code, 0, out)


class SchemaContractTests(ToolkitCase):
    def test_malformed_input_set_is_reported_without_traceback(self) -> None:
        self.ready_inputs()
        record = read_json(self.data / "input-validation.json")
        record["inputs"]["set"] = ["unexpected-array"]
        write_json(self.data / "input-validation.json", record)
        self.run_tool("sync")
        for args in (("gate",), ("validate", "--strict")):
            with self.subTest(command=args):
                proc = self.run_tool(*args)
                out = proc.stdout + proc.stderr
                self.assertEqual(proc.returncode, 1, out)
                self.assertIn("inputs.set", out)
                self.assertNotIn("Traceback", out)

    def test_required_profile_fields_and_nested_array_types_are_checked(self) -> None:
        self.load_examples()
        record = read_json(self.data / "project-profile.json")
        record.pop("projectName")
        record["technology"]["languages"] = [None]
        write_json(self.data / "project-profile.json", record)
        self.run_tool("sync")
        code, out = self.validate()
        self.assertEqual(code, 1, out)
        self.assertIn("projectName", out)
        self.assertIn("languages[0]", out)
        self.assertNotIn("Traceback", out)

    def test_verified_result_requires_existing_schema_fields(self) -> None:
        self.load_examples()
        path = self.root / "security-results/SAMPLE-001.json"
        write_json(path, {"schemaVersion": "1.0", "id": "SAMPLE-001", "workflowStatus": "verified",
                          "conclusion": "fix", "reason": "Applied fix",
                          "verification": {"status": "passed", "method": "unit-test"}})
        self.run_tool("sync")
        code, out = self.validate()
        self.assertEqual(code, 1, out)
        for field in ("resultFiles", "resultCodeDiff", "updatedAt", "commands", "results", "verifiedAt"):
            self.assertIn(field, out)

    def test_nested_and_container_types_fail_without_traceback(self) -> None:
        self.load_examples()
        for relative, field, invalid in (("result", "resultFiles", "src/file.py"),
                                         ("result", "verification", []),
                                         ("findings", "sequence", []),
                                         ("findings", "checker", None)):
            with self.subTest(record=relative, field=field):
                value = read_json(self.root / "examples" / f"{relative}.json")
                target = value[0] if relative == "findings" else value
                target[field] = invalid
                path = self.data / "findings.json" if relative == "findings" else self.root / "security-results/SAMPLE-001.json"
                write_json(path, value)
                self.run_tool("sync")
                code, out = self.validate()
                self.assertEqual(code, 1, out)
                self.assertIn(field, out)
                self.assertNotIn("Traceback", out)
                shutil.copyfile(self.root / "examples" / f"{relative}.json", path)

    def test_result_method_and_schema_version_keep_warning_compatibility(self) -> None:
        self.load_examples()
        path = self.root / "security-results/SAMPLE-001.json"
        record = read_json(path)
        record.pop("schemaVersion")
        record["verification"].pop("method")
        write_json(path, record)
        self.run_tool("sync")
        code, out = self.validate()
        self.assertEqual(code, 0, out)
        self.assert_warn(out, "schemaVersion")
        self.assert_warn(out, "verification.method")

    def test_manual_review_may_have_no_commands(self) -> None:
        self.load_examples()
        path = self.root / "security-results/SAMPLE-001.json"
        record = read_json(path)
        record["verification"].update(method="manual-review", commands=[])
        write_json(path, record)
        self.run_tool("sync")
        code, out = self.validate()
        self.assertEqual(code, 0, out)

    def test_null_blank_or_wrong_type_audit_fields_fail(self) -> None:
        self.load_examples()
        for invalid in (None, "   ", [], False, 42):
            with self.subTest(value=invalid):
                record = read_json(self.root / "examples/decisions.json")
                record["decisions"][0].update(observation=invalid, reviewTrigger=invalid)
                write_json(self.data / "decisions.json", record)
                self.run_tool("sync")
                code, out = self.validate()
                self.assertEqual(code, 1, out)
                self.assertIn("observation", out)
                self.assertIn("reviewTrigger", out)
                self.assertNotIn("Traceback", out)


class LightweightGuideTests(ToolkitCase):
    def add_member(self) -> None:
        self.load_examples()
        findings = read_json(self.data / "findings.json")
        member = json.loads(json.dumps(findings[0]))
        member.update(id="SAMPLE-002", sequence=2)
        member["sourceMapping"]["fingerprint"] += ":member"
        findings.append(member)
        write_json(self.data / "findings.json", findings)
        profile = read_json(self.data / "project-profile.json")
        profile["report"]["findingCount"] = 2
        write_json(self.data / "project-profile.json", profile)
        self.guide_path = self.root / "security-guides/SAMPLE-002.json"
        write_json(self.guide_path, {"schemaVersion": "1.0", "id": "SAMPLE-002", "sequence": 2,
                                   "title": "Member", "sourceMapping": "exact", "summary": "Same as representative",
                                   "groupGuideRef": "SAMPLE-001", "delta": []})
        self.run_tool("sync")

    def test_valid_lightweight_member_is_accepted(self) -> None:
        self.add_member()
        code, out = self.validate()
        self.assertEqual(code, 0, out)

    def test_missing_or_self_referencing_representative_is_rejected(self) -> None:
        self.add_member()
        for reference in ("NOPE-001", "SAMPLE-002"):
            with self.subTest(reference=reference):
                guide = read_json(self.guide_path)
                guide["groupGuideRef"] = reference
                write_json(self.guide_path, guide)
                self.run_tool("sync")
                code, out = self.validate()
                self.assertEqual(code, 1, out)
                self.assertIn("groupGuideRef", out)

    def test_reference_cycle_is_rejected(self) -> None:
        self.add_member()
        path = self.root / "security-guides/SAMPLE-001.json"
        guide = read_json(path)
        guide["groupGuideRef"] = "SAMPLE-002"
        write_json(path, guide)
        self.run_tool("sync")
        code, out = self.validate()
        self.assertEqual(code, 1, out)
        self.assertIn("cycle", out)


class BaselineTests(ToolkitCase):
    def test_shipped_toolkit_validates(self) -> None:
        code, out = self.validate()
        self.assertEqual(code, 0, out)
        self.assertNotIn("ERROR:", out)

    def test_example_data_validates(self) -> None:
        self.load_examples()
        code, out = self.validate()
        self.assertEqual(code, 0, out)


class InterruptionTests(ToolkitCase):
    def test_half_written_progress_is_named(self) -> None:
        (self.data / "progress.json").write_text('{"schemaVersion": "1.0", "items": {', encoding="utf-8")
        code, out = self.validate()
        self.assertEqual(code, 1)
        self.assert_error(out, "data/progress.json")
        self.assertIn("half-written", out)

    def test_half_written_result_record_is_named(self) -> None:
        self.load_examples()
        (self.root / "security-results" / "SAMPLE-001.json").write_text('{"id": "SAMPLE-001",', encoding="utf-8")
        code, out = self.validate()
        self.assertEqual(code, 1)
        self.assert_error(out, "security-results/SAMPLE-001.json")


class SchemaVersionTests(ToolkitCase):
    def test_single_file_mismatch_is_error(self) -> None:
        progress = read_json(self.data / "progress.json")
        progress["schemaVersion"] = "2.0"
        write_json(self.data / "progress.json", progress)
        self.run_tool("sync")
        code, out = self.validate()
        self.assertEqual(code, 1)
        self.assert_error(out, "progress schemaVersion is '2.0'")

    def test_record_mismatch_is_warning_only(self) -> None:
        self.load_examples()
        findings = read_json(self.data / "findings.json")
        findings[0]["schemaVersion"] = "0.9"
        write_json(self.data / "findings.json", findings)
        self.run_tool("sync")
        code, out = self.validate()
        self.assertEqual(code, 0, out)
        self.assert_warn(out, "findings[0] schemaVersion is '0.9'")

    def test_schema_const_and_validator_must_agree(self) -> None:
        schema = read_json(self.root / "schemas" / "result.schema.json")
        schema["properties"]["schemaVersion"]["const"] = "2.0"
        write_json(self.root / "schemas" / "result.schema.json", schema)
        code, out = self.validate()
        self.assertEqual(code, 1)
        self.assert_error(out, "schemaVersion const is '2.0' but validator SCHEMA_VERSION is '1.0'")


class MirrorDriftTests(ToolkitCase):
    def test_data_mirror_drift(self) -> None:
        self.load_examples()
        findings = read_json(self.data / "findings.json")
        findings[0]["suggestedReason"] = "changed without sync"
        write_json(self.data / "findings.json", findings)
        code, out = self.validate()
        self.assertEqual(code, 1)
        self.assertIn("findings", out)
        self.assertRegex(out, r"ERROR:.*(mirror|out of date|drift)")

    def test_generated_decision_log_drift(self) -> None:
        self.load_examples()
        log = self.project / "DECISION_LOG.md"
        log.write_text(log.read_text(encoding="utf-8") + "\n손으로 덧붙임\n", encoding="utf-8")
        code, out = self.validate()
        self.assertEqual(code, 1)
        self.assert_error(out, "DECISION_LOG.md is out of date")

    def test_usage_html_drift(self) -> None:
        (self.root / "USAGE.md").write_text(
            (self.root / "USAGE.md").read_text(encoding="utf-8") + "\n## 새 절\n\n추가.\n",
            encoding="utf-8",
        )
        code, out = self.validate()
        self.assertEqual(code, 1)
        self.assert_error(out, "USAGE.html is out of date")
        self.assertEqual(self.run_tool("sync").returncode, 0)
        code, out = self.validate()
        self.assertEqual(code, 0, out)
        self.assertIn("새 절", (self.root / "USAGE.html").read_text(encoding="utf-8"))


class DecisionAuditTests(ToolkitCase):
    """원리 9의 감사 장치: 미확인 결정에는 관찰 장치와 재검토 조건이 있어야 한다."""

    def decision(self, **overrides: object) -> dict[str, object]:
        base = read_json(self.root / "examples" / "decisions.json")["decisions"][0]
        base = dict(base)
        base.update(overrides)
        return base

    def write_decisions(self, *decisions: dict[str, object]) -> None:
        record = read_json(self.data / "decisions.json")
        record["decisions"] = list(decisions)
        write_json(self.data / "decisions.json", record)
        self.assertEqual(self.run_tool("sync").returncode, 0)

    def test_unconfirmed_without_observation_is_error(self) -> None:
        self.load_examples()
        self.write_decisions(self.decision(observation=""))
        code, out = self.validate()
        self.assertEqual(code, 1)
        self.assert_error(out, "DEC-002 was applied unconfirmed (baseline-default) but has no observation")

    def test_unconfirmed_without_trigger_is_error(self) -> None:
        self.load_examples()
        self.write_decisions(self.decision(reviewTrigger=""))
        code, out = self.validate()
        self.assertEqual(code, 1)
        self.assert_error(out, "has no reviewTrigger")

    def test_user_confirmed_needs_no_observation(self) -> None:
        self.load_examples()
        self.write_decisions(self.decision(decidedBy="user", observation="", reviewTrigger=""))
        code, out = self.validate()
        self.assertEqual(code, 0, out)

    def test_invalid_decided_by_is_error(self) -> None:
        self.load_examples()
        self.write_decisions(self.decision(decidedBy="confirmed"))
        code, out = self.validate()
        self.assertEqual(code, 1)
        self.assert_error(out, "invalid decidedBy")

    def test_duplicate_id_and_unknown_finding(self) -> None:
        self.load_examples()
        self.write_decisions(self.decision(), self.decision(findingIds=["NOPE-1"]))
        code, out = self.validate()
        self.assertEqual(code, 1)
        self.assert_error(out, "duplicate decision id: DEC-002")
        self.assertIn("references unknown finding id NOPE-1", out)

    def test_hand_written_log_is_preserved_and_warned(self) -> None:
        """1.8 이전 프로젝트: 손으로 쓴 DECISION_LOG.md를 sync가 덮어쓰면 안 된다."""
        log = self.project / "DECISION_LOG.md"
        log.write_text("# Security Decision Log\n\n- 결정 ID: DEC-OLD\n", encoding="utf-8")
        self.assertEqual(self.run_tool("sync").returncode, 0)
        self.assertIn("DEC-OLD", log.read_text(encoding="utf-8"))
        code, out = self.validate()
        self.assertEqual(code, 0, out)
        self.assert_warn(out, "DECISION_LOG.md is hand-written")

    def test_generated_log_is_newest_first_with_frontmatter(self) -> None:
        self.load_examples()
        text = (self.project / "DECISION_LOG.md").read_text(encoding="utf-8")
        self.assertTrue(text.startswith("---\ntype: sast/decision-log"))
        self.assertLess(text.index("DEC-002"), text.index("DEC-001"))
        self.assertIn("결정 주체: 기본안 적용(미확인)", text)
        self.assertIn("관찰 장치: SmsSender.send:88", text)

    def test_missing_decisions_file_is_warning_and_init_creates_it(self) -> None:
        (self.data / "decisions.json").unlink()
        code, out = self.validate()
        self.assertEqual(code, 0, out)
        self.assert_warn(out, "decisions.json is missing")


class QueryTests(ToolkitCase):
    def query(self, *args: str) -> object:
        proc = self.run_tool("query", *args)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout)

    def test_filters_and_progress_join(self) -> None:
        self.load_examples()
        rows = self.query("--group", "WG-001")
        self.assertEqual([r["id"] for r in rows], ["SAMPLE-001"])
        self.assertEqual(rows[0]["progress"]["workflowStatus"], "verified")
        self.assertTrue(rows[0]["hasResult"])
        self.assertEqual(self.query("--status", "todo"), [])
        self.assertEqual(self.query("--group", "WG-999"), [])

    def test_fields_and_summary(self) -> None:
        self.load_examples()
        rows = self.query("--fields", "id,risk.level,progress.conclusion")
        self.assertEqual(rows, [{"id": "SAMPLE-001", "risk.level": "high", "progress.conclusion": "fix"}])
        summary = self.query("--summary")
        self.assertEqual(summary["total"], 1)
        self.assertEqual(summary["by"]["workflowStatus"], {"verified": 1})

    def test_missing_progress_defaults_to_todo(self) -> None:
        self.load_examples()
        # An unstarted item has neither canonical result nor provisional entry.
        # Existing results with missing progress are an interruption to reconcile.
        (self.root / "security-results/SAMPLE-001.json").unlink()
        progress = read_json(self.data / "progress.json")
        progress["items"] = {}
        write_json(self.data / "progress.json", progress)
        rows = self.query("--status", "todo")
        self.assertEqual(rows[0]["progress"]["conclusion"], "unreviewed")


class DashboardTests(ToolkitCase):
    @unittest.skipUnless(shutil.which("node"), "node not installed")
    def test_dashboard_script_parses(self) -> None:
        proc = subprocess.run(["node", "--check", str(self.root / "assets" / "checklist.js")], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
