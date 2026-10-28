"""security-assessment M0 회귀 테스트 — 표준 라이브러리 unittest만.

실행: 툴킷 디렉터리에서 `python3 -B -m unittest tools.test_assess`.

인가 게이트의 핵심 성질을 고정한다: 미인가·기간 밖·스코프 변경이면 BLOCKED,
notes만 바꾼 것은 승인 유지, 승인은 의미 지문으로 재대조.
"""
from __future__ import annotations

import copy
import io
import json
import re
import sys
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
import tempfile
from typing import Any

TOOLS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS_DIR))
import assess_toolkit  # noqa: E402

# 모듈을 Any로 받아 테스트에서 now_utc·SCOPE_FILE을 교체한다(인-프로세스 격리).
assess: Any = assess_toolkit

EXAMPLE = json.loads((TOOLS_DIR.parent / "examples" / "scope.json").read_text(encoding="utf-8"))


def authorized_scope(**overrides):
    """예시를 바탕으로 지문이 올바르게 기록된 승인 스코프를 만든다."""
    scope = copy.deepcopy(EXAMPLE)
    scope.update(overrides)
    scope["status"] = "authorized"
    scope["authorizedAt"] = "2026-10-22T00:00:00Z"
    scope["approvalFingerprint"] = assess.semantic_fingerprint(scope)
    return scope


class AssessCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.scope_file = Path(self._tmp.name) / "scope.json"
        self._orig_file = assess.SCOPE_FILE
        self._orig_now = assess.now_utc
        assess.SCOPE_FILE = self.scope_file
        # 기간(2026-10-22~29) 안의 고정 '현재'.
        assess.now_utc = lambda: datetime(2026, 10, 24, tzinfo=timezone.utc)

    def tearDown(self):
        assess.SCOPE_FILE = self._orig_file
        assess.now_utc = self._orig_now
        self._tmp.cleanup()

    def write(self, scope):
        self.scope_file.write_text(json.dumps(scope, ensure_ascii=False, indent=2), encoding="utf-8")

    def validate(self, strict=False):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = assess.run_validate(strict)
        return code, buffer.getvalue()

    def gate(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = assess.run_gate()
        return code, buffer.getvalue()

    def authorize(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = assess.run_authorize()
        return code, buffer.getvalue()

    # --- 기본 상태 ---
    def test_authorized_example_validates_and_gate_ready(self):
        self.write(authorized_scope())
        code, out = self.validate()
        self.assertEqual(code, 0, out)
        code, out = self.gate()
        self.assertEqual(code, 0, out)
        self.assertIn("GATE: READY", out)

    def test_unauthorized_scope_blocks_the_gate(self):
        scope = copy.deepcopy(EXAMPLE)
        scope["status"] = "unauthorized"
        scope["authorizedAt"] = None
        scope["approvalFingerprint"] = None
        self.write(scope)
        code, out = self.gate()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED", out)
        self.assertIn("not authorized", out)

    # --- 스코프 변경 무효 ---
    def test_changing_a_semantic_field_voids_approval(self):
        scope = authorized_scope()
        scope["targets"] = scope["targets"] + [{"type": "web", "value": "https://extra.example.test"}]
        self.write(scope)
        code, out = self.validate()
        self.assertEqual(code, 1)
        self.assertIn("scope changed since authorization", out)
        code, out = self.gate()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED", out)

    def test_changing_only_notes_keeps_approval(self):
        scope = authorized_scope()
        scope["targets"][0]["notes"] = "설명만 고침 — 지문에 안 들어감"
        self.write(scope)
        code, out = self.validate()
        self.assertEqual(code, 0, out)
        code, out = self.gate()
        self.assertEqual(code, 0, out)
        self.assertIn("READY", out)

    # --- 기간 ---
    def test_expired_window_blocks_even_when_authorized(self):
        self.write(authorized_scope())
        assess.now_utc = lambda: datetime(2026, 11, 1, tzinfo=timezone.utc)
        code, out = self.gate()
        self.assertEqual(code, 1)
        self.assertIn("expired", out)

    def test_window_not_started_blocks(self):
        self.write(authorized_scope())
        assess.now_utc = lambda: datetime(2026, 10, 1, tzinfo=timezone.utc)
        code, out = self.gate()
        self.assertEqual(code, 1)
        self.assertIn("has not started", out)

    def test_end_date_is_inclusive_through_end_of_day(self):
        self.write(authorized_scope())
        assess.now_utc = lambda: datetime(2026, 10, 29, 18, 0, tzinfo=timezone.utc)
        code, out = self.gate()
        self.assertEqual(code, 0, out)

    # --- 형식 검사 ---
    def test_bad_reference_is_rejected(self):
        scope = authorized_scope(consent={**EXAMPLE["consent"], "reference": "그냥 말로 허락받음"})
        scope["approvalFingerprint"] = assess.semantic_fingerprint(scope)
        self.write(scope)
        code, out = self.validate()
        self.assertEqual(code, 1)
        self.assertIn("reference must be", out)

    def test_missing_consent_field_is_rejected(self):
        scope = authorized_scope()
        scope["consent"] = {**scope["consent"], "authorizer": ""}
        scope["approvalFingerprint"] = assess.semantic_fingerprint(scope)
        self.write(scope)
        code, out = self.validate()
        self.assertEqual(code, 1)
        self.assertIn("consent.authorizer is empty", out)

    def test_invalid_target_type_is_rejected(self):
        scope = authorized_scope()
        scope["targets"][0]["type"] = "database"
        scope["approvalFingerprint"] = assess.semantic_fingerprint(scope)
        self.write(scope)
        code, out = self.validate()
        self.assertEqual(code, 1)
        self.assertIn("targets[0].type", out)

    # --- authorize 명령 ---
    def test_authorize_stamps_fingerprint_and_opens_gate(self):
        scope = copy.deepcopy(EXAMPLE)
        scope["status"] = "unauthorized"
        scope["authorizedAt"] = None
        scope["approvalFingerprint"] = None
        self.write(scope)
        code, out = self.authorize()
        self.assertEqual(code, 0, out)
        self.assertIn("cannot verify consent is genuine", out)
        stored = json.loads(self.scope_file.read_text(encoding="utf-8"))
        self.assertEqual(stored["status"], "authorized")
        self.assertEqual(stored["approvalFingerprint"], assess.semantic_fingerprint(stored))
        code, out = self.gate()
        self.assertEqual(code, 0, out)

    def test_authorize_refuses_a_malformed_scope(self):
        scope = copy.deepcopy(EXAMPLE)
        scope["targets"] = []
        self.write(scope)
        code, out = self.authorize()
        self.assertEqual(code, 1)
        self.assertIn("fix scope errors", out)

    # --- M1a: 어댑터 실행 판정 (순수 함수, 도구 미실행) ---
    def decide(self, adapter_intrusiveness, scope_intrusiveness, direct):
        adapter = {"intrusiveness": adapter_intrusiveness}
        scope = {"intrusiveness": scope_intrusiveness}
        return assess.execution_decision(adapter, scope, direct)[0]

    def test_adapter_over_scope_cap_is_forbidden(self):
        self.assertEqual(self.decide("intrusive", "active-nondestructive", True), "forbidden")
        self.assertEqual(self.decide("active-nondestructive", "passive", True), "forbidden")

    def test_nondestructive_runs_only_when_direct(self):
        self.assertEqual(self.decide("active-nondestructive", "active-nondestructive", True), "run")
        self.assertEqual(self.decide("active-nondestructive", "active-nondestructive", False), "operator")
        self.assertEqual(self.decide("passive", "intrusive", True), "run")
        self.assertEqual(self.decide("passive", "intrusive", False), "operator")

    def test_intrusive_adapter_is_operator_even_within_cap_and_direct(self):
        self.assertEqual(self.decide("intrusive", "intrusive", True), "operator")
        self.assertEqual(self.decide("intrusive", "intrusive", False), "operator")

    def test_invalid_intrusiveness_is_forbidden(self):
        self.assertEqual(self.decide("weird", "intrusive", True), "forbidden")
        self.assertEqual(self.decide("passive", "weird", True), "forbidden")

    # --- M1a: 어댑터 선언 검증 ---
    def adapter_errors(self, name, adapter):
        report = assess.Report()
        assess.validate_adapter(report, name, adapter)
        return report.errors

    def valid_adapter(self, **overrides):
        base = {"id": "semgrep", "category": "sast", "intrusiveness": "passive",
                "availability": "semgrep --version", "command": "semgrep scan {target}",
                "output_format": "sarif"}
        base.update(overrides)
        return base

    def test_valid_adapter_passes(self):
        self.assertEqual(self.adapter_errors("semgrep", self.valid_adapter()), [])

    def test_adapter_id_must_match_filename(self):
        errors = self.adapter_errors("semgrep", self.valid_adapter(id="semgrip"))
        self.assertTrue(any("does not match filename" in e for e in errors))

    def test_unknown_output_format_is_rejected_until_normalizer_exists(self):
        errors = self.adapter_errors("burp", self.valid_adapter(id="burp", category="dast", output_format="burp-xml"))
        self.assertTrue(any("no normalizer yet" in e for e in errors))

    def test_bad_category_and_intrusiveness_are_rejected(self):
        errors = self.adapter_errors("x", self.valid_adapter(id="x", category="fuzzing", intrusiveness="nuclear"))
        self.assertTrue(any("category must be" in e for e in errors))
        self.assertTrue(any("intrusiveness must be" in e for e in errors))

    def test_example_adapter_fixtures_declare_cleanly_except_pending_formats(self):
        # 픽스처는 선언 형식을 보여 준다. semgrep은 깨끗, zap/sqlmap은 정규화기/형식 대기.
        semgrep = json.loads((TOOLS_DIR.parent / "examples/adapters/semgrep.json").read_text(encoding="utf-8"))
        self.assertEqual(self.adapter_errors("semgrep", semgrep), [])

    # --- M1b: SARIF 수집·묶음 (순수 함수, 도구 미실행) ---
    def sarif(self, name):
        return json.loads((TOOLS_DIR.parent / "examples/sarif" / name).read_text(encoding="utf-8"))

    def test_sarif_ingestion_extracts_cwe_location_fingerprint(self):
        findings = assess.findings_from_sarif(self.sarif("semgrep-sample.sarif"), "semgrep")
        self.assertEqual(len(findings), 2)
        first = findings[0]
        self.assertEqual(first["cwe"], "CWE-89")
        self.assertEqual(first["location"]["function"], "UserDao.find")
        self.assertEqual(first["sources"][0], {"scanner": "semgrep", "ruleId": "rule.sql-concat", "line": 42})

    def test_same_function_and_cwe_merge_across_scanners_despite_line_shift(self):
        combined = assess.findings_from_sarif(self.sarif("semgrep-sample.sarif"), "semgrep") + \
            assess.findings_from_sarif(self.sarif("other-sample.sarif"), "other-sast")
        merged = assess.merge_findings(combined)
        self.assertEqual(len(merged), 2)
        sql = next(f for f in merged if f["cwe"] == "CWE-89")
        self.assertEqual(sorted(s["scanner"] for s in sql["sources"]), ["other-sast", "semgrep"])
        self.assertEqual([s["line"] for s in sql["sources"]], [42, 44])

    def test_different_cwe_at_same_fingerprint_stays_separate(self):
        base = assess.findings_from_sarif(self.sarif("other-sample.sarif"), "other-sast")
        variant = copy.deepcopy(base)
        variant[0]["cwe"] = "CWE-20"
        merged = assess.merge_findings(base + variant)
        self.assertEqual(len(merged), 2)

    def test_snippet_fingerprint_used_when_no_function(self):
        findings = assess.findings_from_sarif(self.sarif("semgrep-sample.sarif"), "semgrep")
        rng = next(f for f in findings if f["cwe"] == "CWE-330")
        self.assertIsNone(rng["location"]["function"])
        self.assertTrue(rng["fingerprint"])

    # --- M1b: scan 실행 경로 (execute_adapter를 교체, 실제 스캐너 미실행) ---
    def _run_scan_with_fake(self, scope, adapters, fixture_rel, direct=True):
        """execute_adapter를 교체해 픽스처(examples/ 기준 경로)를 출력에 쓴다 — 도구를 돌리지 않는다."""
        fixture = (TOOLS_DIR.parent / "examples" / fixture_rel).read_text(encoding="utf-8")
        calls = []

        def fake_execute(command_template, target, output_path, timeout=600, extra_args=()):
            calls.append((command_template, target))
            Path(output_path).write_text(fixture, encoding="utf-8")
            return 0

        adapter_dir = Path(self._tmp.name) / "adapters"
        adapter_dir.mkdir()
        for name, adapter in adapters.items():
            (adapter_dir / f"{name}.json").write_text(json.dumps(adapter), encoding="utf-8")
        findings_file = Path(self._tmp.name) / "findings.json"
        self.write(scope)
        orig_dir, orig_find, orig_exec = assess.ADAPTER_DIR, assess.FINDINGS_FILE, assess.execute_adapter
        assess.ADAPTER_DIR, assess.FINDINGS_FILE, assess.execute_adapter = adapter_dir, findings_file, fake_execute
        try:
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = assess.run_scan(direct)
            out = buffer.getvalue()
            data = json.loads(findings_file.read_text(encoding="utf-8")) if findings_file.exists() else None
        finally:
            assess.ADAPTER_DIR, assess.FINDINGS_FILE, assess.execute_adapter = orig_dir, orig_find, orig_exec
        return code, out, data, calls

    def test_scan_runs_only_run_adapters_and_writes_merged_findings(self):
        # 상한을 intrusive로 둬 sqlmap이 금지가 아니라 operator 경로를 타게 한다.
        scope = authorized_scope(intrusiveness="intrusive")
        adapters = {
            "semgrep": {"id": "semgrep", "category": "sast", "intrusiveness": "passive",
                        "availability": "semgrep --version", "command": "semgrep scan --sarif -o {output} {target}",
                        "output_format": "sarif"},
            "sqlmap": {"id": "sqlmap", "category": "dast", "intrusiveness": "intrusive",
                       "availability": "sqlmap --version", "command": "sqlmap -u {target}", "output_format": "sarif"},
        }
        code, out, data, calls = self._run_scan_with_fake(scope, adapters, "sarif/semgrep-sample.sarif", direct=True)
        self.assertEqual(code, 0, out)
        self.assertTrue(all(c[0].startswith("semgrep") for c in calls), calls)  # intrusive는 스킬이 실행 안 함
        self.assertIn("operator", out)  # sqlmap은 운영자 안내
        self.assertIsNotNone(data)
        assert data is not None
        self.assertEqual(len(data["findings"]), 2)

    def test_scan_blocks_when_gate_not_ready(self):
        scope = copy.deepcopy(EXAMPLE)
        scope["status"] = "unauthorized"
        scope["authorizedAt"] = None
        scope["approvalFingerprint"] = None
        _code_out = self._run_scan_with_fake(scope, {"semgrep": {"id": "semgrep", "category": "sast",
            "intrusiveness": "passive", "availability": "x", "command": "x {output} {target}", "output_format": "sarif"}},
            "sarif/semgrep-sample.sarif", direct=True)
        code, out, _data, calls = _code_out
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED", out)
        self.assertEqual(calls, [])  # 아무것도 실행하지 않음

    def test_scan_without_direct_only_instructs_operator(self):
        scope = authorized_scope(intrusiveness="active-nondestructive")
        adapters = {"semgrep": {"id": "semgrep", "category": "sast", "intrusiveness": "passive",
                    "availability": "x", "command": "semgrep -o {output} {target}", "output_format": "sarif"}}
        code, out, data, calls = self._run_scan_with_fake(scope, adapters, "sarif/semgrep-sample.sarif", direct=False)
        self.assertEqual(code, 0, out)
        self.assertEqual(calls, [])
        self.assertIn("operator", out)
        self.assertIn("검출을 바꾸지 않았습니다", out)
        self.assertIsNone(data)  # 아무것도 실행되지 않으면 findings를 쓰지 않는다

    # --- M1: 카테고리 → 대상 타입 매핑 ---
    def test_category_maps_to_target_types(self):
        scope = {"targets": [
            {"type": "repo", "value": "./a"}, {"type": "web", "value": "https://x.test"},
            {"type": "infra", "value": "acct-1"},
        ]}
        self.assertEqual(assess.targets_for_adapter({"category": "sast"}, scope), ["./a"])
        self.assertEqual(assess.targets_for_adapter({"category": "secret"}, scope), ["./a"])
        self.assertEqual(assess.targets_for_adapter({"category": "dast"}, scope), ["https://x.test"])
        # infra 타입은 아직 매핑되는 카테고리가 없다.
        self.assertEqual(assess.targets_for_adapter({"category": "iac"}, scope), ["./a"])

    def test_scan_skips_adapter_with_no_matching_target(self):
        scope = authorized_scope(intrusiveness="active-nondestructive",
                                 targets=[{"type": "repo", "value": "./src"}])
        scope["approvalFingerprint"] = assess.semantic_fingerprint(scope)
        adapters = {  # dast 어댑터인데 web 대상이 없다 → 실행 안 함
            "zap": {"id": "zap", "category": "dast", "intrusiveness": "active-nondestructive",
                    "availability": "x", "command": "zap -t {target} -o {output}", "output_format": "sarif"},
            "semgrep": {"id": "semgrep", "category": "sast", "intrusiveness": "passive",
                        "availability": "x", "command": "semgrep -o {output} {target}", "output_format": "sarif"},
        }
        code, out, _data, calls = self._run_scan_with_fake(scope, adapters, "sarif/semgrep-sample.sarif", direct=True)
        self.assertEqual(code, 0, out)
        self.assertIn("zap: 적용 대상 없음", out)
        self.assertTrue(all(c[0].startswith("semgrep") for c in calls), calls)  # semgrep만 실행

    # --- M1c: 정규화기 (JSON → SARIF) ---
    def osv(self):
        return json.loads((TOOLS_DIR.parent / "examples/osv/osv-sample.json").read_text(encoding="utf-8"))

    def test_osv_normalizer_maps_package_cwe_and_cvss(self):
        sarif = assess.osv_to_sarif(self.osv())
        findings = assess.findings_from_sarif(sarif, "osv")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["cwe"], "CWE-400")
        self.assertEqual(f["location"]["file"], "requirements.txt")
        self.assertEqual(f["location"]["function"], "example-lib@1.2.0")  # 지문이 패키지로 묶이도록
        self.assertEqual(f["severity"], "7.5")  # CVSS가 level에 덮이지 않음
        self.assertEqual(f["sources"][0]["ruleId"], "GHSA-xxxx-yyyy-zzzz")

    def test_normalize_dispatch_and_unknown_format(self):
        payload = {"runs": []}
        self.assertIs(assess.normalize_to_sarif("sarif", payload), payload)  # sarif는 그대로 통과
        with self.assertRaises(ValueError):
            assess.normalize_to_sarif("nope-json", {})

    def test_osv_output_format_now_validates(self):
        errors = self.adapter_errors("osv", self.valid_adapter(id="osv", category="sca", output_format="osv-json"))
        self.assertEqual(errors, [])

    def test_scan_normalizes_osv_output_into_findings(self):
        scope = authorized_scope(intrusiveness="passive", targets=[{"type": "repo", "value": "./"}])
        scope["approvalFingerprint"] = assess.semantic_fingerprint(scope)
        adapters = {"osv": {"id": "osv", "category": "sca", "intrusiveness": "passive",
                            "availability": "osv-scanner --version",
                            "command": "osv-scanner --format json -o {output} {target}", "output_format": "osv-json"}}
        code, out, data, calls = self._run_scan_with_fake(scope, adapters, "osv/osv-sample.json", direct=True)
        self.assertEqual(code, 0, out)
        self.assertIsNotNone(data)
        assert data is not None
        self.assertEqual(len(data["findings"]), 1)
        self.assertEqual(data["findings"][0]["cwe"], "CWE-400")

    # --- M1b: findings 파일 검증 ---
    def test_validate_rejects_unmerged_findings(self):
        self.write(authorized_scope())
        findings_file = self.scope_file.parent / "findings.json"
        dup = {"fingerprint": "abc", "cwe": "CWE-89", "location": {"file": "a.c"}, "sources": [{"scanner": "s", "ruleId": "r"}]}
        findings_file.write_text(json.dumps({"schemaVersion": "1.0", "generatedAt": None, "findings": [dup, dict(dup)]}), encoding="utf-8")
        orig = assess.FINDINGS_FILE
        assess.FINDINGS_FILE = findings_file
        try:
            code, out = self.validate()
        finally:
            assess.FINDINGS_FILE = orig
        self.assertEqual(code, 1)
        self.assertIn("merge was not applied", out)

    # --- M2a: 판정 레코드 ---
    def setup_findings_and_dispositions(self, findings, dispositions):
        """임시 findings/dispositions 파일을 꽂고 validate를 돌린다."""
        self.write(authorized_scope())
        ff = self.scope_file.parent / "findings.json"
        df = self.scope_file.parent / "dispositions.json"
        ff.write_text(json.dumps({"schemaVersion": "1.0", "generatedAt": None, "findings": findings}), encoding="utf-8")
        df.write_text(json.dumps({"schemaVersion": "1.0", "updatedAt": None, "dispositions": dispositions}), encoding="utf-8")
        orig_f, orig_d = assess.FINDINGS_FILE, assess.DISPOSITIONS_FILE
        assess.FINDINGS_FILE, assess.DISPOSITIONS_FILE = ff, df
        try:
            return self.validate()
        finally:
            assess.FINDINGS_FILE, assess.DISPOSITIONS_FILE = orig_f, orig_d

    def a_finding(self, fp="abc", cwe="CWE-89"):
        return {"fingerprint": fp, "cwe": cwe, "location": {"file": "a.c"}, "sources": [{"scanner": "s", "ruleId": "r"}]}

    def test_confirmed_requires_reason(self):
        code, out = self.setup_findings_and_dispositions(
            [self.a_finding()], {"abc:CWE-89": {"disposition": "confirmed", "stage": "reviewed", "reason": ""}})
        self.assertEqual(code, 1)
        self.assertIn("'confirmed' but has no reason", out)

    def test_false_positive_and_out_of_scope_require_reason(self):
        for value in ("false-positive", "out-of-scope"):
            code, out = self.setup_findings_and_dispositions(
                [self.a_finding()], {"abc:CWE-89": {"disposition": value, "stage": "reviewed", "reason": ""}})
            self.assertEqual(code, 1, value)
            self.assertIn("has no reason", out)

    def test_suspected_and_needs_review_do_not_require_reason(self):
        code, out = self.setup_findings_and_dispositions(
            [self.a_finding()], {"abc:CWE-89": {"disposition": "suspected", "stage": "in-review"}})
        self.assertEqual(code, 0, out)

    def test_handed_off_only_when_confirmed(self):
        code, out = self.setup_findings_and_dispositions(
            [self.a_finding()], {"abc:CWE-89": {"disposition": "suspected", "stage": "in-review", "handedOff": True}})
        self.assertEqual(code, 1)
        self.assertIn("handed off but disposition is 'suspected'", out)

    def test_reviewed_stage_cannot_stay_unreviewed_disposition(self):
        code, out = self.setup_findings_and_dispositions(
            [self.a_finding()], {"abc:CWE-89": {"disposition": "unreviewed", "stage": "reviewed"}})
        self.assertEqual(code, 1)
        self.assertIn("still 'unreviewed'", out)

    def test_disposition_must_reference_a_finding(self):
        code, out = self.setup_findings_and_dispositions(
            [self.a_finding()], {"nope:CWE-1": {"disposition": "suspected", "stage": "in-review"}})
        self.assertEqual(code, 1)
        self.assertIn("references no finding", out)

    def test_example_dispositions_validate_clean(self):
        semgrep = assess.merge_findings(assess.findings_from_sarif(self.sarif("semgrep-sample.sarif"), "semgrep"))
        records = json.loads((TOOLS_DIR.parent / "examples/dispositions.json").read_text(encoding="utf-8"))["dispositions"]
        code, out = self.setup_findings_and_dispositions(semgrep, records)
        self.assertEqual(code, 0, out)

    def test_disposition_summary_counts_missing_as_unreviewed(self):
        findings = [self.a_finding("f1", "CWE-89"), self.a_finding("f2", "CWE-330"), self.a_finding("f3", "")]
        records = {"f1:CWE-89": {"disposition": "confirmed", "stage": "reviewed", "handedOff": True}}
        summary = assess.disposition_summary(findings, records)
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["byDisposition"], {"confirmed": 1, "unreviewed": 2})
        self.assertEqual(summary["byStage"], {"reviewed": 1, "unreviewed": 2})
        self.assertEqual(summary["handedOff"], 1)

    # --- M2b: SARIF 다리 ---
    def test_is_code_level_excludes_urls(self):
        self.assertTrue(assess.is_code_level({"location": {"file": "src/A.java"}}))
        self.assertFalse(assess.is_code_level({"location": {"file": "https://x.test"}}))
        self.assertFalse(assess.is_code_level({"location": {"file": ""}}))

    def test_build_handoff_sarif_includes_only_confirmed_code(self):
        findings = [
            self.a_finding("fp1", "CWE-89"),                         # confirmed code
            self.a_finding("fp2", "CWE-330"),                        # false-positive
            {"fingerprint": "fp3", "cwe": "CWE-79", "location": {"file": "https://x.test"},
             "sources": [{"scanner": "zap", "ruleId": "r"}]},        # confirmed but web
        ]
        records = {
            "fp1:CWE-89": {"disposition": "confirmed", "stage": "reviewed", "reason": "실제 주입"},
            "fp2:CWE-330": {"disposition": "false-positive", "stage": "reviewed", "reason": "영향 없음"},
            "fp3:CWE-79": {"disposition": "confirmed", "stage": "reviewed", "reason": "웹"},
        }
        sarif = assess.build_handoff_sarif(findings, records)
        results = sarif["runs"][0]["results"]
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["ruleId"], "CWE-89")
        self.assertIn("confirmed: 실제 주입", results[0]["message"]["text"])

    def _run_bridge(self, findings, dispositions, dry_run=False, include_all=False):
        ff = self.scope_file.parent / "findings.json"
        df = self.scope_file.parent / "dispositions.json"
        hf = self.scope_file.parent / "handoff.sarif"
        ff.write_text(json.dumps({"schemaVersion": "1.0", "generatedAt": None, "findings": findings}), encoding="utf-8")
        df.write_text(json.dumps({"schemaVersion": "1.0", "updatedAt": None, "dispositions": dispositions}), encoding="utf-8")
        orig = (assess.FINDINGS_FILE, assess.DISPOSITIONS_FILE, assess.HANDOFF_SARIF)
        assess.FINDINGS_FILE, assess.DISPOSITIONS_FILE, assess.HANDOFF_SARIF = ff, df, hf
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = assess.run_bridge(dry_run, include_all)
            sarif = json.loads(hf.read_text(encoding="utf-8")) if hf.exists() else None
            disp = json.loads(df.read_text(encoding="utf-8"))["dispositions"]
            return code, buf.getvalue(), sarif, disp
        finally:
            assess.FINDINGS_FILE, assess.DISPOSITIONS_FILE, assess.HANDOFF_SARIF = orig

    def test_bridge_exports_and_marks_handed_off(self):
        findings = [self.a_finding("fp1", "CWE-89")]
        dispositions = {"fp1:CWE-89": {"disposition": "confirmed", "stage": "reviewed", "reason": "실제"}}
        code, out, sarif, disp = self._run_bridge(findings, dispositions)
        self.assertEqual(code, 0, out)
        assert sarif is not None
        self.assertEqual(len(sarif["runs"][0]["results"]), 1)
        self.assertTrue(disp["fp1:CWE-89"]["handedOff"])  # 넘김 표시됨

    def test_bridge_does_not_re_export_already_handed_off(self):
        findings = [self.a_finding("fp1", "CWE-89")]
        dispositions = {"fp1:CWE-89": {"disposition": "confirmed", "stage": "reviewed", "reason": "x", "handedOff": True}}
        code, out, sarif, disp = self._run_bridge(findings, dispositions)
        self.assertEqual(code, 0)
        self.assertIn("없습니다", out)
        self.assertIsNone(sarif)  # 파일을 쓰지 않음

    def test_bridge_dry_run_does_not_write_or_mark(self):
        findings = [self.a_finding("fp1", "CWE-89")]
        dispositions = {"fp1:CWE-89": {"disposition": "confirmed", "stage": "reviewed", "reason": "x"}}
        code, out, sarif, disp = self._run_bridge(findings, dispositions, dry_run=True)  # noqa
        self.assertEqual(code, 0)
        self.assertIn("dry-run", out)
        self.assertIsNone(sarif)
        self.assertNotIn("handedOff", disp["fp1:CWE-89"])

    def test_bridge_all_re_exports_handed_off(self):
        findings = [self.a_finding("fp1", "CWE-89")]
        dispositions = {"fp1:CWE-89": {"disposition": "confirmed", "stage": "reviewed", "reason": "x", "handedOff": True}}
        code, _out, sarif, _disp = self._run_bridge(findings, dispositions, include_all=True)
        self.assertEqual(code, 0)
        assert sarif is not None
        self.assertEqual(len(sarif["runs"][0]["results"]), 1)

    # --- M2c: 증적 워크북(CSV) + 표지 보고서(MD) ---
    def evidence_fixture(self):
        findings = assess.merge_findings(assess.findings_from_sarif(self.sarif("semgrep-sample.sarif"), "semgrep"))
        records = json.loads((TOOLS_DIR.parent / "examples/dispositions.json").read_text(encoding="utf-8"))["dispositions"]
        return findings, records

    def test_evidence_csv_has_header_and_one_row_per_finding(self):
        import csv
        findings, records = self.evidence_fixture()
        rows = list(csv.reader(assess.render_evidence_csv(findings, records).splitlines()))
        self.assertEqual(tuple(rows[0]), assess.EVIDENCE_COLUMNS)
        self.assertEqual(len(rows), 1 + len(findings))
        by_cwe = {r[1]: r for r in rows[1:]}
        self.assertEqual(by_cwe["CWE-89"][6], "confirmed")
        handed_col = assess.EVIDENCE_COLUMNS.index("handedOff")
        self.assertEqual(by_cwe["CWE-89"][handed_col], "true")
        self.assertEqual(by_cwe["CWE-89"][assess.EVIDENCE_COLUMNS.index("decidedBy")], "ai")
        self.assertEqual(by_cwe["CWE-330"][6], "false-positive")

    def test_unreviewed_finding_appears_as_unreviewed_in_csv(self):
        import csv
        rows = list(csv.reader(assess.render_evidence_csv([self.a_finding("z", "CWE-1")], {}).splitlines()))
        self.assertEqual(rows[1][6:8], ["unreviewed", "unreviewed"])

    def test_cover_numbers_match_workbook(self):
        import csv
        findings, records = self.evidence_fixture()
        rows = list(csv.reader(assess.render_evidence_csv(findings, records).splitlines()))[1:]
        cover = assess.render_cover_md(EXAMPLE, findings, records, "2026-10-22T00:00:00Z")
        self.assertIn(f"전체 검출 {len(rows)}건", cover)
        handed = sum(1 for r in rows if r[assess.EVIDENCE_COLUMNS.index("handedOff")] == "true")
        self.assertIn(f"넘김 {handed}건", cover)
        for disposition in {r[6] for r in rows}:
            count = sum(1 for r in rows if r[6] == disposition)
            self.assertIn(f"| {disposition} | {count} |", cover)
        self.assertIn("동의의 진위를 검증하지 않는다", cover)  # 게이트 한계 명시

    def test_rendering_is_deterministic(self):
        findings, records = self.evidence_fixture()
        self.assertEqual(assess.render_evidence_csv(findings, records),
                         assess.render_evidence_csv(list(reversed(findings)), records))

    def _with_evidence_paths(self, fn):
        base = self.scope_file.parent
        names = ("FINDINGS_FILE", "DISPOSITIONS_FILE", "EVIDENCE_CSV", "COVER_MD")
        orig = {n: getattr(assess, n) for n in names}
        assess.FINDINGS_FILE = base / "findings.json"
        assess.DISPOSITIONS_FILE = base / "dispositions.json"
        assess.EVIDENCE_CSV = base / "evidence" / "findings.csv"
        assess.COVER_MD = base / "evidence" / "cover.md"
        try:
            return fn()
        finally:
            for n, v in orig.items():
                setattr(assess, n, v)

    def test_evidence_then_validate_passes_and_detects_drift(self):
        findings, records = self.evidence_fixture()
        self.write(authorized_scope())

        def body():
            assess.FINDINGS_FILE.write_text(json.dumps({"schemaVersion": "1.0", "generatedAt": "2026-10-22T00:00:00Z", "findings": findings}), encoding="utf-8")
            assess.DISPOSITIONS_FILE.write_text(json.dumps({"schemaVersion": "1.0", "updatedAt": None, "dispositions": records}), encoding="utf-8")
            buf = io.StringIO()
            with redirect_stdout(buf):
                self.assertEqual(assess.run_evidence(), 0)
            code, out = self.validate()
            self.assertEqual(code, 0, out)
            # 판정을 바꾸고 evidence를 다시 안 돌리면 드리프트 에러
            changed = dict(records)
            changed["e778ea7e9751f862:CWE-330"] = {"disposition": "suspected", "stage": "in-review"}
            assess.DISPOSITIONS_FILE.write_text(json.dumps({"schemaVersion": "1.0", "updatedAt": None, "dispositions": changed}), encoding="utf-8")
            code, out = self.validate()
            self.assertEqual(code, 1)
            self.assertIn("findings.csv is out of date", out)
            self.assertIn("cover.md is out of date", out)

        self._with_evidence_paths(body)

    def test_hand_written_cover_is_warned_not_checked(self):
        findings, records = self.evidence_fixture()
        self.write(authorized_scope())

        def body():
            assess.FINDINGS_FILE.write_text(json.dumps({"schemaVersion": "1.0", "generatedAt": None, "findings": findings}), encoding="utf-8")
            assess.DISPOSITIONS_FILE.write_text(json.dumps({"schemaVersion": "1.0", "updatedAt": None, "dispositions": records}), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                assess.run_evidence()
            assess.COVER_MD.write_text("# 손으로 쓴 보고서\n", encoding="utf-8")
            code, out = self.validate()
            self.assertEqual(code, 0, out)
            self.assertIn("cover.md is hand-written", out)

        self._with_evidence_paths(body)

    # --- 점검 결함 1: scan이 기존 검출을 지우지 않는다 ---
    def _scan_env(self):
        """findings·어댑터·실행부를 임시 위치로 돌리는 컨텍스트 값과 복구 함수."""
        base = Path(self._tmp.name)
        adapter_dir = base / "adapters"
        adapter_dir.mkdir(exist_ok=True)
        orig = (assess.ADAPTER_DIR, assess.FINDINGS_FILE, assess.DISPOSITIONS_FILE, assess.execute_adapter)
        assess.ADAPTER_DIR, assess.FINDINGS_FILE, assess.DISPOSITIONS_FILE = adapter_dir, base / "findings.json", base / "dispositions.json"

        def restore():
            assess.ADAPTER_DIR, assess.FINDINGS_FILE, assess.DISPOSITIONS_FILE, assess.execute_adapter = orig
        return adapter_dir, restore

    def _set_adapter(self, adapter_dir, name, sarif_doc, category="sast", intrusiveness="passive"):
        (adapter_dir / f"{name}.json").write_text(json.dumps({
            "id": name, "category": category, "intrusiveness": intrusiveness, "availability": "x",
            "command": f"{name} -o {{output}} {{target}}", "output_format": "sarif"}), encoding="utf-8")
        self._fixtures = getattr(self, "_fixtures", {})
        self._fixtures[name] = json.dumps(sarif_doc)

        def fake_execute(command_template, target, output_path, timeout=600, extra_args=()):
            Path(output_path).write_text(self._fixtures[command_template.split()[0]], encoding="utf-8")
            return 0
        assess.execute_adapter = fake_execute

    def _scan(self, direct=True):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = assess.run_scan(direct)
        return code, buf.getvalue()

    def _findings(self):
        return json.loads(assess.FINDINGS_FILE.read_text(encoding="utf-8"))["findings"]

    def test_scan_without_direct_keeps_previous_findings(self):
        self.write(authorized_scope(intrusiveness="passive", targets=[{"type": "repo", "value": "./src"}]))
        adapter_dir, restore = self._scan_env()
        try:
            self._set_adapter(adapter_dir, "semgrep", self.sarif("semgrep-sample.sarif"))
            self.assertEqual(self._scan(direct=True)[0], 0)
            self.assertEqual(len(self._findings()), 2)
            code, out = self._scan(direct=False)
            self.assertEqual(code, 0, out)
            self.assertEqual(len(self._findings()), 2)  # 지워지지 않음
        finally:
            restore()

    def test_running_one_adapter_keeps_other_adapters_results(self):
        self.write(authorized_scope(intrusiveness="passive", targets=[{"type": "repo", "value": "./src"}]))
        adapter_dir, restore = self._scan_env()
        try:
            self._set_adapter(adapter_dir, "semgrep", self.sarif("semgrep-sample.sarif"))
            self._set_adapter(adapter_dir, "other", self.sarif("other-sample.sarif"))
            self._scan()
            # semgrep이 이번에 실행되지 않아도(상한 초과로 건너뜀) semgrep 결과는 남는다
            self._set_adapter(adapter_dir, "semgrep", self.sarif("semgrep-sample.sarif"), intrusiveness="intrusive")
            _code, out = self._scan()
            self.assertIn("semgrep: forbidden", out)
            self.assertIn("실행 other", out)
            self.assertEqual({f["cwe"] for f in self._findings()}, {"CWE-89", "CWE-330"})
        finally:
            restore()

    def test_existing_findings_are_preserved_on_upgrade(self):
        self.write(authorized_scope(intrusiveness="passive", targets=[{"type": "repo", "value": "./src"}]))
        adapter_dir, restore = self._scan_env()
        try:
            legacy = assess.merge_findings(assess.findings_from_sarif(self.sarif("semgrep-sample.sarif"), "semgrep"))
            assess.FINDINGS_FILE.write_text(json.dumps({"schemaVersion": "1.0", "generatedAt": None, "findings": legacy}), encoding="utf-8")
            other = self.sarif("other-sample.sarif")
            other["runs"][0]["results"][0]["locations"][0]["logicalLocations"][0]["fullyQualifiedName"] = "Other.fn"
            self._set_adapter(adapter_dir, "other", other)
            self._scan()
            self.assertEqual(len(self._findings()), 3)  # 이전 2건 + 새 1건
        finally:
            restore()

    def test_half_written_scan_result_stops_scan_and_is_named(self):
        self.write(authorized_scope(intrusiveness="passive", targets=[{"type": "repo", "value": "./src"}]))
        adapter_dir, restore = self._scan_env()
        try:
            self._set_adapter(adapter_dir, "semgrep", self.sarif("semgrep-sample.sarif"))
            self._scan()
            (assess.scans_dir() / "semgrep.json").write_text('{"findings": [', encoding="utf-8")
            code, out = self._scan()
            self.assertEqual(code, 1)
            self.assertIn("data/scans/semgrep.json", out)
            code, out = self.validate()
            self.assertEqual(code, 1)
            self.assertIn("data/scans/semgrep.json", out)
        finally:
            restore()

    # --- 점검 결함 2: 제외 자산 ---
    def test_is_excluded_paths_urls_and_hosts(self):
        ex = ["src/dao", "https://staging.example.test/admin", "prod.example.test"]
        self.assertTrue(assess.is_excluded("src/dao/UserDao.java", ex))
        self.assertTrue(assess.is_excluded("./src/dao", ex))
        self.assertFalse(assess.is_excluded("src/daolike/X.java", ex))  # 경로 경계
        self.assertTrue(assess.is_excluded("https://staging.example.test/admin/users", ex))
        self.assertFalse(assess.is_excluded("https://staging.example.test/administrator", ex))
        self.assertTrue(assess.is_excluded("https://api.prod.example.test/x", ex))
        self.assertFalse(assess.is_excluded("https://staging.example.test/", ex))

    def test_scan_drops_findings_in_excluded_assets(self):
        scope = authorized_scope(intrusiveness="passive", targets=[{"type": "repo", "value": "./src"}],
                                 exclusions=["src/dao"])
        scope["approvalFingerprint"] = assess.semantic_fingerprint(scope)
        self.write(scope)
        adapter_dir, restore = self._scan_env()
        try:
            self._set_adapter(adapter_dir, "semgrep", self.sarif("semgrep-sample.sarif"))
            code, out = self._scan()
            self.assertIn("제외 자산 1건 제외", out)
            self.assertEqual([f["location"]["file"] for f in self._findings()], ["src/util/Token.java"])
        finally:
            restore()

    def test_validate_rejects_findings_in_excluded_assets(self):
        scope = authorized_scope(exclusions=["src/dao"])
        scope["approvalFingerprint"] = assess.semantic_fingerprint(scope)
        self.write(scope)
        orig = assess.FINDINGS_FILE
        assess.FINDINGS_FILE = self.scope_file.parent / "findings.json"
        try:
            assess.FINDINGS_FILE.write_text(json.dumps({"schemaVersion": "1.0", "generatedAt": None, "findings": [
                {"fingerprint": "f", "cwe": "CWE-89", "location": {"file": "src/dao/A.java"}, "sources": [{"scanner": "s", "ruleId": "r"}]}]}),
                encoding="utf-8")
            code, out = self.validate()
        finally:
            assess.FINDINGS_FILE = orig
        self.assertEqual(code, 1)
        self.assertIn("excluded asset", out)

    # --- 점검 결함 3: 차수와 해소 판단 ---
    def test_round_resolution_requires_the_finding_adapter_to_rerun(self):
        prev = [
            {"fingerprint": "a", "cwe": "CWE-89", "sources": [{"adapter": "semgrep"}]},
            {"fingerprint": "b", "cwe": "CWE-79", "sources": [{"adapter": "zap"}]},
            {"fingerprint": "c", "cwe": "CWE-1", "sources": [{"adapter": "semgrep"}]},
        ]
        current = [{"fingerprint": "c", "cwe": "CWE-1", "sources": [{"adapter": "semgrep"}]}]
        result = assess.round_resolution(prev, current, {"semgrep"})
        self.assertEqual(result, {"resolved": ["a:CWE-89"], "notRechecked": ["b:CWE-79"]})

    def test_handed_off_finding_disappearing_next_round_is_resolved_not_an_error(self):
        self.write(authorized_scope(intrusiveness="passive", targets=[{"type": "repo", "value": "./src"}]))
        adapter_dir, restore = self._scan_env()
        try:
            self._set_adapter(adapter_dir, "semgrep", self.sarif("semgrep-sample.sarif"))
            self._scan()
            records = json.loads((TOOLS_DIR.parent / "examples/dispositions.json").read_text(encoding="utf-8"))
            assess.DISPOSITIONS_FILE.write_text(json.dumps(records), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(assess.run_new_round(), 0)
            fixed = self.sarif("semgrep-sample.sarif")
            fixed["runs"][0]["results"] = fixed["runs"][0]["results"][1:]  # SQL 결함이 고쳐짐
            self._set_adapter(adapter_dir, "semgrep", fixed)
            self._scan()
            code, out = self.validate()
            self.assertNotIn("references no finding", out)
            buf = io.StringIO()
            with redirect_stdout(buf):
                assess.run_dispositions()
            summary = json.loads(buf.getvalue())
            self.assertEqual(summary["sincePreviousRound"]["resolved"], ["7872908dde452cab:CWE-89"])
            self.assertEqual(summary["sincePreviousRound"]["notRechecked"], [])
        finally:
            restore()

    def test_disposition_for_unknown_key_is_still_an_error(self):
        code, out = self.setup_findings_and_dispositions(
            [self.a_finding()], {"nope:CWE-1": {"disposition": "suspected", "stage": "in-review"}})
        self.assertEqual(code, 1)
        self.assertIn("references no finding", out)

    # --- 판정 주체 ---
    def test_ai_cannot_close_a_finding_as_reviewed(self):
        for value in ("false-positive", "out-of-scope"):
            code, out = self.setup_findings_and_dispositions([self.a_finding()], {"abc:CWE-89": {
                "disposition": value, "stage": "reviewed", "reason": "근거", "decidedBy": "ai"}})
            self.assertEqual(code, 1, value)
            self.assertIn("only the user can confirm it", out)

    def test_ai_may_propose_closing_while_in_review_and_confirm_findings(self):
        code, out = self.setup_findings_and_dispositions(
            [self.a_finding("f1"), self.a_finding("f2")], {
                "f1:CWE-89": {"disposition": "false-positive", "stage": "in-review", "reason": "근거", "decidedBy": "ai"},
                "f2:CWE-89": {"disposition": "confirmed", "stage": "reviewed", "reason": "근거", "decidedBy": "ai"}})
        self.assertEqual(code, 0, out)
        self.assertNotIn("WARN", out)

    def test_user_may_close_a_finding(self):
        code, out = self.setup_findings_and_dispositions([self.a_finding()], {"abc:CWE-89": {
            "disposition": "false-positive", "stage": "reviewed", "reason": "근거", "decidedBy": "user"}})
        self.assertEqual(code, 0, out)

    def test_reviewed_without_decided_by_is_a_warning_and_bad_value_an_error(self):
        code, out = self.setup_findings_and_dispositions([self.a_finding()], {"abc:CWE-89": {
            "disposition": "confirmed", "stage": "reviewed", "reason": "근거"}})
        self.assertEqual(code, 0, out)
        self.assertIn("has no decidedBy", out)
        code, out = self.setup_findings_and_dispositions([self.a_finding()], {"abc:CWE-89": {
            "disposition": "suspected", "stage": "in-review", "decidedBy": "boss"}})
        self.assertEqual(code, 1)
        self.assertIn("decidedBy must be one of", out)

    def test_summary_and_cover_count_who_decided(self):
        findings = [self.a_finding("f1"), self.a_finding("f2"), self.a_finding("f3")]
        records = {"f1:CWE-89": {"disposition": "confirmed", "stage": "reviewed", "decidedBy": "ai"},
                   "f2:CWE-89": {"disposition": "false-positive", "stage": "reviewed", "decidedBy": "user"},
                   "f3:CWE-89": {"disposition": "confirmed", "stage": "reviewed"}}
        summary = assess.disposition_summary(findings, records)
        self.assertEqual(summary["reviewedBy"], {"ai": 1, "user": 1, "unrecorded": 1})
        cover = assess.render_cover_md(EXAMPLE, findings, records, None)
        self.assertIn("| user | 1 |", cover)
        self.assertIn("| unrecorded | 1 |", cover)

    # --- 운영자 출력 들여오기 ---
    def _ingest(self, adapter, file, target=None):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = assess.run_ingest(adapter, str(file) if file else None, target)
        return code, buf.getvalue()

    def _operator_file(self, name, doc):
        path = Path(self._tmp.name) / name
        path.write_text(json.dumps(doc), encoding="utf-8")
        return path

    def test_ingest_collects_operator_output_like_scan(self):
        self.write(authorized_scope(intrusiveness="intrusive", targets=[{"type": "repo", "value": "./src"}]))
        adapter_dir, restore = self._scan_env()
        try:
            self._set_adapter(adapter_dir, "semgrep", self.sarif("semgrep-sample.sarif"), intrusiveness="intrusive")
            out_file = self._operator_file("semgrep.sarif", self.sarif("semgrep-sample.sarif"))
            code, out = self._ingest("semgrep", out_file)
            self.assertEqual(code, 0, out)
            findings = self._findings()
            self.assertEqual(len(findings), 2)
            source = findings[0]["sources"][0]
            self.assertEqual((source["adapter"], source["target"], source["collectedBy"]), ("semgrep", "./src", "operator"))
            stored = json.loads((assess.scans_dir() / "semgrep.json").read_text(encoding="utf-8"))
            self.assertEqual(stored["ingested"][0]["file"], "semgrep.sarif")
            self.assertEqual(len(stored["ingested"][0]["sha256"]), 64)
            self.assertEqual(self.validate()[0], 0)
        finally:
            restore()

    def test_ingest_refuses_when_gate_blocked_or_adapter_forbidden(self):
        scope = authorized_scope(intrusiveness="passive", targets=[{"type": "repo", "value": "./src"}])
        self.write(scope)
        adapter_dir, restore = self._scan_env()
        try:
            self._set_adapter(adapter_dir, "sqlmapish", self.sarif("semgrep-sample.sarif"), intrusiveness="intrusive")
            out_file = self._operator_file("x.sarif", self.sarif("semgrep-sample.sarif"))
            code, out = self._ingest("sqlmapish", out_file)
            self.assertEqual(code, 1)
            self.assertIn("거부", out)
            scope["status"] = "unauthorized"
            self.write(scope)
            code, out = self._ingest("sqlmapish", out_file)
            self.assertEqual(code, 1)
            self.assertIn("BLOCKED", out)
            self.assertFalse(assess.FINDINGS_FILE.exists())
        finally:
            restore()

    def test_ingest_needs_a_scope_target(self):
        self.write(authorized_scope(intrusiveness="passive", targets=[
            {"type": "repo", "value": "./a"}, {"type": "repo", "value": "./b"}]))
        adapter_dir, restore = self._scan_env()
        try:
            self._set_adapter(adapter_dir, "semgrep", self.sarif("semgrep-sample.sarif"))
            out_file = self._operator_file("s.sarif", self.sarif("semgrep-sample.sarif"))
            code, out = self._ingest("semgrep", out_file)
            self.assertEqual(code, 1)
            self.assertIn("--target이 필요합니다", out)
            code, out = self._ingest("semgrep", out_file, "./elsewhere")
            self.assertEqual(code, 1)
            self.assertIn("스코프 대상이 아닙니다", out)
        finally:
            restore()

    def test_ingest_replaces_only_that_target(self):
        self.write(authorized_scope(intrusiveness="passive", targets=[
            {"type": "repo", "value": "./a"}, {"type": "repo", "value": "./b"}]))
        adapter_dir, restore = self._scan_env()
        try:
            self._set_adapter(adapter_dir, "semgrep", self.sarif("semgrep-sample.sarif"))
            full = self._operator_file("full.sarif", self.sarif("semgrep-sample.sarif"))
            self._ingest("semgrep", full, "./a")
            other = self._operator_file("other.sarif", self.sarif("other-sample.sarif"))
            self._ingest("semgrep", other, "./b")
            before = {(f["fingerprint"], f["cwe"]) for f in self._findings()}
            empty = self.sarif("semgrep-sample.sarif")
            empty["runs"][0]["results"] = []
            code, out = self._ingest("semgrep", self._operator_file("empty.sarif", empty), "./a")
            self.assertEqual(code, 0, out)
            stored = json.loads((assess.scans_dir() / "semgrep.json").read_text(encoding="utf-8"))
            self.assertEqual({s["target"] for f in stored["findings"] for s in f["sources"]}, {"./b"})
            self.assertEqual([e["target"] for e in stored["ingested"]], ["./b", "./a"])
            self.assertLess(len(self._findings()), len(before))
        finally:
            restore()

    def test_replace_target_findings_treats_unmarked_results_by_target_list(self):
        old = {"fingerprint": "o", "cwe": "", "sources": [{"scanner": "s", "ruleId": "r"}]}
        new = {"fingerprint": "n", "cwe": "", "sources": [{"scanner": "s", "ruleId": "r", "target": "./a"}]}
        self.assertEqual(assess.replace_target_findings({"targets": ["./a"], "findings": [old]}, "./a", [new]), [new])
        self.assertEqual(assess.replace_target_findings({"targets": ["./a", "./b"], "findings": [old]}, "./a", [new]), [old, new])

    def test_scan_tags_sources_as_collected_by_skill(self):
        self.write(authorized_scope(intrusiveness="passive", targets=[{"type": "repo", "value": "./src"}]))
        adapter_dir, restore = self._scan_env()
        try:
            self._set_adapter(adapter_dir, "semgrep", self.sarif("semgrep-sample.sarif"))
            self._scan()
            source = self._findings()[0]["sources"][0]
            self.assertEqual((source["target"], source["collectedBy"]), ("./src", "skill"))
        finally:
            restore()

    def test_operator_instruction_names_the_ingest_command(self):
        self.write(authorized_scope(intrusiveness="passive", targets=[{"type": "repo", "value": "./src"}]))
        adapter_dir, restore = self._scan_env()
        try:
            self._set_adapter(adapter_dir, "semgrep", self.sarif("semgrep-sample.sarif"))
            _code, out = self._scan(direct=False)
            self.assertIn("ingest --adapter semgrep --file <출력 파일> --target ./src", out)
        finally:
            restore()

    # --- 웹 스캔 (ADR 0003) ---
    WEB = "https://staging.example.test"

    def zap_sample(self):
        return json.loads((TOOLS_DIR.parent / "examples/zap/zap-sample.json").read_text(encoding="utf-8"))

    def example_adapter(self, name):
        return json.loads((TOOLS_DIR.parent / "examples/adapters" / f"{name}.json").read_text(encoding="utf-8"))

    def test_url_fingerprint_ignores_query_values_and_ids(self):
        findings = assess.merge_findings(assess.findings_from_sarif(assess.zap_to_sarif(self.zap_sample()), "zap"))
        self.assertEqual(len(findings), 2)  # 같은 헤더 결함 두 인스턴스는 하나로, XSS는 따로
        header = next(f for f in findings if f["cwe"] == "CWE-693")
        self.assertEqual(header["location"]["web"]["path"], "staging.example.test/orders/{n}")
        self.assertEqual(header["location"]["web"]["params"], ["token", "view", "x-content-type-options"])
        xss = next(f for f in findings if f["cwe"] == "CWE-79")
        self.assertEqual(xss["location"]["web"], {"method": "GET", "path": "staging.example.test/search", "params": ["q"]})

    def test_web_path_normalizes_ids(self):
        self.assertEqual(assess.normalize_web_path("https://A.test/u/42/doc/550e8400-e29b-41d4-a716-446655440000/"),
                         "a.test/u/{n}/doc/{id}")

    def test_rate_limit_is_semantic_only_for_web_and_keeps_old_fingerprints(self):
        scope = copy.deepcopy(EXAMPLE)
        for target in scope["targets"]:
            for field in ("rateLimit", "regions", "credential"):
                target.pop(field, None)
        old_material = {
            "targets": sorted((t["type"], t["value"]) for t in scope["targets"]),
            "exclusions": sorted(scope["exclusions"]), "window": scope["window"],
            "consent": {k: scope["consent"][k] for k in ("authorizer", "role", "date", "reference")},
            "intrusiveness": scope["intrusiveness"],
        }
        import hashlib
        old = hashlib.sha256(json.dumps(old_material, ensure_ascii=False, sort_keys=True).encode()).hexdigest()
        self.assertEqual(assess.semantic_fingerprint(scope), old)  # 상한 없는 스코프의 기존 승인은 유지
        scope["targets"][1]["rateLimit"] = 10
        self.assertNotEqual(assess.semantic_fingerprint(scope), old)
        scope["targets"][0]["rateLimit"] = 3
        report = assess.Report()
        assess.validate_scope(report, scope)
        self.assertTrue(any("web targets only" in e for e in report.errors))

    def test_exclusions_for_target_and_scope_args(self):
        relevant = assess.exclusions_for_target(self.WEB, [
            "https://staging.example.test/admin", "api.staging.example.test", "prod.example.test", "src/dao"])
        self.assertEqual(relevant, {"hosts": ["api.staging.example.test"], "urls": ["https://staging.example.test/admin"]})
        nuclei = self.example_adapter("nuclei")
        args, why = assess.web_scope_args(nuclei, relevant)
        self.assertIsNone(args)
        self.assertIn("exclude_url", why)
        args, _ = assess.web_scope_args(nuclei, {"hosts": ["api.staging.example.test"], "urls": []})
        self.assertEqual(args, ["-exclude-hosts", "api.staging.example.test"])

    def test_render_command_fills_container_placeholders(self):
        argv = assess.render_command(self.example_adapter("nuclei")["command"], self.WEB,
                                     Path("/tmp/x/nuclei.out"), ["-rate-limit", "10"])
        self.assertIn("/tmp/x:/out", argv)
        self.assertIn("/out/nuclei.out", argv)
        self.assertEqual(argv[-2:], ["-rate-limit", "10"])

    def test_web_adapter_without_rate_or_scope_control_is_operator_only(self):
        zap = self.example_adapter("zap-baseline")
        self.assertEqual(len(assess.web_direct_blockers(zap)), 2)
        self.assertEqual(assess.web_direct_blockers(self.example_adapter("nuclei")), [])

    def test_web_adapter_fields_are_validated(self):
        bad = self.valid_adapter(id="w", category="dast", rate_limit="-rl", coverage={"mode": "url-list"},
                                 scope_control={"stays_on_target": "yes", "exclude_host": "-eh"}, max_seconds=0)
        errors = self.adapter_errors("w", bad)
        for text in ("rate_limit must contain", "coverage.file is required", "stays_on_target must be",
                     "exclude_host must contain", "max_seconds must be"):
            self.assertTrue(any(text in e for e in errors), text)

    def _web_scan_env(self, exclusions=(), window_end="2026-10-29"):
        scope = authorized_scope(intrusiveness="active-nondestructive",
                                 targets=[{"type": "web", "value": self.WEB, "rateLimit": 7}],
                                 exclusions=list(exclusions), window={"start": "2026-10-22", "end": window_end})
        self.write(scope)
        adapter_dir, restore = self._scan_env()
        (adapter_dir / "nuclei.json").write_text(json.dumps(self.example_adapter("nuclei")), encoding="utf-8")
        calls = []

        def fake_execute(command_template, target, output_path, timeout=600, extra_args=()):
            calls.append({"target": target, "timeout": timeout, "args": list(extra_args),
                          "argv": assess.render_command(command_template, target, Path(output_path), extra_args)})
            Path(output_path).write_text(json.dumps(self.sarif("nuclei-sample.sarif")), encoding="utf-8")
            return 0
        assess.execute_adapter = fake_execute
        return calls, restore

    def _scan_confirm(self, confirm):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = assess.run_scan(True, confirm)
        return code, buf.getvalue()

    def test_web_scan_runs_only_with_the_plan_confirmation_code(self):
        calls, restore = self._web_scan_env(exclusions=["api.staging.example.test"])
        try:
            code, out = self._scan_confirm(None)
            self.assertEqual(code, 0, out)
            self.assertEqual(calls, [])
            self.assertIn("초당 7건 이하", out)
            self.assertIn("api.staging.example.test", out)
            match = re.search(r"확인 코드: (\w+)", out)
            assert match is not None, out
            plan_code = match.group(1)
            code, out = self._scan_confirm("wrong")
            self.assertEqual(calls, [])
            self.assertIn("계획과 다릅니다", out)
            code, out = self._scan_confirm(plan_code)
            self.assertEqual(code, 0, out)
            self.assertEqual(calls[0]["args"], ["-exclude-hosts", "api.staging.example.test", "-rate-limit", "7"])
            self.assertLessEqual(calls[0]["timeout"], 900)
            stored = json.loads((assess.scans_dir() / "nuclei.json").read_text(encoding="utf-8"))
            self.assertEqual(stored["coverage"], {self.WEB: {"mode": "fixed-probes"}})
            self.assertEqual(self._findings()[0]["location"]["web"]["path"], "staging.example.test/.git/config")
        finally:
            restore()

    def test_web_scan_refuses_targets_with_unpassable_exclusions(self):
        calls, restore = self._web_scan_env(exclusions=["https://staging.example.test/admin"])
        try:
            code, out = self._scan_confirm(None)
            self.assertIn("거부", out)
            self.assertNotIn("확인 코드", out)
            self.assertEqual(calls, [])
        finally:
            restore()

    def test_web_time_limit_stops_at_window_end(self):
        adapter = {"max_seconds": 900}
        scope = {"window": {"end": "2026-10-24"}}
        late = datetime(2026, 10, 24, 23, 55, tzinfo=timezone.utc)
        self.assertEqual(assess.web_time_limit(adapter, scope, late), 299)
        self.assertLessEqual(assess.web_time_limit(adapter, scope, datetime(2026, 10, 25, tzinfo=timezone.utc)), 0)

    def test_ingest_refuses_web_output_when_exclusions_cannot_be_enforced(self):
        self.write(authorized_scope(intrusiveness="active-nondestructive",
                                    targets=[{"type": "web", "value": self.WEB}],
                                    exclusions=["https://staging.example.test/admin"]))
        adapter_dir, restore = self._scan_env()
        try:
            (adapter_dir / "zap-baseline.json").write_text(json.dumps(self.example_adapter("zap-baseline")), encoding="utf-8")
            out_file = Path(self._tmp.name) / "zap.json"
            out_file.write_text(json.dumps(self.zap_sample()), encoding="utf-8")
            code, out = self._ingest("zap-baseline", out_file)
            self.assertEqual(code, 1)
            self.assertIn("들여오지 않습니다", out)
        finally:
            restore()

    def test_ingest_web_output_records_url_list_coverage(self):
        self.write(authorized_scope(intrusiveness="active-nondestructive", targets=[{"type": "web", "value": self.WEB}],
                                    exclusions=[]))
        adapter_dir, restore = self._scan_env()
        try:
            zap = self.example_adapter("zap-baseline")
            zap["coverage"] = {"mode": "url-list", "file": "visited.txt"}
            (adapter_dir / "zap-baseline.json").write_text(json.dumps(zap), encoding="utf-8")
            out_file = Path(self._tmp.name) / "zap.json"
            out_file.write_text(json.dumps(self.zap_sample()), encoding="utf-8")
            visited = Path(self._tmp.name) / "visited.txt"
            visited.write_text("https://staging.example.test/search?q=1\nhttps://staging.example.test/orders/5\n", encoding="utf-8")
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = assess.run_ingest("zap-baseline", str(out_file), None, str(visited))
            self.assertEqual(code, 0, buf.getvalue())
            stored = json.loads((assess.scans_dir() / "zap-baseline.json").read_text(encoding="utf-8"))
            self.assertEqual(stored["coverage"][self.WEB]["paths"],
                             ["staging.example.test/orders/{n}", "staging.example.test/search"])
        finally:
            restore()

    def test_web_finding_resolves_only_when_coverage_saw_its_path(self):
        def web(fp, path):
            return {"fingerprint": fp, "cwe": "CWE-79", "location": {"file": f"https://{path}", "web": {"path": path}},
                    "sources": [{"adapter": "zap", "target": self.WEB}]}
        previous = [web("a", "staging.example.test/search"), web("b", "staging.example.test/admin2")]
        seen = {"zap": {self.WEB: {"mode": "url-list", "paths": ["staging.example.test/search"]}}}
        result = assess.round_resolution(previous, [], {"zap"}, seen)
        self.assertEqual(result, {"resolved": ["a:CWE-79"], "notRechecked": ["b:CWE-79"]})
        none = assess.round_resolution(previous, [], {"zap"}, {"zap": {self.WEB: {"mode": "none"}}})
        self.assertEqual(none["resolved"], [])
        probes = assess.round_resolution(previous, [], {"zap"}, {"zap": {self.WEB: {"mode": "fixed-probes"}}})
        self.assertEqual(len(probes["resolved"]), 2)

    def test_example_web_adapters_validate(self):
        for name in ("nuclei", "zap-baseline"):
            self.assertEqual(self.adapter_errors(name, self.example_adapter(name)), [], name)

    # --- 인프라·클라우드 설정 (ADR 0004) ---
    ACCOUNT = "aws:123456789012"

    def prowler_sample(self):
        return json.loads((TOOLS_DIR.parent / "examples/prowler/prowler-sample.json").read_text(encoding="utf-8"))

    def infra_scope(self, exclusions=(), regions=("ap-northeast-2", "us-east-1")):
        return authorized_scope(intrusiveness="passive", exclusions=list(exclusions), targets=[{
            "type": "infra", "value": self.ACCOUNT, "regions": list(regions),
            "credential": {"profile": "security-audit", "readOnlyConfirmed": True}}])

    def test_infra_target_needs_account_regions_and_read_only_credential_reference(self):
        cases = [
            ({"value": "123456789012"}, "provider:account"),
            ({"regions": []}, "regions must be"),
            ({"credential": {}}, "credential.profile is required"),
            ({"credential": {"profile": "p", "readOnlyConfirmed": False}}, "readOnlyConfirmed must be true"),
            ({"credential": {"profile": "p", "readOnlyConfirmed": True, "secretKey": "x"}}, "do not store secrets"),
        ]
        for change, message in cases:
            scope = self.infra_scope()
            scope["targets"][0].update(change)
            report = assess.Report()
            assess.validate_scope(report, scope)
            self.assertTrue(any(message in e for e in report.errors), message)
        clean = assess.Report()
        assess.validate_scope(clean, self.infra_scope())
        self.assertEqual(clean.errors, [])

    def test_regions_and_credential_are_semantic(self):
        scope = self.infra_scope()
        before = assess.semantic_fingerprint(scope)
        scope["targets"][0]["regions"].append("eu-west-1")
        self.assertNotEqual(assess.semantic_fingerprint(scope), before)
        scope = self.infra_scope()
        scope["targets"][0]["credential"]["profile"] = "admin"
        self.assertNotEqual(assess.semantic_fingerprint(scope), before)

    def test_prowler_failures_become_findings_and_controls_are_counted(self):
        sarif = assess.prowler_to_sarif(self.prowler_sample())
        props = assess.sarif_run_properties(sarif)
        self.assertEqual(assess.summarize_controls(props["controlResults"], []), {"CIS-2.0": {"pass": 1, "fail": 2, "manual": 1}})
        self.assertEqual(assess.summarize_controls(props["controlResults"], ["arn:aws:s3:::example-logs"]),
                         {"CIS-2.0": {"pass": 1, "fail": 1, "manual": 1}})  # 제외 자산은 세지 않는다
        self.assertEqual(len(props["checksRun"]), 4)
        self.assertEqual(props["regionsSeen"], ["ap-northeast-2", "global"])
        findings = assess.merge_findings(assess.findings_from_sarif(sarif, "prowler", "cloud"))
        self.assertEqual(len(findings), 2)
        s3 = next(f for f in findings if "s3" in f["location"]["file"])
        self.assertEqual(s3["group"], "CIS-2.0 2.1.4")
        self.assertEqual(assess.finding_key(s3), f"{s3['fingerprint']}:CIS-2.0 2.1.4")
        self.assertEqual(s3["location"]["cloud"]["region"], "ap-northeast-2")
        self.assertFalse(assess.is_code_level(s3))  # 클라우드 설정은 넘기지 않는다

    def test_iac_findings_without_cwe_group_by_check_and_stay_code_level(self):
        sarif = {"runs": [{"tool": {"driver": {"name": "checkov"}}, "results": [
            {"ruleId": "CKV_AWS_20", "message": {"text": "S3 public"},
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "infra/s3.tf"},
                                                 "region": {"startLine": 3, "snippet": {"text": "acl = public-read"}}}}]}]}]}
        finding = assess.findings_from_sarif(sarif, "checkov", "iac")[0]
        self.assertEqual(finding["group"], "check:CKV_AWS_20")
        self.assertTrue(assess.is_code_level(finding))
        sast = assess.findings_from_sarif(sarif, "semgrep", "sast")[0]
        self.assertNotIn("group", sast)  # 소스 점검 키는 예전 그대로
        self.assertEqual(assess.finding_key(sast), f"{sast['fingerprint']}:")

    def test_cloud_regions_exclusions_and_args(self):
        scope = self.infra_scope(exclusions=["aws:123456789012:us-east-1", "arn:aws:s3:::example-logs"])
        self.assertEqual(assess.cloud_allowed_regions(scope, self.ACCOUNT), ["ap-northeast-2"])
        args, _ = assess.cloud_args(self.example_adapter("prowler"), scope, self.ACCOUNT, ["ap-northeast-2"])
        self.assertEqual(args, ["--profile", "security-audit", "--region", "ap-northeast-2"])
        self.assertIsNone(assess.cloud_allowed_regions(self.infra_scope(exclusions=[self.ACCOUNT]), self.ACCOUNT))
        no_regions = dict(self.example_adapter("prowler"), cloud_args={"profile": "--profile {profile}"})
        self.assertIsNone(assess.cloud_args(no_regions, scope, self.ACCOUNT, ["ap-northeast-2"])[0])
        cloud = {"account": "123456789012", "region": "ap-northeast-2", "resource": "arn:aws:s3:::example-logs"}
        self.assertTrue(assess.cloud_excluded(cloud, ["arn:aws:s3:::example-logs"]))
        self.assertTrue(assess.cloud_excluded(cloud, ["aws:123456789012:ap-northeast-2"]))
        self.assertFalse(assess.cloud_excluded(cloud, ["aws:123456789012:us-east-1", "aws:999:ap-northeast-2"]))

    def test_cloud_scope_violation_detects_other_accounts_and_regions(self):
        props = {"accountsSeen": ["123456789012"], "regionsSeen": ["global", "ap-northeast-2"]}
        self.assertEqual(assess.cloud_scope_violation(props, self.ACCOUNT, ["ap-northeast-2"]), "")
        self.assertIn("리전", assess.cloud_scope_violation(props, self.ACCOUNT, ["us-east-1"]))
        self.assertIn("계정", assess.cloud_scope_violation({"accountsSeen": ["999"]}, self.ACCOUNT, []))

    def _cloud_scan_env(self, scope):
        self.write(scope)
        adapter_dir, restore = self._scan_env()
        (adapter_dir / "prowler.json").write_text(json.dumps(self.example_adapter("prowler")), encoding="utf-8")
        calls = []

        def fake_execute(command_template, target, output_path, timeout=600, extra_args=()):
            calls.append(list(extra_args))
            (Path(output_path).parent / "prowler.ocsf.json").write_text(json.dumps(self.prowler_sample()), encoding="utf-8")
            return 0
        assess.execute_adapter = fake_execute
        return calls, restore

    def test_cloud_scan_passes_profile_and_regions_and_records_controls(self):
        calls, restore = self._cloud_scan_env(self.infra_scope())
        try:
            code, out = self._scan(direct=True)
            self.assertEqual(code, 0, out)
            self.assertEqual(calls[0], ["--profile", "security-audit", "--region", "ap-northeast-2", "us-east-1"])
            stored = json.loads((assess.scans_dir() / "prowler.json").read_text(encoding="utf-8"))
            self.assertEqual(stored["coverage"][self.ACCOUNT]["regions"], ["ap-northeast-2", "us-east-1"])
            self.assertEqual(stored["controls"][self.ACCOUNT]["CIS-2.0"]["pass"], 1)
            self.assertEqual(len(self._findings()), 2)
            orig_cover = assess.COVER_MD
            self.assertIn("| CIS-2.0 | 1 | 2 | 1 |", assess.render_cover_md({}, self._findings(), {}, None,
                                                                          assess.load_control_summary()))
            self.assertIs(assess.COVER_MD, orig_cover)
        finally:
            restore()

    def test_cloud_results_outside_allowed_regions_are_discarded(self):
        calls, restore = self._cloud_scan_env(self.infra_scope(exclusions=["aws:123456789012:ap-northeast-2"]))
        try:
            code, out = self._scan(direct=True)
            self.assertEqual(calls[0], ["--profile", "security-audit", "--region", "us-east-1"])
            self.assertIn("결과를 버림", out)
            self.assertFalse((assess.scans_dir() / "prowler.json").exists())
        finally:
            restore()

    def test_ingest_refuses_cloud_output_that_read_excluded_regions(self):
        self.write(self.infra_scope(exclusions=["aws:123456789012:ap-northeast-2"]))
        adapter_dir, restore = self._scan_env()
        try:
            (adapter_dir / "prowler.json").write_text(json.dumps(self.example_adapter("prowler")), encoding="utf-8")
            out_file = Path(self._tmp.name) / "prowler.json"
            out_file.write_text(json.dumps(self.prowler_sample()), encoding="utf-8")
            code, out = self._ingest("prowler", out_file)
            self.assertEqual(code, 1)
            self.assertIn("허용하지 않은 리전", out)
        finally:
            restore()

    def test_cloud_finding_resolves_only_when_region_and_check_were_rechecked(self):
        def cloud(fp, region, check):
            return {"fingerprint": fp, "group": "CIS-2.0 x", "cwe": "",
                    "location": {"file": "arn:x", "cloud": {"account": "123456789012", "region": region, "check": check}},
                    "sources": [{"adapter": "prowler", "target": self.ACCOUNT}]}
        previous = [cloud("a", "ap-northeast-2", "s3_public"), cloud("b", "us-east-1", "s3_public"),
                    cloud("c", "global", "iam_root_mfa")]
        seen = {"prowler": {self.ACCOUNT: {"mode": "cloud", "regions": ["ap-northeast-2"], "checks": ["s3_public"]}}}
        result = assess.round_resolution(previous, [], {"prowler"}, seen)
        self.assertEqual(result, {"resolved": ["a:CIS-2.0 x"], "notRechecked": ["b:CIS-2.0 x", "c:CIS-2.0 x"]})

    def test_example_infra_adapters_validate(self):
        for name in ("checkov", "prowler"):
            self.assertEqual(self.adapter_errors(name, self.example_adapter(name)), [], name)
        bad = self.valid_adapter(id="c", category="cloud", output_file="../x", cloud_args={"regions": "--region"})
        errors = self.adapter_errors("c", bad)
        self.assertTrue(any("output_file must be" in e for e in errors))
        self.assertTrue(any("cloud_args.regions must contain" in e for e in errors))

    # --- 방법론 체크리스트 (ADR 0005) ---
    def wstg(self):
        return json.loads((TOOLS_DIR.parent / "examples/checklists/wstg-sample.json").read_text(encoding="utf-8"))

    def _checklist_env(self, records, scope=None):
        """체크리스트·증적 경로를 임시 위치로 돌리고 기준 파일과 기록을 둔다."""
        base = Path(self._tmp.name)
        names = ("CHECKLIST_DIR", "CHECKLIST_FILE", "CHECKLIST_CSV", "EVIDENCE_CSV", "COVER_MD",
                 "FINDINGS_FILE", "DISPOSITIONS_FILE", "ADAPTER_DIR")
        orig = {n: getattr(assess, n) for n in names}
        assess.CHECKLIST_DIR = base / "checklists"
        assess.CHECKLIST_FILE = base / "checklist.json"
        assess.CHECKLIST_CSV = base / "evidence" / "checklist.csv"
        assess.EVIDENCE_CSV = base / "evidence" / "findings.csv"
        assess.COVER_MD = base / "evidence" / "cover.md"
        assess.FINDINGS_FILE = base / "findings.json"
        assess.DISPOSITIONS_FILE = base / "dispositions.json"
        assess.ADAPTER_DIR = base / "adapters"
        assess.CHECKLIST_DIR.mkdir(exist_ok=True)
        (assess.CHECKLIST_DIR / "wstg-sample.json").write_text(json.dumps(self.wstg()), encoding="utf-8")
        assess.CHECKLIST_FILE.write_text(json.dumps({"schemaVersion": "1.0", "standard": "wstg-sample",
                                                     "items": records}), encoding="utf-8")
        self.write(scope or authorized_scope())

        def restore():
            for n, v in orig.items():
                setattr(assess, n, v)
        return restore

    def test_standard_file_holds_records_not_procedures(self):
        report = assess.Report()
        assess.validate_standard(report, "wstg-sample", self.wstg())
        self.assertEqual(report.errors, [])
        bad = self.wstg()
        bad["items"][0]["steps"] = ["..."]
        bad["items"][1]["intrusiveness"] = "loud"
        report = assess.Report()
        assess.validate_standard(report, "wstg-sample", bad)
        self.assertTrue(any("records results only" in e for e in report.errors))
        self.assertTrue(any("intrusiveness must be" in e for e in report.errors))

    def test_items_beyond_the_scope_cap_or_without_targets_are_out_of_scope(self):
        items = {i["id"]: i for i in self.wstg()["items"]}
        scope = authorized_scope()  # 상한 active-nondestructive, repo·web·infra 대상
        self.assertEqual(assess.item_out_of_scope(items["WSTG-CONF-07"], scope), "")
        self.assertIn("상한", assess.item_out_of_scope(items["WSTG-INPV-05"], scope))
        repo_only = authorized_scope(targets=[{"type": "repo", "value": "./"}])
        self.assertIn("대상", assess.item_out_of_scope(items["WSTG-CONF-07"], repo_only))

    def test_rows_suggest_scan_coverage_but_do_not_confirm(self):
        zap = self.example_adapter("zap-baseline")
        rows = assess.checklist_rows(self.wstg(), {"WSTG-CONF-07": {}, "WSTG-INPV-05": {"status": "checked"}},
                                     authorized_scope(), [("zap-baseline", zap)],
                                     {"zap-baseline": {"targets": [self.WEB]}})
        by = {r["item"]: r for r in rows}
        self.assertEqual(by["WSTG-CONF-07"]["status"], "not-checked")
        self.assertEqual(by["WSTG-CONF-07"]["suggestedBy"], ["zap-baseline"])
        self.assertEqual(by["WSTG-INPV-05"]["status"], "out-of-scope")
        none_ran = assess.checklist_rows(self.wstg(), {"WSTG-CONF-07": {}}, authorized_scope(), [("zap-baseline", zap)], {})
        self.assertEqual(none_ran[0]["suggestedBy"], [])

    def test_checklist_results_need_user_confirmation_reason_and_scope(self):
        restore = self._checklist_env({
            "WSTG-CONF-07": {"status": "checked", "decidedBy": "ai", "reason": "근거"},
            "WSTG-SESS-02": {"status": "issue-found", "decidedBy": "user", "reason": "근거"},
            "WSTG-INPV-05": {"status": "checked", "decidedBy": "user", "reason": "근거"},
            "WSTG-NOPE-01": {"status": "not-checked"},
            "WSTG-INFO-02": {"status": "not-applicable", "decidedBy": "user"},
        })
        try:
            report = assess.Report()
            assess.validate_checklist(report)
        finally:
            restore()
        joined = "\n".join(report.errors)
        self.assertIn("WSTG-CONF-07 is 'checked'; only the user confirms", joined)
        self.assertIn("WSTG-SESS-02 is 'issue-found' but names no evidence", joined)
        self.assertIn("WSTG-INPV-05 is out of scope", joined)
        self.assertIn("WSTG-NOPE-01 is not in checklists", joined)
        self.assertIn("WSTG-INFO-02 is 'not-applicable' but has no reason", joined)

    def test_example_checklist_validates_and_evidence_carries_it(self):
        records = json.loads((TOOLS_DIR.parent / "examples/checklist.json").read_text(encoding="utf-8"))["items"]
        restore = self._checklist_env(records)
        try:
            report = assess.Report()
            assess.validate_checklist(report)
            self.assertEqual(report.errors, [])
            with redirect_stdout(io.StringIO()):
                self.assertEqual(assess.run_evidence(), 0)
            cover = assess.COVER_MD.read_text(encoding="utf-8")
            self.assertIn("## 5. 방법론 체크리스트", cover)
            self.assertIn("| 점검함 | 1 |", cover)
            self.assertIn("| 결함 발견 | 1 |", cover)
            self.assertIn("| 범위 밖 | 1 |", cover)  # INPV-05는 상한 밖
            csv_text = assess.CHECKLIST_CSV.read_text(encoding="utf-8")
            self.assertTrue(csv_text.startswith("item,title,status,decidedBy,reason,evidence,suggestedBy,link"))
            report = assess.Report()
            assess.validate_evidence(report)
            self.assertEqual(report.errors, [])
            data = json.loads(assess.CHECKLIST_FILE.read_text(encoding="utf-8"))
            data["items"]["WSTG-INFO-02"] = {"status": "not-applicable", "decidedBy": "user", "reason": "정적 사이트"}
            assess.CHECKLIST_FILE.write_text(json.dumps(data), encoding="utf-8")
            report = assess.Report()
            assess.validate_evidence(report)
            self.assertTrue(any("checklist.csv is out of date" in e for e in report.errors))
        finally:
            restore()

    # --- strict ---
    def test_strict_validate_folds_gate_block_into_errors(self):
        scope = copy.deepcopy(EXAMPLE)
        scope["status"] = "unauthorized"
        scope["authorizedAt"] = None
        scope["approvalFingerprint"] = None
        self.write(scope)
        code, out = self.validate(strict=True)
        self.assertEqual(code, 1)
        self.assertIn("gate not ready", out)


    # --- 저장소 전체 리뷰 반영 ---
    def test_partial_scan_keeps_the_failed_target_results(self):
        self.write(authorized_scope(intrusiveness="passive",
                                    targets=[{"type": "repo", "value": "./a"}, {"type": "repo", "value": "./b"}]))
        adapter_dir, restore = self._scan_env()
        try:
            self._set_adapter(adapter_dir, "semgrep", self.sarif("semgrep-sample.sarif"))
            self.assertEqual(self._scan()[0], 0)
            fixture = self._fixtures["semgrep"]

            def flaky(command_template, target, output_path, timeout=600, extra_args=()):
                if target == "./b":
                    raise RuntimeError("tool crashed")
                Path(output_path).write_text(fixture, encoding="utf-8")
                return 0
            assess.execute_adapter = flaky
            code, out = self._scan()
            self.assertEqual(code, 0, out)
            record = json.loads((assess.scans_dir() / "semgrep.json").read_text(encoding="utf-8"))
            self.assertEqual(record["targets"], ["./a", "./b"])
            self.assertEqual({s.get("target") for f in record["findings"] for s in f["sources"]}, {"./a", "./b"})
            self.assertEqual(len(self._findings()), 2)
        finally:
            restore()

    def test_error_json_does_not_replace_previous_results(self):
        self.write(authorized_scope(intrusiveness="passive", targets=[{"type": "repo", "value": "./src"}]))
        adapter_dir, restore = self._scan_env()
        try:
            self._set_adapter(adapter_dir, "semgrep", self.sarif("semgrep-sample.sarif"))
            self._scan()
            self._set_adapter(adapter_dir, "semgrep", {"error": "scan failed"})
            code, out = self._scan()
            self.assertIn("runs 목록이 없습니다", out)
            self.assertEqual(len(self._findings()), 2)
        finally:
            restore()
        for fmt, raw in (("osv-json", {"error": "x"}), ("zap-json", {}), ("prowler-ocsf", {"error": "x"})):
            with self.assertRaises(ValueError):
                assess.normalize_to_sarif(fmt, raw)
        self.assertEqual(assess.normalize_to_sarif("osv-json", {"results": []})["runs"][0]["results"], [])

    def test_code_finding_is_resolved_only_when_its_own_target_was_rescanned(self):
        previous = [{"fingerprint": "a", "cwe": "CWE-89", "sources": [{"adapter": "semgrep", "target": "repo-B"}]}]
        other = assess.round_resolution(previous, [], {"semgrep"}, None, {"semgrep": {"repo-A"}})
        self.assertEqual(other, {"resolved": [], "notRechecked": ["a:CWE-89"]})
        same = assess.round_resolution(previous, [], {"semgrep"}, None, {"semgrep": {"repo-A", "repo-B"}})
        self.assertEqual(same, {"resolved": ["a:CWE-89"], "notRechecked": []})

    def test_explicit_midnight_end_is_not_extended_to_end_of_day(self):
        self.write(authorized_scope(window={"start": "2026-10-22", "end": "2026-10-24T00:00:00Z"}))
        assess.now_utc = lambda: datetime(2026, 10, 24, 0, 0, 1, tzinfo=timezone.utc)
        code, out = self.gate()
        self.assertEqual(code, 1)
        self.assertIn("expired", out)
        scope = {"window": {"end": "2026-10-24T00:00:00Z"}}
        self.assertLessEqual(assess.web_time_limit({"max_seconds": 600}, scope,
                                                   datetime(2026, 10, 24, 0, 0, 1, tzinfo=timezone.utc)), 0)
        self.write(authorized_scope(window={"start": "2026-10-22", "end": "2026-10-24"}))
        assess.now_utc = lambda: datetime(2026, 10, 24, 23, 0, tzinfo=timezone.utc)
        self.assertEqual(self.gate()[0], 0)

    def test_stored_location_and_message_drop_secret_values(self):
        sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "zap"}}, "results": [{
            "ruleId": "r", "message": {"text": "leak api_key=sk-abcdefghijklmnopqrstuvwx at https://h.test/x?session=zz9 "
                                                "Authorization: Bearer abcdefghijkl"},
            "properties": {"method": "GET"},
            "locations": [{"physicalLocation": {"artifactLocation": {
                "uri": "https://user:pw@h.test/a?token=abc123&q=1"}}}]}]}]}
        finding = assess.findings_from_sarif(sarif, "zap")[0]
        stored = json.dumps(finding)
        for secret in ("pw@", "abc123", "sk-abcdefghijklmnopqrstuvwx", "zz9", "abcdefghijkl"):
            self.assertNotIn(secret, stored)
        self.assertEqual(finding["location"]["file"], "https://h.test/a?token=REDACTED&q=REDACTED")
        self.assertEqual(finding["location"]["web"]["params"], ["q", "token"])
        self.assertLessEqual(len(assess.redact_text("x" * 1000)), assess.MESSAGE_LIMIT)

    def test_csv_cells_cannot_start_a_spreadsheet_formula(self):
        finding = {"fingerprint": "f", "cwe": "CWE-1", "location": {"file": "=HYPERLINK(\"x\")", "line": 3},
                   "sources": [{"scanner": "@s"}]}
        text = assess.render_evidence_csv([finding], {"f:CWE-1": {"reason": "-1+2", "disposition": "suspected"}})
        self.assertIn("'=HYPERLINK", text)
        self.assertIn("'-1+2", text)
        self.assertIn("'@s", text)
        self.assertIn(",3,", text)
        rows = [{"item": "I", "title": "+t", "status": "checked", "decidedBy": "user", "reason": "", "outOfScope": "",
                 "evidence": [], "suggestedBy": [], "link": ""}]
        self.assertIn("'+t", assess.render_checklist_csv(rows))

    def test_new_round_archives_checklist_and_reopens_items_unchecked(self):
        restore = self._checklist_env({
            "WSTG-CONF-07": {"status": "checked", "decidedBy": "user", "reason": "확인함", "evidence": ["x"]},
            "WSTG-INFO-02": {"status": "not-checked"}})
        try:
            assess.FINDINGS_FILE.write_text(json.dumps({"schemaVersion": "1.0", "findings": []}), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(assess.run_new_round(), 0)
            reopened = json.loads(assess.CHECKLIST_FILE.read_text(encoding="utf-8"))
            self.assertEqual(reopened["standard"], "wstg-sample")
            self.assertEqual(reopened["items"], {"WSTG-CONF-07": {"status": "not-checked"},
                                                 "WSTG-INFO-02": {"status": "not-checked"}})
            archived = json.loads((assess.rounds_dir() / "checklist-001.json").read_text(encoding="utf-8"))
            self.assertEqual(archived["items"]["WSTG-CONF-07"]["status"], "checked")
            self.assertEqual(archived["round"], 1)
        finally:
            restore()

if __name__ == "__main__":
    unittest.main(verbosity=2)
