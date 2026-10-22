"""security-assessment M0 회귀 테스트 — 표준 라이브러리 unittest만.

실행: 툴킷 디렉터리에서 `python3 -B -m unittest tools.test_assess`.

인가 게이트의 핵심 성질을 고정한다: 미인가·기간 밖·스코프 변경이면 BLOCKED,
notes만 바꾼 것은 승인 유지, 승인은 의미 지문으로 재대조.
"""
from __future__ import annotations

import copy
import io
import json
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
        errors = self.adapter_errors("zap", self.valid_adapter(id="zap", category="dast", output_format="zap-json"))
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

        def fake_execute(command_template, target, output_path, timeout=600):
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
        self.assertIsNotNone(data)
        assert data is not None
        self.assertEqual(data["findings"], [])

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
