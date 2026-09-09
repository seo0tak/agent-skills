"""Behavioral tests; all records and payload files live in temporary directories."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("improvement_tracker.py")


class TrackerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = self.root / "records"
        self.serial = 0

    def cli(self, *args, data=None, ok=True):
        argv = [sys.executable, str(SCRIPT), "--store", str(self.store), *args]
        if data is not None:
            self.serial += 1
            path = self.root / ("input-%d.json" % self.serial)
            path.write_text(json.dumps(data), encoding="utf-8")
            argv += ["--data", str(path)]
        proc = subprocess.run(argv, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0 if ok else 2, proc.stderr + proc.stdout)
        self.assertTrue(proc.stdout.strip(), "Missing JSON CLI response: " + proc.stderr)
        value = json.loads(proc.stdout)
        self.assertEqual(value["ok"], ok)
        return value.get("summary", value)

    def record_bytes(self):
        return (self.store / "empty-input.json").read_bytes()

    def capture(self):
        return self.cli("capture", "--id", "empty-input", data={
            "problem": "Empty audit input is accepted as complete.",
            "reproduction": "Pass a zero-byte SKILL.md to the local audit fixture.",
            "context": "Local skill review; no customer data."})

    def proposal(self):
        return {
            "baseline": {"reproduction": "empty-input fixture", "observed": "exit 0"},
            "target": {"path": "skills/example/SKILL.md", "sha256": "a" * 64},
            "candidate": {"summary": "Reject empty input", "change": "Require nonempty input before audit."},
            "rollback": {"version": "0.3.0", "plan": "Restore saved pre-change copy."}}

    def move(self, current, state, data, ok=True):
        return self.cli("transition", "--id", "empty-input", "--to", state,
                        "--expected-revision", str(current["revision"]), data=data, ok=ok)

    def propose(self):
        return self.move(self.capture(), "proposed", self.proposal())

    def evaluation(self, current, result="pass"):
        return {"binding": current["binding"], "result": result,
                "baselineObserved": "empty input accepted (exit 0)",
                "candidateObserved": "empty input rejected (exit 2)",
                "evidence": "Temporary fixture run: empty input rejected, valid input accepted.",
                "regressionResult": "pass", "regressionEvidence": "3 existing audit cases passed."}

    def evaluated(self):
        current = self.propose()
        return self.move(current, "evaluated", self.evaluation(current))

    def authority(self, current):
        return {"binding": current["binding"], "evaluationDigest": current["evaluationDigest"],
                "reference": "conversation:maintainer-turn-42", "scope": "Apply this candidate to the local skill only."}

    def approved(self):
        current = self.evaluated()
        return self.move(current, "approved", self.authority(current))

    def application(self, current):
        return {"binding": current["binding"], "evaluationDigest": current["evaluationDigest"],
                "authorityReference": "conversation:maintainer-turn-42",
                "preApplyTargetSha256": "a" * 64, "resultingTargetSha256": "b" * 64,
                "version": "0.4.0", "evidence": "Applied locally and inspected resulting diff."}

    def applied(self):
        current = self.approved()
        return self.move(current, "applied", self.application(current))

    def verification(self, current):
        return {"binding": current["binding"], "resultingTargetSha256": "b" * 64,
                "version": "0.4.0", "regressionResult": "pass",
                "regressionEvidence": "Post-application empty-input and existing audit cases passed.",
                "rollbackChecked": "Saved version 0.3.0 copy is present and readable."}

    def rejected_without_mutation(self, current, state, data):
        before = self.record_bytes()
        self.move(current, state, data, ok=False)
        self.assertEqual(self.record_bytes(), before)

    def test_full_lifecycle_preserves_history_and_never_grants_authority(self):
        current = self.applied()
        current = self.move(current, "verified", self.verification(current))
        self.assertEqual(current["state"], "verified")
        self.assertEqual(current["revision"], 6)
        self.assertIs(current["authorityAuthenticated"], False)
        self.assertIn("actual user permission", current["authorityNotice"])
        self.assertEqual(self.cli("validate", "--id", "empty-input"), current)
        self.assertEqual(len(json.loads(self.record_bytes())["events"]), 6)
        self.assertEqual(current.get("version"), "0.4.0")
        self.assertEqual(current["rollbackVersion"], "0.3.0")
        self.assertEqual(current["evaluationResult"], "pass")
        self.assertEqual(current["regressionResult"], "pass")

    def test_changed_candidate_alone_invalidates_old_evaluation(self):
        current = self.evaluated()
        old_evaluation = self.evaluation(current)
        data = self.proposal()
        data["candidate"]["change"] = "Only reject inputs with no non-whitespace characters."
        current = self.move(current, "proposed", data)
        self.rejected_without_mutation(current, "evaluated", old_evaluation)

    def test_changed_target_alone_invalidates_old_evaluation(self):
        current = self.evaluated()
        old_evaluation = self.evaluation(current)
        data = self.proposal()
        data["target"]["sha256"] = "e" * 64
        current = self.move(current, "proposed", data)
        self.rejected_without_mutation(current, "evaluated", old_evaluation)

    def test_applied_requires_evaluation_and_authority(self):
        current = self.propose()
        self.rejected_without_mutation(current, "applied", {})
        current = self.move(current, "evaluated", self.evaluation(current))
        self.rejected_without_mutation(current, "applied", self.application(current))

    def test_wrong_candidate_evaluation_is_rejected(self):
        current = self.propose()
        data = self.evaluation(current)
        data["binding"] = "c" * 64
        self.rejected_without_mutation(current, "evaluated", data)

    def test_failed_evaluation_or_regression_cannot_be_approved(self):
        for field in ("result", "regressionResult"):
            with self.subTest(field=field):
                if self.store.exists():
                    (self.store / "empty-input.json").unlink()
                current = self.propose()
                data = self.evaluation(current)
                data[field] = "fail"
                current = self.move(current, "evaluated", data)
                self.rejected_without_mutation(current, "approved", self.authority(current))

    def test_revised_candidate_or_target_invalidates_evaluation_and_authority(self):
        current = self.approved()
        old = copy.deepcopy(current)
        proposal = self.proposal()
        proposal["target"]["sha256"] = "c" * 64
        proposal["candidate"]["change"] += " Include whitespace-only input."
        current = self.move(current, "proposed", proposal)
        self.assertNotEqual(current["binding"], old["binding"])
        self.assertIsNone(current["evaluationDigest"])
        self.assertIsNone(current["authorityReference"])
        self.rejected_without_mutation(current, "evaluated", self.evaluation(old))

    def test_changed_evaluation_invalidates_previous_authority_binding(self):
        current = self.approved()
        old_authority = self.authority(current)
        current = self.move(current, "proposed", self.proposal())
        data = self.evaluation(current)
        data["evidence"] = "Rerun with an additional whitespace case."
        current = self.move(current, "evaluated", data)
        self.rejected_without_mutation(current, "approved", old_authority)

    def test_target_and_authority_mismatch_reject_application(self):
        current = self.approved()
        for field, value in (("preApplyTargetSha256", "c" * 64),
                             ("authorityReference", "unrelated-message"),
                             ("evaluationDigest", "d" * 64)):
            data = self.application(current)
            data[field] = value
            self.rejected_without_mutation(current, "applied", data)

    def test_verification_needs_matching_result_regression_and_rollback(self):
        current = self.applied()
        for field, value in (("resultingTargetSha256", "c" * 64),
                             ("version", "9.9.9"), ("regressionResult", "fail"),
                             ("rollbackChecked", "")):
            data = self.verification(current)
            data[field] = value
            self.rejected_without_mutation(current, "verified", data)

    def test_checkpoint_resumes_incomplete_work_without_advancing_state(self):
        current = self.propose()
        checkpoint = {"completed": ["baseline empty-file case"],
                      "remaining": ["evaluate whitespace and valid input"],
                      "notes": "Evaluation interrupted; no result claimed.",
                      "nextAction": "Rerun missing cases against current candidate and target."}
        current = self.cli("checkpoint", "--id", "empty-input", "--expected-revision", "2", data=checkpoint)
        self.assertEqual(current["state"], "proposed")
        self.assertEqual(current["checkpoint"], checkpoint)
        self.assertEqual(self.cli("summary", "--id", "empty-input"), current)
        self.rejected_without_mutation(current, "approved", {})

    def test_summary_prioritizes_checkpoint_action_and_restores_lifecycle_fallback(self):
        current = self.propose()
        fallback = current["nextAction"]
        checkpoint = {"completed": [], "remaining": ["Reconcile changed target and user scope"],
                      "notes": "Resume prerequisite before reevaluation.",
                      "nextAction": "Confirm the current target and actual user scope first."}
        current = self.cli("checkpoint", "--id", "empty-input", "--expected-revision", "2", data=checkpoint)
        resumed = self.cli("summary", "--id", "empty-input")
        self.assertEqual(resumed["nextAction"], checkpoint["nextAction"])
        self.assertEqual(resumed["lifecycleNextAction"], fallback)
        self.assertEqual(resumed["state"], "proposed")
        self.assertIs(resumed["authorityAuthenticated"], False)
        self.rejected_without_mutation(resumed, "approved", {})
        current = self.move(current, "evaluated", self.evaluation(current))
        self.assertIsNone(current["checkpoint"])
        self.assertEqual(current["nextAction"], current["lifecycleNextAction"])
        self.assertNotEqual(current["nextAction"], checkpoint["nextAction"])

    def test_explicit_rejection_and_rollback_are_terminal(self):
        current = self.propose()
        current = self.move(current, "rejected", {"reason": "Candidate changes valid-input behavior."})
        self.assertEqual(current["state"], "rejected")
        self.rejected_without_mutation(current, "proposed", self.proposal())
        (self.store / "empty-input.json").unlink()
        current = self.applied()
        current = self.move(current, "rolled-back", {
            "reason": "Post-apply manual check found a scope issue.", "restoredVersion": "0.3.0",
            "evidence": "Restored saved copy; original audit fixtures pass."})
        self.assertEqual(current["state"], "rolled-back")
        self.assertEqual(current["version"], "0.3.0")
        self.assertIsNone(current["regressionResult"])

    def test_duplicate_capture_revision_conflict_and_lock_preserve_record(self):
        current = self.propose()
        before = self.record_bytes()
        self.cli("capture", "--id", "empty-input", data={}, ok=False)
        self.cli("transition", "--id", "empty-input", "--to", "evaluated",
                 "--expected-revision", "1", data=self.evaluation(current), ok=False)
        lock = self.store / ".write-lock"
        lock.mkdir()
        self.move(current, "evaluated", self.evaluation(current), ok=False)
        self.assertEqual(self.record_bytes(), before)
        self.assertTrue(lock.exists())

    def test_malformed_and_partial_records_fail_without_repair_or_reset(self):
        self.capture()
        for raw in (b'{"schemaVersion":', b'{}', b'[]',
                    b'{"schemaVersion":"1.0","id":"empty-input","revision":1,"events":[]}'):
            (self.store / "empty-input.json").write_bytes(raw)
            self.cli("summary", "--id", "empty-input", ok=False)
            self.assertEqual(self.record_bytes(), raw)

    def test_manual_history_edit_is_validated_on_resume(self):
        self.evaluated()
        record = json.loads(self.record_bytes())
        record["events"][1]["data"]["candidate"]["change"] += " changed after evaluation"
        (self.store / "empty-input.json").write_text(json.dumps(record), encoding="utf-8")
        self.cli("validate", "--id", "empty-input", ok=False)

    def test_record_path_traversal_and_symlink_are_rejected(self):
        self.cli("capture", "--id", "../outside", data={}, ok=False)
        self.assertFalse((self.root / "outside.json").exists())
        self.store.mkdir(exist_ok=True)
        outside = self.root / "outside.json"
        outside.write_text("keep", encoding="utf-8")
        (self.store / "empty-input.json").symlink_to(outside)
        self.cli("capture", "--id", "empty-input", data={}, ok=False)
        self.cli("validate", "--id", "empty-input", ok=False)
        self.assertEqual(outside.read_text(), "keep")

    def test_external_target_paths_and_unknown_payload_fields_are_rejected(self):
        current = self.capture()
        for path in ("../secret", "/tmp/outside", "skills/../outside", "C:\\outside", "https://host/file"):
            data = self.proposal()
            data["target"]["path"] = path
            self.rejected_without_mutation(current, "proposed", data)
        data = self.proposal()
        data["run"] = "touch /tmp/should-never-run"
        self.rejected_without_mutation(current, "proposed", data)

    def test_command_looking_strings_are_inert(self):
        current = self.capture()
        marker = self.root / "executed"
        data = self.proposal()
        data["candidate"]["change"] = "$(touch %s); python3 -c 'raise Exception()'" % marker
        current = self.move(current, "proposed", data)
        self.cli("summary", "--id", "empty-input")
        self.assertFalse(marker.exists())
        self.assertIn("$(touch", json.loads(self.record_bytes())["events"][1]["data"]["candidate"]["change"])

    def test_failed_replace_preserves_record_and_cleans_own_temporary_file(self):
        self.capture()
        before = self.record_bytes()
        spec = importlib.util.spec_from_file_location("improvement_tracker", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        # Inject only the filesystem commit boundary, after a real temporary write.
        with mock.patch.object(module.os, "replace", side_effect=OSError("interrupted replacement")):
            with self.assertRaises(OSError):
                with module.writer(self.store):
                    module.save(self.store / "empty-input.json", {"uncommitted": True})
        self.assertEqual(self.record_bytes(), before)
        self.assertEqual(sorted(p.name for p in self.store.iterdir()), ["empty-input.json"])

    def test_duplicate_json_keys_and_incomplete_event_fail_closed(self):
        self.capture()
        raw = self.record_bytes()
        broken = json.loads(raw)
        broken["events"][0]["data"].pop("reproduction")
        for value in (raw.replace(b'"revision": 1', b'"revision": 1, "revision": 2'),
                      json.dumps(broken).encode()):
            (self.store / "empty-input.json").write_bytes(value)
            self.cli("summary", "--id", "empty-input", ok=False)
            self.assertEqual(self.record_bytes(), value)

    def test_example_record_resumes_without_fabricating_evaluation_or_authority(self):
        self.store.mkdir()
        example = SCRIPT.parent.parent / "references" / "improvement-example.json"
        (self.store / "empty-input.json").write_bytes(example.read_bytes())
        current = self.cli("validate", "--id", "empty-input")
        self.assertEqual((current["state"], current["revision"]), ("captured", 2))
        self.assertIsNone(current["evaluationDigest"])
        self.assertIsNone(current["authorityReference"])
        self.assertEqual(len(current["checkpoint"]["remaining"]), 2)

    def test_nonstandard_json_constants_and_wrong_types_are_rejected(self):
        self.capture()
        original = self.record_bytes()
        record = json.loads(original)
        variants = []
        for revision in (True, None, "1", 0):
            changed = copy.deepcopy(record)
            changed["revision"] = revision
            variants.append(json.dumps(changed).encode())
        variants += [original.replace(b'"revision": 1', b'"revision": NaN'),
                     original.replace(b'"data": {', b'"data": null, "unused": {')]
        for raw in variants:
            (self.store / "empty-input.json").write_bytes(raw)
            self.cli("validate", "--id", "empty-input", ok=False)
            self.assertEqual(self.record_bytes(), raw)

    def test_two_cooperating_writers_cannot_overwrite_a_record(self):
        data = self.root / "capture.json"
        data.write_text(json.dumps({"problem": "Blank input accepted", "reproduction": "empty-file fixture",
                                    "context": "isolated concurrency fixture"}), encoding="utf-8")
        argv = [sys.executable, str(SCRIPT), "--store", str(self.store), "capture", "--id",
                "empty-input", "--data", str(data)]
        processes = [subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                     for _ in range(2)]
        outputs = [process.communicate(timeout=10) for process in processes]
        self.assertEqual(sorted(process.returncode for process in processes), [0, 2], outputs)
        self.assertEqual(self.cli("validate", "--id", "empty-input")["revision"], 1)


if __name__ == "__main__":
    unittest.main()
