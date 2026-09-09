"""Behavioral recovery tests; all state and source changes use temporary fixtures."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

TOOLKIT = Path(__file__).resolve().parent.parent


class StateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.project = Path(self.tmp.name)
        self.root = self.project / "toolkit"
        shutil.copytree(TOOLKIT, self.root, ignore=shutil.ignore_patterns("__pycache__"))
        for name in ("findings", "progress", "project-profile"):
            shutil.copyfile(self.root / "examples" / (name + ".json"), self.root / "data" / (name + ".json"))
        self.source = self.project / "service.py"
        self.source.write_text("value = 1\n")
        self.progress_path = self.root / "data/progress.json"
        self.progress = self.read(self.progress_path)
        self.progress["items"]["SAMPLE-001"] = {
            "workflowStatus": "in-progress", "conclusion": "unreviewed",
            "note": "Investigating boundary", "draftDetail": {"hypothesis": "null input"},
        }
        self.write(self.progress_path, self.progress)

    def tearDown(self):
        self.tmp.cleanup()

    def read(self, path):
        return json.loads(path.read_text())

    def write(self, path, value):
        path.write_text(json.dumps(value))

    def run_state(self, *args, ok=True):
        result = subprocess.run([sys.executable, "tools/sast_state.py", *args], cwd=self.root,
                                text=True, capture_output=True,
                                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        if ok:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        return json.loads(result.stdout)

    def tree(self):
        return {str(p.relative_to(self.root)): p.read_bytes()
                for p in self.root.rglob("*") if p.is_file()}

    def result(self):
        record = self.read(self.root / "examples/result.json")
        record["resultFiles"] = ["service.py"]
        return record

    def store_result(self, record):
        self.write(self.root / "security-results/SAMPLE-001.json", record)

    def mark_verified_now(self):
        from datetime import datetime, timezone
        record = self.result()
        record["verification"]["verifiedAt"] = datetime.now(timezone.utc).isoformat()
        self.store_result(record)

    def test_checkpoint_restores_provisional_progress_and_notes_without_preview_writes(self):
        self.run_state("checkpoint", "--id", "SAMPLE-001", "--note", "Stopped before edit",
                       "--next-action", "Check null path", "--path", "service.py")
        self.progress_path.write_text('{"items":')
        before = self.tree()
        preview = self.run_state("recover-progress")
        self.assertEqual(self.tree(), before)
        self.assertEqual(preview["progress"]["items"]["SAMPLE-001"], self.progress["items"]["SAMPLE-001"])
        applied = self.run_state("recover-progress", "--apply")
        self.assertEqual(self.read(self.progress_path)["items"]["SAMPLE-001"], self.progress["items"]["SAMPLE-001"])
        self.assertEqual((self.root / applied["backup"]).read_text(), '{"items":')
        status = self.run_state("status")
        self.assertIn("SAMPLE-001", status["resumeCandidates"])
        self.assertEqual(status["checkpoints"]["SAMPLE-001"]["note"], "Stopped before edit")

    def test_source_change_rejects_verified_binding_without_result_change(self):
        self.run_state("snapshot", "--id", "SAMPLE-001", "--path", "service.py")
        self.mark_verified_now()
        self.source.write_text("value = 2\n")
        before = (self.root / "security-results/SAMPLE-001.json").read_bytes()
        rejected = self.run_state("seal-verification", "--id", "SAMPLE-001", ok=False)
        self.assertIn("changed", rejected["error"])
        self.assertEqual((self.root / "security-results/SAMPLE-001.json").read_bytes(), before)

    def test_seal_does_not_trust_old_passed_result_and_detects_later_source_change(self):
        self.store_result(self.result())
        status = self.run_state("status")
        self.assertEqual(status["verification"]["SAMPLE-001"]["status"], "unbound")
        self.run_state("snapshot", "--id", "SAMPLE-001", "--path", "service.py")
        rejected = self.run_state("seal-verification", "--id", "SAMPLE-001", ok=False)
        self.assertIn("predates", rejected["error"])
        self.mark_verified_now()
        self.run_state("seal-verification", "--id", "SAMPLE-001")
        self.assertEqual(self.run_state("status")["verification"]["SAMPLE-001"]["status"], "fresh")
        self.source.write_text("value = 3\n")
        status = self.run_state("status")
        self.assertEqual(status["verification"]["SAMPLE-001"]["status"], "stale")
        self.assertIn("SAMPLE-001", status["resumeCandidates"])

    def test_recovery_reconstructs_result_status_but_preserves_checkpoint_note(self):
        self.run_state("checkpoint", "--id", "SAMPLE-001")
        self.store_result(self.result())
        self.progress_path.write_text("broken")
        preview = self.run_state("recover-progress")
        item = preview["progress"]["items"]["SAMPLE-001"]
        self.assertEqual(item["workflowStatus"], "verified")
        self.assertEqual(item["note"], "Investigating boundary")
        self.assertEqual(preview["verification"]["SAMPLE-001"]["status"], "unbound")

    def test_foreign_or_malformed_backup_rejected_without_state_mutation(self):
        self.run_state("checkpoint", "--id", "SAMPLE-001")
        backup = self.project / "backup.json"
        for value in ({**self.progress, "workspaceId": "another-workspace"},
                      {**self.progress, "items": {"SAMPLE-001": {"workflowStatus": "bogus"}}},
                      {**self.progress, "items": {"../escape": self.progress["items"]["SAMPLE-001"]}}):
            with self.subTest(value=value):
                self.write(backup, value)
                before = self.tree()
                self.run_state("recover-progress", "--backup", str(backup), "--apply", ok=False)
                self.assertEqual(self.tree(), before)

    def test_browser_drafts_are_retained_when_merging_a_backup(self):
        backup = self.project / "backup.json"
        draft = {"source": "browser-answer", "savedAt": self.result()["updatedAt"], "result": self.result()}
        self.write(backup, {**self.progress, "draftResults": {"SAMPLE-001": draft}})
        self.run_state("recover-progress", "--backup", str(backup), "--apply")
        self.assertEqual(self.read(self.progress_path)["draftResults"]["SAMPLE-001"], draft)
        self.assertFalse((self.root / "security-results/SAMPLE-001.json").exists())

    def test_parallel_atomic_writers_and_serialized_updates(self):
        script = (
            "import json, sys; from pathlib import Path; "
            "from tools.sast_io import writer_lock, write_text_atomic; "
            "root=Path('.'); target=root/'counter.json'; "
            "\nfor _ in range(12):\n"
            " with writer_lock(root):\n"
            "  value=json.loads(target.read_text()) if target.exists() else 0\n"
            "  write_text_atomic(target,json.dumps(value+1))\n"
        )
        processes = [subprocess.Popen([sys.executable, "-c", script], cwd=self.root,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                     for _ in range(5)]
        for process in processes:
            output = process.communicate(timeout=20)
            self.assertEqual(process.returncode, 0, output)
        self.assertEqual(self.read(self.root / "counter.json"), 60)
        self.assertEqual(list(self.root.glob(".counter.json.*.tmp")), [])

    def test_lock_is_released_after_process_death(self):
        script = ("from pathlib import Path; from tools.sast_io import writer_lock; import time; "
                  "\nwith writer_lock(Path('.')):\n print('locked', flush=True)\n time.sleep(30)\n")
        process = subprocess.Popen([sys.executable, "-c", script], cwd=self.root,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertEqual(process.stdout.readline().strip(), "locked")
            process.kill()
            process.communicate(timeout=5)
            self.run_state("checkpoint", "--id", "SAMPLE-001")
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)

    def test_validator_reports_stale_binding_and_sync_refuses_to_publish_it(self):
        self.run_state("snapshot", "--id", "SAMPLE-001", "--path", "service.py")
        self.mark_verified_now()
        self.run_state("seal-verification", "--id", "SAMPLE-001")
        self.source.write_text("value = 4\n")
        for command in ("validate", "sync", "query"):
            with self.subTest(command=command):
                before = self.tree()
                result = subprocess.run([sys.executable, "tools/sast_toolkit.py", command],
                                        cwd=self.root, text=True, capture_output=True,
                                        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("source changed", result.stdout + result.stderr)
                self.assertEqual(self.tree(), before)

    def test_identifier_and_source_path_boundaries(self):
        # No outside writes: point a source symlink at an existing shipped file.
        (self.project / "external.py").symlink_to(TOOLKIT / "tools/test_sast_state.py")
        for path in ("../escape.py", str(self.source), "external.py", "./service.py", "C:/file.py", "a\\b.py"):
            with self.subTest(path=path):
                self.run_state("snapshot", "--id", "SAMPLE-001", "--path", path, ok=False)
        for finding_id in ("../escape", "index", "UNKNOWN", "a/b", ""):
            with self.subTest(finding_id=finding_id):
                self.run_state("checkpoint", "--id", finding_id, ok=False)
        self.assertFalse((self.root / "data/resume-state.json").exists())

    def test_new_checkpoint_keeps_previously_verified_item_pending(self):
        self.run_state("snapshot", "--id", "SAMPLE-001", "--path", "service.py")
        self.mark_verified_now()
        self.run_state("seal-verification", "--id", "SAMPLE-001")
        self.progress["items"]["SAMPLE-001"].update(workflowStatus="verified", conclusion="fix")
        self.write(self.progress_path, self.progress)
        self.run_state("checkpoint", "--id", "SAMPLE-001", "--phase", "before-edit")
        status = self.run_state("status")
        self.assertIn("SAMPLE-001", status["pendingCheckpoints"])
        self.run_state("snapshot", "--id", "SAMPLE-001", "--path", "service.py")
        self.mark_verified_now()
        self.run_state("seal-verification", "--id", "SAMPLE-001")
        status = self.run_state("status")
        self.assertNotIn("SAMPLE-001", status["pendingCheckpoints"])
        self.assertNotIn("SAMPLE-001", status["resumeCandidates"])

    def test_verified_progress_without_result_is_a_resume_candidate(self):
        self.progress["items"]["SAMPLE-001"].update(workflowStatus="verified", conclusion="fix")
        self.write(self.progress_path, self.progress)
        self.assertIn("SAMPLE-001", self.run_state("status")["resumeCandidates"])

    def test_recovery_preserves_non_utf8_damaged_progress_bytes(self):
        self.run_state("checkpoint", "--id", "SAMPLE-001")
        self.progress_path.write_bytes(b"\xff\xfeinterrupted")
        applied = self.run_state("recover-progress", "--apply")
        self.assertEqual((self.root / applied["backup"]).read_bytes(), b"\xff\xfeinterrupted")

    def test_malformed_checkpoint_and_foreign_project_root_fail_closed(self):
        self.run_state("checkpoint", "--id", "SAMPLE-001", "--path", "service.py")
        other = self.project / "other-source"
        other.mkdir()
        before = self.tree()
        self.run_state("recover-progress", "--project-root", str(other), "--apply", ok=False)
        self.assertEqual(self.tree(), before)
        path = self.root / "data/resume-state.json"
        state = self.read(path)
        state["checkpoints"]["SAMPLE-001"]["progress"]["workflowStatus"] = "finished"
        self.write(path, state)
        before = self.tree()
        self.run_state("recover-progress", "--apply", ok=False)
        self.assertEqual(self.tree(), before)

    def test_conflicting_notes_reject_recovery_instead_of_discarding_either(self):
        self.run_state("checkpoint", "--id", "SAMPLE-001")
        self.progress["items"]["SAMPLE-001"]["note"] = "A different unsaved hypothesis"
        self.write(self.progress_path, self.progress)
        before = self.tree()
        self.assertIn("conflict", self.run_state("recover-progress", "--apply", ok=False)["error"])
        self.assertEqual(self.tree(), before)

    def test_result_evidence_change_invalidates_binding_without_running_commands(self):
        self.run_state("snapshot", "--id", "SAMPLE-001", "--path", "service.py")
        self.mark_verified_now()
        path = self.root / "security-results/SAMPLE-001.json"
        result = self.read(path)
        result["verification"]["commands"] = ["touch MUST_NOT_EXIST"]
        self.store_result(result)
        self.run_state("seal-verification", "--id", "SAMPLE-001")
        self.assertFalse((self.root / "MUST_NOT_EXIST").exists())
        result = self.read(path)
        result["verification"]["results"] = ["edited after verification"]
        self.store_result(result)
        self.assertEqual(self.run_state("status")["verification"]["SAMPLE-001"]["status"], "stale")

    def test_module_invocation_works(self):
        result = subprocess.run([sys.executable, "-m", "tools.sast_state", "status"],
                                cwd=self.root, capture_output=True, text=True,
                                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(json.loads(result.stdout)["ok"])

    def test_parallel_unlocked_atomic_replacements_never_collide(self):
        script = ("from pathlib import Path; from tools.sast_io import write_text_atomic; import sys; "
                  "\nfor _ in range(35):\n write_text_atomic(Path('complete.txt'),sys.argv[1]*32000)\n")
        processes = [subprocess.Popen([sys.executable, "-c", script, letter], cwd=self.root,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                     for letter in "ABCDE"]
        for process in processes:
            output = process.communicate(timeout=20)
            self.assertEqual(process.returncode, 0, output)
        content = (self.root / "complete.txt").read_text()
        self.assertIn(content, [letter * 32000 for letter in "ABCDE"])
        self.assertEqual(list(self.root.glob(".complete.txt.*.tmp")), [])

    def test_sync_does_not_follow_external_data_directory(self):
        escaped = self.project / "escaped-data"
        (self.root / "data").rename(escaped)
        (self.root / "data").symlink_to(escaped, target_is_directory=True)
        before = {p.name: p.read_bytes() for p in escaped.iterdir() if p.is_file()}
        result = subprocess.run([sys.executable, "tools/sast_toolkit.py", "sync"], cwd=self.root,
                                capture_output=True, text=True,
                                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stdout + result.stderr)
        self.assertEqual({p.name: p.read_bytes() for p in escaped.iterdir() if p.is_file()}, before)

    def test_after_edit_checkpoint_preserves_omitted_note_and_source_context(self):
        self.run_state("checkpoint", "--id", "SAMPLE-001", "--path", "service.py",
                       "--note", "Important pending hypothesis", "--next-action", "Test invalid input")
        self.source.write_text("value = 8\n")
        self.run_state("checkpoint", "--id", "SAMPLE-001", "--phase", "after-edit")
        status = self.run_state("status")
        self.assertEqual(status["checkpoints"]["SAMPLE-001"]["note"], "Important pending hypothesis")
        self.assertEqual(status["checkpoints"]["SAMPLE-001"]["nextAction"], "Test invalid input")
        self.assertEqual(status["checkpointSourceChanges"]["SAMPLE-001"], ["service.py"])

    def test_malformed_additive_binding_never_crashes_validator(self):
        for binding in (None, [], {}, {"files": []}):
            with self.subTest(binding=binding):
                result = self.result()
                result.pop("workflowStatus")
                result["verification"]["sourceSnapshot"] = binding
                self.store_result(result)
                validation = subprocess.run([sys.executable, "tools/sast_toolkit.py", "validate"],
                                            cwd=self.root, text=True, capture_output=True,
                                            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
                self.assertNotEqual(validation.returncode, 0)
                self.assertNotIn("Traceback", validation.stdout + validation.stderr)

    def test_structural_progress_damage_recovers_with_known_identity_and_keeps_original(self):
        self.run_state("checkpoint", "--id", "SAMPLE-001")
        damaged_versions = [
            {key: value for key, value in self.progress.items() if key != "items"},
            {**self.progress, "items": {"SAMPLE-001": {"workflowStatus": "bogus"}}},
            {**self.progress, "items": {"SAMPLE-001": {"workflowStatus": [], "conclusion": {}, "note": "partial"}}},
        ]
        for damaged in damaged_versions:
            with self.subTest(damaged=damaged):
                self.write(self.progress_path, damaged)
                before = self.tree()
                preview = self.run_state("recover-progress")
                self.assertEqual(self.tree(), before)
                self.assertEqual(preview["progress"]["items"]["SAMPLE-001"], self.progress["items"]["SAMPLE-001"])
                applied = self.run_state("recover-progress", "--apply")
                self.assertEqual((self.root / applied["backup"]).read_bytes(), before["data/progress.json"])

    def test_parseable_progress_with_uncertain_or_foreign_identity_never_recovers(self):
        self.run_state("checkpoint", "--id", "SAMPLE-001")
        for record in (None, [], {"items": {}}, {**self.progress, "workspaceId": "foreign"},
                       {**self.progress, "schemaVersion": "2.0"}):
            with self.subTest(record=record):
                self.write(self.progress_path, record)
                before = self.tree()
                self.run_state("recover-progress", "--apply", ok=False)
                self.assertEqual(self.tree(), before)

    def test_malformed_browser_drafts_are_rejected_before_recovery_writes(self):
        import copy
        self.run_state("checkpoint", "--id", "SAMPLE-001")
        valid = {"source": "browser-answer", "savedAt": self.result()["updatedAt"], "result": self.result()}
        invalid = [None, [], {"../foreign": valid}, {"SAMPLE-001": self.result()}]
        for field, value in (("source", "other"), ("savedAt", "not-a-time"), ("result", "garbage")):
            invalid.append({"SAMPLE-001": {**valid, field: value}})
        for field, value in (("id", "SAMPLE-999"), ("sequence", 99), ("updatedAt", "not-a-time"),
                             ("workspaceId", "foreign"), ("resultFiles", "not-an-array")):
            draft = copy.deepcopy(valid)
            draft["result"][field] = value
            invalid.append({"SAMPLE-001": draft})
        draft = copy.deepcopy(valid)
        draft["result"]["verification"]["verifiedAt"] = "not-a-time"
        invalid.append({"SAMPLE-001": draft})
        for index, drafts in enumerate(invalid):
            with self.subTest(index=index):
                self.write(self.progress_path, self.progress)
                backup = self.project / "backup.json"
                self.write(backup, {**self.progress, "draftResults": drafts})
                before = self.tree()
                self.run_state("recover-progress", "--backup", str(backup), "--apply", ok=False)
                self.assertEqual(self.tree(), before)

    def test_seal_rejects_blank_evidence_and_equal_snapshot_timestamp(self):
        snapshot = self.run_state("snapshot", "--id", "SAMPLE-001", "--path", "service.py")["snapshot"]
        for contents in ([""], [" \t\n"], ["passed", ""]):
            with self.subTest(contents=contents):
                self.mark_verified_now()
                result = self.read(self.root / "security-results/SAMPLE-001.json")
                result["verification"]["results"] = contents
                self.store_result(result)
                before = (self.root / "security-results/SAMPLE-001.json").read_bytes()
                self.run_state("seal-verification", "--id", "SAMPLE-001", ok=False)
                self.assertEqual((self.root / "security-results/SAMPLE-001.json").read_bytes(), before)
        result = self.result()
        result["verification"]["verifiedAt"] = snapshot["capturedAt"]
        self.store_result(result)
        self.run_state("seal-verification", "--id", "SAMPLE-001", ok=False)

    def test_result_written_before_progress_blocks_query_and_sync(self):
        self.run_state("checkpoint", "--id", "SAMPLE-001")
        self.store_result(self.result())
        for command in ("query", "sync"):
            with self.subTest(command=command):
                before = self.tree()
                result = subprocess.run([sys.executable, "tools/sast_toolkit.py", command], cwd=self.root,
                                        capture_output=True, text=True,
                                        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("progress and result disagree", result.stdout + result.stderr)
                self.assertEqual(self.tree(), before)

    def test_provisional_progress_without_result_remains_usable(self):
        for command in ("query", "sync"):
            result = subprocess.run([sys.executable, "tools/sast_toolkit.py", command], cwd=self.root,
                                    capture_output=True, text=True,
                                    env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_gate_waits_for_cooperative_writer_and_init_does_not_deadlock(self):
        script = ("from pathlib import Path; from tools.sast_io import writer_lock; import sys; "
                  "\nwith writer_lock(Path('.')):\n print('locked',flush=True)\n sys.stdin.readline()\n")
        holder = subprocess.Popen([sys.executable, "-c", script], cwd=self.root, stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        gate = None
        try:
            self.assertEqual(holder.stdout.readline().strip(), "locked")
            gate = subprocess.Popen([sys.executable, "tools/sast_toolkit.py", "gate"], cwd=self.root,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            with self.assertRaises(subprocess.TimeoutExpired):
                gate.communicate(timeout=0.5)
        finally:
            holder.communicate("release\n", timeout=5)
            if gate is not None:
                gate.communicate(timeout=5)
        result = subprocess.run([sys.executable, "tools/sast_toolkit.py", "init"], cwd=self.root,
                                capture_output=True, text=True, timeout=5)
        self.assertIn("GATE: BLOCKED", result.stdout)

    def test_malformed_checkpoint_phase_and_progress_types_return_json_error(self):
        self.run_state("checkpoint", "--id", "SAMPLE-001")
        path = self.root / "data/resume-state.json"
        original = self.read(path)
        import copy
        for field, value in (("phase", []), ("phase", {}), ("progress", {"workflowStatus": [], "conclusion": {}, "note": "x"})):
            state = copy.deepcopy(original)
            state["checkpoints"]["SAMPLE-001"][field] = value
            self.write(path, state)
            self.assertFalse(self.run_state("status", ok=False)["ok"])

    def test_input_gate_stays_usable_with_damaged_progress_and_refreshes_its_mirror(self):
        try:
            from .test_toolkit import ToolkitCase
        except ImportError:
            from test_toolkit import ToolkitCase
        fixture = ToolkitCase()
        fixture.setUp()
        try:
            fixture.ready_inputs()
            mirror = fixture.data / "input-validation.js"
            expected = mirror.read_bytes()
            mirror.write_text("stale input mirror")
            progress = fixture.data / "progress.json"
            progress.write_bytes(b'{"items":')
            result = fixture.run_tool("gate")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("GATE: READY", result.stdout)
            self.assertEqual(mirror.read_bytes(), expected)
            self.assertEqual(progress.read_bytes(), b'{"items":')
            self.assertNotEqual(fixture.run_tool("validate").returncode, 0)
        finally:
            fixture.tearDown()


if __name__ == "__main__":
    unittest.main()
