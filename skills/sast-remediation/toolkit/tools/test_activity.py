"""Durable activity behavior through real temporary workspaces and public APIs."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from . import sast_activity

TOOLKIT = Path(__file__).resolve().parent.parent


class ActivityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "toolkit"
        shutil.copytree(TOOLKIT, self.root, ignore=shutil.ignore_patterns("__pycache__", ".sast-write.lock"))
        shutil.copyfile(self.root / "examples/project-profile.json", self.root / "data/project-profile.json")

    def tearDown(self):
        self.tmp.cleanup()

    def run_activity(self, *arguments, ok=True):
        result = subprocess.run([sys.executable, "-B", "tools/sast_activity.py", *arguments],
                                cwd=self.root, capture_output=True, text=True,
                                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        if ok:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        return json.loads(result.stdout)

    def tree(self):
        return {str(path.relative_to(self.root)): path.read_bytes()
                for path in self.root.rglob("*") if path.is_file()}

    def test_start_survives_process_exit_and_status_is_read_only(self):
        attempt = self.run_activity("start", "--action", "remediation", "--summary", "fixture edit",
                                    "--actor", "fixture", "--id", "SAMPLE-001")
        before = self.tree()
        status = self.run_activity("status")
        self.assertEqual(status["unfinishedCount"], 1)
        self.assertEqual(status["unfinishedAttempts"][0]["attemptId"], attempt["attemptId"])
        self.assertEqual(status["unfinishedAttempts"][0]["itemIds"], ["SAMPLE-001"])
        self.assertEqual(before, self.tree(), "status must not invent a finish or refresh files")

    def test_failed_attempt_and_completed_retry_keep_both_attempts(self):
        first = self.run_activity("start", "--action", "remediation", "--summary", "first try",
                                  "--actor", "fixture", "--operation-id", "op-1", "--attempt-id", "try-1")
        failed = self.run_activity("finish", "--attempt-id", first["attemptId"],
                                   "--outcome", "failed", "--summary", "test failed")
        repeated = self.run_activity("finish", "--attempt-id", first["attemptId"],
                                     "--outcome", "failed", "--summary", "test failed")
        self.assertEqual(failed, repeated)
        second = self.run_activity("start", "--action", "remediation", "--summary", "retry",
                                   "--actor", "fixture", "--operation-id", "op-1", "--attempt-id", "try-2")
        self.run_activity("finish", "--attempt-id", second["attemptId"],
                          "--outcome", "succeeded", "--summary", "command completed")
        status = self.run_activity("status")
        self.assertEqual(status["eventCount"], 4)
        self.assertEqual(status["unfinishedCount"], 0)
        self.assertEqual(status["failedCount"], 1)
        self.assertEqual(status["succeededCount"], 1)
        self.assertNotIn("verified", json.dumps(status))

    def test_event_replay_is_idempotent_and_conflicting_payload_is_rejected(self):
        journal = sast_activity.ActivityJournal(self.root)
        event = journal.start("analysis", "same action", "fixture")
        self.assertEqual(journal.append(event), event)
        before = self.tree()
        with self.assertRaisesRegex(ValueError, "conflicting payload"):
            journal.append({**event, "summary": "different action"})
        self.assertEqual(before, self.tree())

    def test_record_action_persists_start_before_callback_and_actual_finish(self):
        seen = []
        def callback():
            status = sast_activity.ActivityJournal(self.root).status()
            seen.append(status["unfinishedCount"])
            return {"ok": True, "checkpoint": {"phase": "after-edit", "note": "retained note",
                                                  "nextAction": "run tests", "progress": {"workflowStatus": "analyzed"}}}
        result = sast_activity.record_action(self.root, "checkpoint", callback, actor="fixture")
        self.assertTrue(result["ok"])
        self.assertEqual(seen, [1])
        events = self.run_activity("query")["events"]
        self.assertEqual(events[-1]["outcome"], "succeeded")
        self.assertEqual(events[-1]["after"]["result"]["checkpoint"]["nextAction"], "run tests")

    def test_failed_activity_storage_prevents_callback(self):
        (self.root / "data/activity").write_text("not a directory", encoding="utf-8")
        called = []
        with self.assertRaises((OSError, ValueError)):
            sast_activity.record_action(self.root, "edit", lambda: called.append(True))
        self.assertEqual(called, [])

    def test_callback_system_exit_is_recorded_and_reraised(self):
        def callback():
            raise SystemExit(3)
        with self.assertRaises(SystemExit):
            sast_activity.record_action(self.root, "sync", callback)
        status = self.run_activity("status")
        self.assertEqual(status["unfinishedCount"], 0)
        self.assertEqual(status["failedCount"], 1)

    def test_notes_redact_explicit_secrets_and_bound_large_values(self):
        event = self.run_activity("note", "--action", "analysis", "--actor", "fixture",
                                  "--summary", "password=very-private Bearer abc.def.ghi",
                                  "--after", json.dumps({"token": "private-value", "note": "x" * 10000}),
                                  "--important")
        serialized = json.dumps(event)
        self.assertNotIn("very-private", serialized)
        self.assertNotIn("abc.def.ghi", serialized)
        self.assertNotIn("private-value", serialized)
        self.assertEqual(event["after"]["token"], "[REDACTED]")
        self.assertLessEqual(len(event["after"]["note"]), 2000)
        self.assertTrue(event["important"])

    def test_browser_import_preserves_prior_report_payload_and_deduplicates(self):
        event = sast_activity.ActivityJournal(self.root).start("fixture", "fixture", "fixture")
        event = {**event, "eventId": "browser-1", "attemptId": "browser-attempt", "operationId": "browser-op",
                 "source": "browser", "kind": "changed", "outcome": "info", "reportId": "prior-report"}
        backup = Path(self.tmp.name) / "browser-backup.json"
        backup.write_text(json.dumps({"schemaVersion": "1.0", "workspaceId": "sample-workspace",
                                       "activityEvents": [event]}), encoding="utf-8")
        imported = self.run_activity("import-browser", "--file", str(backup))
        self.assertEqual(imported["importedCount"], 1)
        self.assertEqual(self.run_activity("import-browser", "--file", str(backup))["importedCount"], 0)
        self.assertIn(event, self.run_activity("query")["events"])
        backup.write_text(json.dumps({"schemaVersion": "1.0", "workspaceId": "sample-workspace",
                                       "activityEvents": [{**event, "summary": "different"}]}), encoding="utf-8")
        self.assertIn("conflict", self.run_activity("import-browser", "--file", str(backup), ok=False)["error"])

    def test_reconcile_records_baseline_then_both_direct_progress_changes(self):
        progress_path = self.root / "data/progress.json"
        progress = {"schemaVersion": "1.0", "workspaceId": "sample-workspace", "items": {
            "SAMPLE-001": {"workflowStatus": "todo", "conclusion": "unreviewed", "note": "first"}}}
        progress_path.write_text(json.dumps(progress), encoding="utf-8")
        first = self.run_activity("reconcile")
        self.assertEqual(first["changedCount"], 0)
        self.assertGreater(first["observedCount"], 0)
        for text in ("second", "third"):
            progress["items"]["SAMPLE-001"]["note"] = text
            progress_path.write_text(json.dumps(progress), encoding="utf-8")
            before = self.tree()
            self.assertGreater(self.run_activity("status")["driftCount"], 0)
            self.assertEqual(before, self.tree())
            self.assertGreater(self.run_activity("reconcile")["changedCount"], 0)
        events = self.run_activity("query", "--id", "SAMPLE-001")["events"]
        changes = [event for event in events if event["kind"] == "changed"]
        self.assertEqual([event["after"]["value"]["note"] for event in changes], ["second", "third"])
        self.assertEqual(changes[0]["before"]["value"]["note"], "first")
        self.assertTrue(all(event["important"] and event["actor"] == "unknown" for event in changes))
        self.assertEqual(self.run_activity("status")["driftCount"], 0)

    def test_automatic_checkpoint_retains_replaced_note_and_next_action(self):
        for name in ("findings", "progress"):
            shutil.copyfile(self.root / "examples" / (name + ".json"), self.root / "data" / (name + ".json"))
        for note in ("earlier note", "later note"):
            result = subprocess.run([sys.executable, "-B", "tools/sast_state.py", "checkpoint", "--id", "SAMPLE-001",
                                     "--phase", "after-edit", "--note", note, "--next-action", "inspect tests"],
                                    cwd=self.root, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        events = self.run_activity("query", "--id", "SAMPLE-001")["events"]
        finished = [event for event in events if event["kind"] == "finished"]
        self.assertEqual([event["after"]["result"]["checkpoint"]["note"] for event in finished], ["earlier note", "later note"])
        self.assertTrue(all(event["important"] for event in finished))
        self.assertEqual(finished[0]["after"]["result"]["checkpoint"]["nextAction"], "inspect tests")

    def test_uninitialized_sync_does_not_create_live_activity(self):
        shutil.copyfile(TOOLKIT / "data/project-profile.json", self.root / "data/project-profile.json")
        result = subprocess.run([sys.executable, "-B", "tools/sast_toolkit.py", "sync"],
                                cwd=self.root, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.root / "data/activity").exists())
        self.assertEqual((self.root / "data/activity.js").read_bytes(), (TOOLKIT / "data/activity.js").read_bytes())

    def test_start_retry_is_idempotent_and_important_survives_finish(self):
        journal = sast_activity.ActivityJournal(self.root)
        first = journal.start("analysis", "same start", "fixture", attempt_id="attempt-1", operation_id="op-1", important=True)
        repeated = journal.start("analysis", "same start", "fixture", attempt_id="attempt-1", operation_id="op-1", important=True)
        self.assertEqual(repeated, first)
        finished = journal.finish("attempt-1", "succeeded", "command succeeded")
        self.assertTrue(finished["important"])

    def test_browser_batch_rejects_late_invalid_lifecycle_without_partial_import(self):
        journal = sast_activity.ActivityJournal(self.root)
        base = journal.start("fixture", "fixture", "fixture")
        browser = {**base, "source": "browser", "eventId": "browser-start", "attemptId": "browser-attempt", "operationId": "browser-operation"}
        bad_finish = {**browser, "eventId": "browser-finish", "kind": "finished", "outcome": "succeeded",
                      "recordedAt": "2000-01-01T00:00:00Z"}
        backup = Path(self.tmp.name) / "bad-browser.json"
        backup.write_text(json.dumps({"schemaVersion": "1.0", "workspaceId": "sample-workspace",
                                       "activityEvents": [browser, bad_finish]}), encoding="utf-8")
        before = journal.projection()["events"]
        with self.assertRaisesRegex(ValueError, "preced|earlier"):
            journal.import_browser(backup)
        self.assertEqual(journal.projection()["events"], before)

    def test_corrupt_record_and_symlink_block_changes_but_remain_readable_diagnostics(self):
        journal = sast_activity.ActivityJournal(self.root)
        event = journal.start("analysis", "fixture", "fixture")
        path = next((self.root / "data/activity").glob("*/*.json"))
        path.write_text("{broken", encoding="utf-8")
        self.assertTrue(journal.status()["warnings"])
        called = []
        with self.assertRaises(ValueError):
            sast_activity.record_action(self.root, "edit", lambda: called.append(True))
        self.assertEqual(called, [])
        self.assertEqual(path.read_text(), "{broken")
        path.unlink()
        path.symlink_to(self.root / "examples/result.json")
        self.assertTrue(journal.projection()["warnings"])
        with self.assertRaises(ValueError):
            journal.append(event)

    def test_large_canonical_observation_retains_identity_and_does_not_repeat(self):
        progress = {"schemaVersion": "1.0", "workspaceId": "sample-workspace", "items": {
            "SAMPLE-001": {"workflowStatus": "analyzed", "conclusion": "fix", "note": "important note",
                           "draftDetail": {f"field-{index}": "x" * 2500 for index in range(50)}}}}
        (self.root / "data/progress.json").write_text(json.dumps(progress), encoding="utf-8")
        self.run_activity("reconcile")
        self.assertEqual(self.run_activity("status")["driftCount"], 0)
        self.assertEqual(self.run_activity("reconcile")["observedCount"], 0)
        events = self.run_activity("query", "--id", "SAMPLE-001")["events"]
        self.assertEqual(events[0]["after"]["record"], "data/progress.json#items/SAMPLE-001")
        self.assertTrue(events[0]["after"]["exists"])
        self.assertEqual(events[0]["after"]["itemIds"], ["SAMPLE-001"])

    def test_result_reconcile_preserves_judgment_verification_and_prior_reason(self):
        result = json.loads((self.root / "examples/result.json").read_text(encoding="utf-8"))
        result.update(reason="original judgment", resultSummary="changed boundary", evidenceNote="test evidence")
        result["verification"].update(results=["unit test passed"], limitations=["external system unavailable"])
        path = self.root / "security-results/SAMPLE-001.json"
        path.write_text(json.dumps(result), encoding="utf-8")
        self.run_activity("reconcile")
        result["reason"] = "reconsidered judgment"
        path.write_text(json.dumps(result), encoding="utf-8")
        self.run_activity("reconcile")
        changes = [event for event in self.run_activity("query", "--id", "SAMPLE-001")["events"] if event["kind"] == "changed"]
        self.assertEqual(changes[0]["before"]["value"]["reason"], "original judgment")
        self.assertEqual(changes[0]["after"]["value"]["reason"], "reconsidered judgment")
        self.assertEqual(changes[0]["after"]["value"]["verification"]["results"], ["unit test passed"])

    def test_manually_corrupted_finish_does_not_hide_unfinished_start(self):
        journal = sast_activity.ActivityJournal(self.root)
        start = journal.start("analysis", "fixture", "fixture")
        finish = journal.finish(start["attemptId"], "succeeded", "completed")
        path = next((self.root / "data/activity").glob("*/" + finish["eventId"] + ".json"))
        finish["operationId"] = "other-operation"
        path.write_text(json.dumps(finish), encoding="utf-8")
        status = journal.status()
        self.assertTrue(status["warnings"])
        self.assertEqual(status["unfinishedCount"], 1)

    def test_fsync_failure_prevents_callback_and_post_action_failure_is_explicit(self):
        called = []
        with mock.patch.object(sast_activity.os, "fsync", side_effect=OSError("disk unavailable")):
            with self.assertRaises(OSError):
                sast_activity.record_action(self.root, "edit", lambda: called.append(True))
        self.assertEqual(called, [])
        # A later disk failure cannot roll back a completed external edit.
        patcher = mock.patch.object(sast_activity.os, "fsync", side_effect=OSError("disk unavailable"))
        def changed():
            called.append(True)
            patcher.start()
            return 0
        try:
            with self.assertRaisesRegex(RuntimeError, "may already be applied"):
                sast_activity.record_action(self.root, "edit", changed)
        finally:
            patcher.stop()
        self.assertEqual(called, [True])
        self.assertEqual(self.run_activity("status")["unfinishedCount"], 1)

    def test_corrupt_progress_is_observed_as_unknown_not_deleted_items(self):
        progress_path = self.root / "data/progress.json"
        shutil.copyfile(self.root / "examples/progress.json", progress_path)
        self.run_activity("reconcile")
        progress_path.write_text("{broken", encoding="utf-8")
        status = self.run_activity("status")
        item_changes = [change for change in status["canonicalChanges"] if "#items/" in change["after"]["record"]]
        self.assertTrue(item_changes)
        self.assertTrue(all(change["after"]["exists"] is None for change in item_changes))
        self.assertTrue(status["warnings"])

    def test_large_unicode_before_and_after_fit_the_event_byte_limit(self):
        values = {f"field-{index}": "한" * 3000 for index in range(50)}
        event = sast_activity.ActivityJournal(self.root).note("analysis", "large metadata", "fixture",
                                                               before=values, after=values)
        self.assertLessEqual(len(sast_activity.json_text(event).encode()), 32768)

    def test_process_kill_after_start_leaves_unfinished_without_synthesized_cause(self):
        script = ("from pathlib import Path\nimport time\nfrom tools.sast_activity import record_action\n"
                  "def callback():\n print('entered', flush=True)\n time.sleep(30)\n"
                  "record_action(Path('.'), 'fixture-interruption', callback)\n")
        process = subprocess.Popen([sys.executable, "-B", "-c", script], cwd=self.root,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertEqual(process.stdout.readline().strip(), "entered")
            process.kill()
            process.communicate(timeout=5)
            before = self.tree()
            status = self.run_activity("status")
            self.assertEqual(status["unfinishedCount"], 1)
            self.assertEqual(status["failedCount"], 0)
            self.assertEqual(status["stoppedCount"], 0)
            self.assertEqual(before, self.tree())
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)

    @unittest.skipUnless(shutil.which("node"), "Node is required to evaluate the static browser projection")
    def test_display_projection_preserves_safe_metadata_and_omission_markers(self):
        metadata = {"__proto__": {"note": "unsafe key"}, "constructor": "unsafe key", "safe": "retained data"}
        event = sast_activity.ActivityJournal(self.root).note("analysis", "metadata", "fixture", after=metadata)
        self.assertEqual(event["after"], {"safe": "retained data", "_omittedKeys": ["__proto__", "constructor"]})
        script = ("const fs=require('node:fs'); global.window={}; "
                  "eval(fs.readFileSync('data/activity.js','utf8')); "
                  "console.log(JSON.stringify(window.SAST_TOOLKIT_DATA.activity.events[0].after));")
        result = subprocess.run(["node", "-e", script], cwd=self.root, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), event["after"])

    def test_browser_and_general_notes_cannot_spoof_canonical_observations(self):
        progress_path = self.root / "data/progress.json"
        shutil.copyfile(self.root / "examples/progress.json", progress_path)
        journal = sast_activity.ActivityJournal(self.root)
        journal.reconcile()
        progress = json.loads(progress_path.read_text(encoding="utf-8"))
        progress["items"]["SAMPLE-001"]["note"] = "actual unobserved change"
        progress_path.write_text(json.dumps(progress), encoding="utf-8")
        drift = journal.status()["canonicalChanges"]
        self.assertEqual(len(drift), 1)
        base = journal.note("browser.state", "fixture", "user", source="browser")
        fake = {**base, "eventId": "browser-fake-observation", "recordedAt": "2099-01-01T00:00:00Z",
                "action": "canonical.reconcile", "kind": "observation", "after": drift[0]["after"]}
        backup = Path(self.tmp.name) / "spoofed-browser.json"
        backup.write_text(json.dumps({"schemaVersion": "1.0", "workspaceId": "sample-workspace", "activityEvents": [fake]}), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "reserved"):
            journal.import_browser(backup)
        self.assertEqual(journal.status()["driftCount"], 1)
        with self.assertRaisesRegex(ValueError, "reserved"):
            journal.note("canonical.reconcile", "spoof", "unknown", source="external", after=drift[0]["after"])
        self.assertEqual(journal.status()["driftCount"], 1)

    def test_operation_retry_requires_same_logical_identity_but_allows_new_actor(self):
        journal = sast_activity.ActivityJournal(self.root)
        journal.start("remediation", "first", "worker-one", operation_id="same-operation", item_ids=["ITEM-A"])
        before = journal.projection()["events"]
        profile_path = self.root / "data/project-profile.json"
        original = json.loads(profile_path.read_text(encoding="utf-8"))
        for variation in ("action", "items", "workspace", "report", "source"):
            with self.subTest(variation=variation):
                profile = json.loads(json.dumps(original))
                if variation == "workspace":
                    profile["workspaceId"] = "different-workspace"
                if variation == "report":
                    profile["report"]["id"] = "different-report"
                profile_path.write_text(json.dumps(profile), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "operation"):
                    journal.start("verification" if variation == "action" else "remediation", "retry", "worker-two",
                                  operation_id="same-operation", item_ids=["ITEM-B"] if variation == "items" else ["ITEM-A"],
                                  source="external" if variation == "source" else "agent")
                self.assertEqual(journal.projection()["events"], before)
        profile_path.write_text(json.dumps(original), encoding="utf-8")
        retry = journal.start("remediation", "retry", "worker-two", operation_id="same-operation", item_ids=["ITEM-A"])
        self.assertEqual(retry["actor"], "worker-two")
        self.assertEqual(journal.status()["unfinishedCount"], 2)

    def test_browser_batch_operation_conflict_is_rejected_before_any_import(self):
        journal = sast_activity.ActivityJournal(self.root)
        base = journal.note("browser.state", "fixture", "user", source="browser", item_ids=["ITEM-A"])
        first = {**base, "eventId": "browser-new-1", "operationId": "import-operation", "attemptId": "import-attempt-1"}
        second = {**first, "eventId": "browser-new-2", "attemptId": "import-attempt-2", "action": "browser.note", "itemIds": ["ITEM-B"]}
        backup = Path(self.tmp.name) / "operation-conflict.json"
        backup.write_text(json.dumps({"schemaVersion": "1.0", "workspaceId": "sample-workspace", "activityEvents": [first, second]}), encoding="utf-8")
        before = journal.projection()["events"]
        with self.assertRaisesRegex(ValueError, "operation"):
            journal.import_browser(backup)
        self.assertEqual(journal.projection()["events"], before)

    def test_browser_progress_validation_rejects_conflicting_logical_operations(self):
        first = {"schemaVersion": "1.0", "eventId": "browser-state", "recordedAt": "2026-09-15T00:00:00Z",
                 "workspaceId": "sample-workspace", "reportId": "sample-report", "operationId": "browser-operation",
                 "attemptId": "browser-state-attempt", "kind": "changed", "action": "browser.state", "outcome": "info",
                 "source": "browser", "actor": "user", "itemIds": ["SAMPLE-001"], "summary": "State changed",
                 "before": {"workflowStatus": "todo"}, "after": {"workflowStatus": "in-progress"},
                 "evidence": [], "important": True}
        second = {**first, "eventId": "browser-note", "attemptId": "browser-note-attempt", "action": "browser.note"}
        before = json.dumps([first, second])
        with self.assertRaisesRegex(ValueError, "operation.*conflicting"):
            sast_activity.validate_browser_events([first, second], "sample-workspace")
        self.assertEqual(json.dumps([first, second]), before)

    def test_browser_progress_validation_preserves_unfinished_and_changed_events(self):
        journal = sast_activity.ActivityJournal(self.root)
        start = journal.start("browser.analysis", "Analysis started", "user", source="browser")
        changed = journal.note("browser.note", "Note changed", "user", source="browser", kind="changed",
                               before={"note": "earlier"}, after={"note": "later"})
        events = [start, changed]
        serialized = json.dumps(events)
        before = self.tree()
        self.assertEqual(sast_activity.validate_browser_events(events, "sample-workspace"), events)
        self.assertEqual(json.dumps(events), serialized)
        self.assertEqual(self.tree(), before)
        self.assertEqual(journal.status()["unfinishedCount"], 1)

    def test_import_contract_rejects_unsafe_metadata_and_loose_timestamps(self):
        journal = sast_activity.ActivityJournal(self.root)
        base = journal.note("browser.state", "fixture", "user", source="browser")
        nested = "leaf"
        for _ in range(9):
            nested = {"child": nested}
        invalid = [{**base, "after": {key: "untrusted"}} for key in ("__proto__", "prototype", "constructor")]
        invalid += [{**base, "after": nested}, {**base, "after": {"number": float("nan")}}]
        invalid += [{**base, "recordedAt": value} for value in
                    ("2026-09-15 00:00:00Z", "2026-09-15T00:00Z", "2026-09-15T00:00:00+0000", "2026-09-15T00:00:00+00:60")]
        for index, value in enumerate(invalid):
            with self.subTest(case=index), self.assertRaises((ValueError, TypeError)):
                sast_activity.validate_event(value)
        self.assertEqual(sast_activity.validate_event({**base, "after": nested["child"]})["after"], nested["child"])


if __name__ == "__main__":
    unittest.main()
