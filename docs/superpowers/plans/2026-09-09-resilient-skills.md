# Resilient Skills Implementation Plan

Historical, completed implementation plan for 1.12.0 / 0.4.0. The following worker
instructions describe that execution; reading this document is not a request to
rerun it. For subsequent repository/release status, see [HANDOFF.md](../../../HANDOFF.md).

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Steps use checkbox syntax for tracking.

**Goal:** Reliable SAST resumption and approval-scoped skill improvement, including readable user guidance.
**Architecture:** File-backed domain-specific checkpoints plus validated browser drafts. Separate optional architect improvement records; no scheduler or self-publishing.
**Tech Stack:** Python standard library, plain browser JavaScript, unittest, node:test.
**Spec:** [Approved design](../specs/2026-09-09-resilient-skills-design.md)

## Global Constraints

- Python standard library and browser-native JavaScript only.
- Preserve schemaVersion 1.0 and existing enums, parser labels, JSON stdout and existing user state.
- No autonomous wake-up, monitor, approval grant, patch execution, deployment, commit, push or installation.
- Canonical edits in skills/; plugin copies are generated at final integration.
- Preserve dirty baseline; versions become SAST 1.12.0 / architect 0.4.0.
- Apply patches for local source/test/document edits; run mutations only on temporary fixtures except intentional source generation at integration.

### Task 1: Durable SAST state and source verification
**Files:** tools/sast_state.py and tools/sast_io.py (new), tools/test_sast_state.py (new), tools/sast_toolkit.py, schemas/result.schema.json, optional dedicated state schema (under skills/sast-remediation/toolkit).
**Interfaces:** A separate CLI python3 tools/sast_state.py with checkpoint, snapshot, seal-verification, status, recover-progress. Status and recovery preview are read-only; recovery applies only with --apply. Publish exact help/arguments before docs integration. Cooperative IO is shared with sast_toolkit; existing public renderer functions remain untouched.
- [x] Add behavioral regression tests before implementation: parallel atomic writers; malformed and foreign backup leaves state untouched; provisional state/notes survive reconstruction; preview causes no writes; source change prevents sealing; stale or unbound verified evidence is reported; interrupted item is not omitted from resume candidates.
```python
def test_source_change_rejects_verified_binding(self):
    self.capture_snapshot("SAMPLE-001", ["service.py"])
    self.change_source("service.py")
    self.assert_rejected_without_result_change("seal-verification", "--id", "SAMPLE-001")
```
- [x] Run focused tests and record expected RED.
- [x] Implement small IO/state helpers, CLI validation and existing validator integration. Fail closed on malformed identifiers, traversal/outside-root source paths, unsupported records, wrong workspace and ambiguous recovery conflicts.
- [x] Require snapshot before verification and verify unchanged targets when binding evidence. Existing passed strings alone do not become fresh evidence automatically.
- [x] Preserve backups before recovery writes; report unrecoverable provisional information instead of inventing it.
- [x] Run focused then full Python tests; report RED/GREEN and exact CLI contract.
**Review:** interruption/authority/path boundaries, old records, helper imports in CLI/module execution.

### Task 2: Browser draft durability and readable UI
**Files:** assets/checklist.js/css, SECURITY_CHECKLIST.html, tools/test_dashboard.cjs.
**Interfaces:** Preserve current functions/IDs and fixed answer labels. Add optional draftResults to the existing schemaVersion 1.0 browser progress envelope (state and draft write together). Drafts are not canonical file results; no import promotes verification. Inform Task 5 of labels.
- [x] Add failing parse→reload→export, export→fresh-context import, malformed/foreign draft atomic rejection, storage failure, file-vs-draft freshness, unknown ID and unchanged timestamp tests.
```javascript
const first = loadDashboard(); parseFixtureAnswer(first);
const next = loadDashboard({storage: first.storage});
assert.equal(exportResult(next).resultCodeDiff, "- old();\n+ checked();\n");
```
- [x] Run RED; persist validated full drafts, retain raw code, preserve legacy state. Do not delete a draft merely because a download was clicked.
- [x] Differentiate browser-saved, pending file reflection and verified matching file; maintain explicit dirty/recovery information.
- [x] Improve snapshot labels, noncumulative count explanation, verification status display, import accounting, meaningful detail headings/code blocks and narrow-screen mapping visibility.
- [x] Run Node suite and self-review. No raw AI HTML, parser-label changes or verification promotion.
**Review:** reload durability, provenance, XSS-safe rendering and DOM accessibility contracts.

### Task 3: Approval-scoped architect improvement workflow
**Files:** skills/skill-architect/SKILL.md, ARCHITECTURE_CHECKLIST.md, references/improvement-workflow.md, scripts/improvement_tracker.py, scripts/test_improvement_tracker.py, small schema/example/evaluation artifacts only if used.
**Interfaces:** Optional local per-project improvement records, never SAST customer data. CLI creates/validates/summarizes records and guarded transitions but never runs stored commands, patches files outside its record store, grants authority or deploys.
- [x] Write failure scenarios and tests for applied-without-evaluation/authority, wrong candidate binding, failed regression, malformed input, incomplete resume, and external path/command injection.
```python
def test_applied_requires_bound_evaluation_and_authority(self):
    record = self.proposed_record()
    self.assert_rejected_without_mutation(record, "applied")
```
- [x] Run baseline tests, then implement record lifecycle: captured→proposed→evaluated→approved→applied→verified, rejected/rolled-back as explicit outcomes; approval is a recorded reference to actual user authority, never evidence created by the helper.
- [x] Bind evaluation and authority to candidate/target digest; changed candidates need renewed validation and applicable authority. Do not call tests or deploy from stored strings.
- [x] Add optional long-review resumption and result-first reporting; keep ordinary one-shot audits small. Keep references discoverable and provide realistic evaluation examples.
- [x] Run tests and independent forward test; report exact CLI and negative cases.
**Review:** no authority widening, false claims of self-learning, or unsafe arbitrary execution.

### Task 4: Markdown renderer
**Files:** tools/usage_renderer.py and tools/test_usage_renderer.py (new); render_inline/render_usage_html integration in sast_toolkit.py after Task 1.
**Interfaces:** render_inline(text) -> str; render_usage_html(markdown, css="", generated_marker="") -> str; existing sast_toolkit wrappers retain signatures and provide CSS/marker.
- [x] Add failing tests for two-space bullet continuations, nested lists, code inside strong emphasis, fences and safe links/escaping.
```python
self.assertIn("<strong>백업 후 <code>sync</code></strong>", render_inline("**백업 후 `sync`**"))
self.assertNotIn("</li>\n<p>대조", render_usage_html("- 기록을\n  대조합니다."))
```
- [x] Run RED; implement renderer without dependencies; preserve CSS/standalone HTML generation.
- [x] Run renderer tests and existing generation/drift tests.

### Task 5: SAST guidance and text alignment
**Files:** SAST SKILL, toolkit USAGE/README, prompts, SECURITY_* guides, supporting README/templates/docs, Claude agent instructions; no JS/Python ownership overlap.
**Interfaces:** Use exact CLI from Tasks 1–3; preserve answer labels and machine keys.
- [x] Map every 2026-09-08 readability finding and 2026-09-09 persistence finding to implementation/document updates.
- [x] Align vendor PDF(s)+spreadsheet or SARIF input set throughout; label historic design material.
- [x] Rewrite resume to check/repair state before trusting queries and indexes, inspect unfinished edits/source freshness, reuse verified authority scope, and preserve policy/backup provenance.
- [x] Rewrite wave with checkpoint/snapshot/seal sequence and single-writer policy; guard carry-over on prior verified evidence and current policy applicability.
- [x] Explain backup coverage and legacy verification limitations. Clarify provisional progress vs canonical results, tool validation vs real test execution.
- [x] Improve all human prose/templates/examples without translating fixed keys/enums or manufacturing results.
- [x] Consumer-oriented scenario review; no source-string tests as a substitute.

### Task 6: Integration, packaging and independent review
**Files:** root README/HANDOFF, manifests/catalogue, generated copies and USAGE.html, implementation evidence.
- [x] Integrate helpers, run all Python/Node tests, verify frontmatter/reference resolution.
- [x] Bump versions and migration/upgrade asset policy together; synchronize generated HTML and plugin copies.
- [x] Run python3 -B tools/sast_toolkit.py validate, Python suites, node --test, scripts/check-versions.sh and scripts/sync-plugins.sh --check.
- [x] Obtain independent spec/quality review and realistic forward tests; address concrete failures and re-run affected tests.
- [x] Record results, unverified real-browser/power-loss/network behavior and remaining rollout requirements. No commit/push/install.
