# Durable Activity Log Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** SAST 작업·오류·중단·변경을 누적 보존하고 기존 체크리스트에서 조회한다.

**Architecture:** 기존 JSON 상태를 유지하고 월별 독립 이벤트 파일을 추가한다. 공통 기록기가
시작과 실제 종료를 분리하고 생성 JS와 브라우저 초안 이력을 화면에서 구분한다.

**Tech Stack:** Python standard library, vanilla JavaScript, static HTML/CSS, unittest, node:test.

**Spec:** `docs/superpowers/specs/2026-09-15-durable-activity-log-design.md`

## Global Constraints

- Python 표준 라이브러리와 기존 정적 HTML/JS만 사용한다.
- 기존 schemaVersion과 workflow/conclusion enum은 유지한다.
- 중요 이벤트는 덮어쓰거나 자동 삭제하지 않는다. 실제 고객/설치본을 변경하지 않는다.
- 종료 기록 없음은 unfinished이며 실제 원인이나 종료 시각을 추측하지 않는다.
- source/actor는 실제 기록 출처이고 권한·검증 완료의 증명이 아니다.
- 로그 오류를 성공으로 숨기지 않는다. query/status/복구 미리보기는 읽기 전용이다.
- sast-remediation 1.14.0, skill-architect 0.4.3. 정본 skills/에서만 편집한다.

---

### Task 1: 누적 기록기와 명령 연결

**Files:** Create `skills/sast-remediation/toolkit/tools/sast_activity.py`,
`tools/test_activity.py`, `schemas/activity-event.schema.json`, `data/activity.js`.
Modify `tools/sast_state.py`, `tools/sast_toolkit.py` and their tests.

**Interfaces:** produces event/projection fields exactly as Spec; window.SAST_TOOLKIT_DATA.activity
is the generated envelope. Common recorder handles read-only projection, automatic command
attempts, explicit agent steps, state reconciliation, browser-event import.

- [x] RED: add real temporary-workspace tests for start without finish, completed retry,
  rejected duplicate event payload, persisted before/after events, and failing write preventing callback.
  Example assertion shape:
  ```python
  self.run_activity('start', '--action', 'remediation', '--summary', 'fixture edit', '--actor', 'fixture')
  status = self.run_activity('status')
  self.assertEqual(status['unfinishedCount'], 1)
  ```
- [x] Run `python3 -B -m unittest tools.test_activity` and capture missing-feature failures.
- [x] Implement append-only file writer, schema validation, attempt lifecycle and projection;
  `start -> callback -> finish` never conflates command success with verified.
- [x] Connect toolkit/state mutation commands, canonical digest/state reconcile, readonly
  recovery diagnostics. Preserve existing errors and record attempts including failure.
- [x] Run focused tests then all Python suites; commit only Task 1 files and report RED/GREEN.

### Task 2: 체크리스트 작업 로그 및 브라우저 이력

**Files:** Create `skills/sast-remediation/toolkit/assets/activity.js`,
`tools/test_activity_dashboard.cjs`. Modify `assets/checklist.js`, `assets/checklist.css`,
`SECURITY_CHECKLIST.html`, `schemas/progress.schema.json`, relevant existing Node tests.

**Interfaces:** consumes `window.SAST_TOOLKIT_DATA.activity` envelope defined in Spec. Produces optional
`activityEvents` array in browser progress envelope using the same event fields and source=browser.
No backend source files are owned by this task. Expose a small `window.SAST_ACTIVITY` helper
for projection/render/validation integration; actual function names documented in task report.

- [x] RED: fixture two status changes, reload and export/import; both history events survive.
  ```javascript
  assert.equal(exported.activityEvents.length, 2);
  assert.equal(restored.activityEvents[0].source, 'browser');
  ```
- [x] RED: failed storage does not falsely claim history persisted; foreign/colliding imported
  events reject atomically; text containing HTML remains text; >50 events paginate.
- [x] Implement event helper and logging at state/draft/import change boundaries; store
  draft state and events together, no event for unchanged refresh or filter changes.
- [x] Add full/item panels, independent filters/search/date, bounded scrolling, expandable
  detail, file/browser source badges and loaded/generated timestamps; keyboard accessible.
- [x] Run focused new and existing Node tests, syntax checks; commit Task 2 files and report.

### Task 3: 사용·재개 계약과 배포 검증

**Files:** Modify SAST SKILL.md, toolkit docs/ACTIVITY_LOG.md (new), HOW_IT_WORKS.md,
VERSIONING.md, USAGE.md, SECURITY_SAST_WORKFLOW.md, prompts/03-remediation-wave.md,
04-reconcile-results.md, 07-resume.md, tools/README.md, data/README.md, toolkit README;
root README/HANDOFF, two SAST plugin manifests; sync generated/mirror files.

**Interfaces:** use actual Task 1 CLI and Task 2 screen labels, no invented flags.

- [x] Run baseline retrieval scenario against old skill: ask how to retain two edits and
  a failed verification across interruption. Record absent cumulative recipe, not inferred remote loss.
- [x] Write a concise lifecycle recipe using implemented start/finish/reconcile/status and
  explicit failure/stopped handling, plus browser-only persistence/import distinction.
- [x] Forward-test revised recipe in isolated fixture; verify no fabricated interruption
  cause, no log-derived verified, no loss of earlier records on retry.
- [x] Document migration preservation, no automatic purge, direct-edit detection limits,
  log-write failures and safe read-only diagnostics. Update 1.14.0 manifests/README.
- [x] Run `python3 -B -m unittest tools.test_toolkit tools.test_sast_state tools.test_usage_renderer tools.test_activity`,
  `node --test tools/test_dashboard.cjs tools/test_activity_dashboard.cjs`, Architect/packaging
  tests, validate, mirror/version checks. Verify generated output and actual browser at narrow/wide width.
- [x] Independent final code review; fix blocking defects with focused regression tests.
- [ ] Commit, integrate to main only after clean verification, push without force and verify remote SHA.
