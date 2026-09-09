# Editorial Copy Polish Implementation Plan

> **For agentic workers:** Use the assigned task brief and read the corresponding editorial report. Steps use checkbox syntax for tracking. The controller integrates, verifies, commits, and pushes.

**Goal:** 기존 문구 검토 결과를 반영해 설명·UI·요청문의 의미와 가독성을 개선하고 검증 후 main에 푸시한다.
**Architecture:** 기능·데이터 모델은 유지하고 정본 문구와 생성기 문구를 수정한다. 문서·프롬프트·UI는 소유 파일을 분리해 병렬 교정하며 생성물은 마지막에 한 번 재생성한다.
**Tech Stack:** Markdown, JSON, Python 표준 라이브러리, 브라우저 JavaScript, unittest, node:test.
**Spec:** 직전 사용자가 승인한 기존 문구 전체 검토. 검토 항목의 원문·대체문구를 기준으로 아래 범위를 구현한다.

## Global Constraints

- schemaVersion 1.0, JSON keys/enums, fixed answer parser labels, workbook column names, code/diff bytes and command stdout structures remain unchanged.
- No new filters, schedulers, authority grants, data migrations on live projects, installations or autonomous execution.
- Canonical skill edits are only in skills/; Claude-only agents and root packaging/docs are independent files. Plugin skill copies and USAGE.html/DECISION_LOG.md are generated, not hand-edited.
- Existing user state is preserved. Never run repository preflight/init. Fixture mutations are isolated in temporary directories.
- Versions: SAST 1.12.1, Architect 0.4.1; patch updates only, no schema change.
- Final target is origin/main, consistent with the preceding main-merge request and current tracked branch. No force push or unrelated changes.
- Instructions remain scoped: actual evidence and user authority are not created by validation; manual resumption is not automatic restart.
- Review terms by meaning, not blind substitution. workGroup classification and an execution's scope remain distinct.
- Development operates on codex/editorial-copy-polish in the existing checkout. Disjoint file ownership allows parallel editing under the active multi-agent directive.

## Tasks

### Task 1: SAST guidance
**Files:** skills/sast-remediation/SKILL.md; toolkit/{README,USAGE,SECURITY_GRILL_GUIDE,SECURITY_POLICY_BASELINE,SECURITY_SAST_WORKFLOW,SECURITY_TEST_GUIDE,AGENTS_SNIPPET}.md; toolkit/docs/*.md; toolkit/tools/README.md.
**Interfaces:** Actual labels from Task 3 must appear in USAGE. tools/README documents unchanged CLI contracts.
- [x] Read E1–E14, preserve useful current guidance, apply concrete replacements.
- [x] Align UI labels: 파일 결과 다시 읽기; 상태+결과 불러오기; 현재 결과 JSON 내보내기; AI 답변에서 브라우저 초안 만들기; 검증 완료 상태 비율; 분석 완료/변경 완료/검증 완료.
- [x] Remove nonexistent workGroup filter descriptions and explain sync before rereading generated indexes.
- [x] Fix existing D03–D06 prose: unresolved legacy decision provenance preserved/deferred; init effects enumerated; schema migration includes all producers/consumers, not two constants.
- [x] Split recovery instructions with original backup before import; actual download success remains user-confirmed.
- [x] Review diff and report findings addressed/kept and remaining concerns.

### Task 2: Prompts, templates, schemas and examples
**Files:** toolkit/prompts/*.md, project/*.md except generated DECISION_LOG.md, templates/*.md, input/data/security-guides/security-results/evidence/README.md, examples/*, schemas/*.json; plugins/sast-remediation/agents/*.md.
**Interfaces:** Generated DECISION_LOG title/body owned by Task 4. Machine fields/required lists and fixed workbook columns unchanged.
- [x] Read PT01–PT11 and LC01; apply human-text changes only.
- [x] Preserve workGroup vs execution scope; define 총괄 AI; remove reader-judging language.
- [x] Preserve required metadata in lightweight-guide instructions, distinguish full vs referenced guides, support PDF or SARIF wording.
- [x] Keep synthetic examples synthetic; no invented verification, provenance, approval, paths or hashes.
- [x] Review JSON semantic diff to ensure only title/description/human prose changed.
- [x] Report coverage of every proposed group; coordinate generator-owned PT05/PT11 with Task 4.

### Task 3: UI copy and regression checks
**Files:** SECURITY_CHECKLIST.html, assets/checklist.js, tools/test_dashboard.cjs.
**Interfaces:** Send labels to Task 1. No generated USAGE.html editing.
- [x] Read UI-01–UI-18. Use the labels listed in Task 1.
- [x] Reproduce relevant dynamic contract mismatches with consumer tests before changing them: SARIF guide/request neutrality; generated prompt keeps parser contract; full-result export and reread messages explain actual outcomes without state promotion.
- [x] Change labels/help/errors/empty states and output wording. Keep storage/draft/verification logic and DOM IDs.
- [x] Use existing two result provenance areas; don't add new filters or UI panels.
- [x] Optional small aria/title clarity edits are allowed on existing controls; no new navigation features.
- [x] Run focused then complete canonical Node suite, inspect fixed-label/diff round trips, record RED/GREEN evidence where behavior changed.

### Task 4: Root docs, Architect, CLI and packaging metadata
**Files:** README.md, HANDOFF.md, CLAUDE.md, root historical docs; Architect SKILL/CHECKLIST/references/improvement_tracker.py; toolkit/tools/sast_toolkit.py, sast_state.py; four plugin manifests, two catalogues, script comments.
**Interfaces:** DECISION_LOG generated title/body here. New versions owned here.
- [x] Apply R01–R25 to relevant prose without expanding optional features.
- [x] Correct universal installation scope/new-session/manual-copy guidance against installed CLI and official sources already identified.
- [x] Fix SARIF-neutral preflight checks, field-validation vs observation wording, nonjudgmental CLI errors, applicable authority-reference error guidance.
- [x] Add a real temporary SARIF preflight regression before code change; unchanged JSON keys/check codes.
- [x] Clarify Architect record directory vs code repository and --data payload vs stored event record.
- [x] Update current handoff with dated facts; retain historical implementation facts and replace nonportable historical links with explicit local-only evidence descriptions.
- [x] Patch versions to 1.12.1/0.4.1 and align manifests/readme/catalogue descriptions.
- [x] Run relevant Python tests, inspect semantic changes and preserve frontmatter discovery.

### Task 5: Integration, review, commit and push
**Files:** generated USAGE.html/DECISION_LOG.md/JS indexes and plugin copies, concise implementation record.
- [x] Cross-review disjoint changes for spec compliance and quality. Correct meaning regressions before integration.
- [x] Regenerate via toolkit sync and scripts/sync-plugins.sh; validate distribution with expected empty-input warning only.
- [x] Run canonical SAST Python, Architect Python, Node, packaging tests and version/sync/diff checks.
- [x] Independently test realistic guide consumption using synthetic scenarios without live writes; do not claim benchmark or real-browser testing.
- [x] Document affected groups, remaining optional features and actual verification limitations.

Publication procedure: commit reviewed changes, fetch/check origin/main, fast-forward local main only if safe, push without force and verify remote SHA. The outcome is recorded in Git and the final user handoff rather than a self-referential commit-hash field in this plan.
