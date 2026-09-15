# Risk Processing Scope Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 위험도 처리 범위를 저장하고 실행·화면·재개·완료 집계에서 동일하게 사용한다.

**Architecture:** 프로젝트 profile이 범위의 정본이며 Python 공통 모듈이 분류·집계를 제공한다.
HTML은 정본을 읽고 변경 요청을 복사한다. 범위 밖 상태와 기존 자료는 보존한다.

**Tech Stack:** Python 표준 라이브러리, JSON Schema, 정적 HTML/CSS/JavaScript, unittest, Node test.

**Spec:** `docs/superpowers/specs/2026-09-15-risk-processing-scope-design.md`

## Global Constraints

- 선택 등급은 `critical`, `very-high`, `high`, `medium`, `low`다. `info`는 범위 밖, `unknown`은 별도다.
- `processingScope`의 필드는 `workspaceId`, `reportId`, `minRisk`, `updatedAt`, `updatedBy`, `reason`이다.
- 기존 결과 형식과 상태 enum, schemaVersion `1.0`은 유지한다.
- 범위 밖 상태·결과·백업을 설정 때문에 변경하지 않는다. 입력 전체 등록과 검증을 유지한다.
- 고객 소스·설치본·프로젝트 복사본을 변경하지 않는다. `.DS_Store`는 기존 사용자 파일로 보존한다.
- 정본은 `skills/`이며 `plugins/*/skills/*`는 sync 스크립트로만 생성한다.
- SAST 버전 `1.13.0`, Architect `0.4.3`. 새 외부 의존성·네트워크 서비스는 추가하지 않는다.

---

### Task 1: 범위 모델·CLI

**Files:**
- Create: `skills/sast-remediation/toolkit/tools/sast_scope.py`
- Modify: `skills/sast-remediation/toolkit/tools/sast_toolkit.py`
- Modify: `skills/sast-remediation/toolkit/schemas/project-profile.schema.json`
- Test: `skills/sast-remediation/toolkit/tools/test_toolkit.py`

**Interfaces:**
- `resolve_scope(profile) -> dict`: 없으면 configured false, 있으면 검증하고 configured true와 범위 필드 반환. 잘못된 범위는 ValueError.
- `scope_bucket(finding, scope) -> str`: `in-scope`, `out-of-scope`, `unknown`, `unconfigured`.
- `scope_summary(profile, findings, progress) -> dict`: `scope`, `counts`, `selectedComplete`, `allComplete`.
- counts 필드: total, inScope, outOfScope, unknown, unconfigured, inScopeVerified, inScopeRemaining, totalVerified.
- progress는 기존 envelope의 items로 해석한다. 빈 대상은 selectedComplete false.

- [x] Step 1: 실제 CLI 테스트를 먼저 추가한다. 7개 등급 literal fixture에서 high 선택 후 counts는 total7/inScope3/outOfScope3/unknown1, in-scope ID는 critical/very-high/high 3개다. 설정 전 대상 조회 실패, 일반 query 7개, 설정 뒤 기존 progress/results byte 보존을 검증한다.

```python
proc = self.run_tool('query', '--scope', 'in-scope')
self.assertNotEqual(proc.returncode, 0)
proc = self.run_tool('scope', '--min-risk', 'high', '--set-by', 'user', '--reason', 'approved scope')
self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
summary = json.loads(self.run_tool('scope').stdout)
self.assertEqual(summary['counts']['inScope'], 3)
self.assertEqual(summary['counts']['outOfScope'], 3)
self.assertEqual(summary['counts']['unknown'], 1)
```

- [x] Step 2: `python3 -B -m unittest tools.test_toolkit`로 추가 동작의 RED를 기록한다.
- [x] Step 3: 공통 모듈·schema·CLI를 구현한다. 인자·식별자·시각 검증, 읽기 전용 scope, 잠금 내 설정 저장·sync, query 교집합을 구현한다. rank에 의존하지 않는다.
- [x] Step 4: 잘못된 enum/상속명/객체형, ID 불일치, 누락 필드, 미승인 입력, 각 임계값, unknown/info, 확대·축소와 일반조회 보존을 테스트하고 GREEN을 기록한다.
- [x] Step 5: 부모에게 구현·RED/GREEN·파일·한계를 보고한다. 공용 git 커밋은 부모가 통합한다.

### Task 2: 실행·재개·사용자 안내

**Files:**
- Modify: `skills/sast-remediation/toolkit/tools/sast_state.py`, `tools/test_sast_state.py`
- Modify: `skills/sast-remediation/SKILL.md`
- Modify: toolkit `SECURITY_SAST_WORKFLOW.md`, `USAGE.md`, `docs/HOW_IT_WORKS.md`, `docs/VERSIONING.md`, prompts `01-initialize.md`, `03-remediation-wave.md`, `04-reconcile-results.md`, `05-final-evidence.md`, `06-carry-over.md`, `07-resume.md`, `templates/evidence-columns.md`
- Modify: `plugins/sast-remediation/agents/sast-remediator.md`

**Interfaces:**
- Task 1의 공통 함수를 사용한다. status 기존 전체 resumeCandidates는 유지하고 `processingScope`(scope_summary 결과), `inScopeResumeCandidates`를 추가한다.
- before-edit/snapshot/seal은 selected 포함만 허용. after-edit/recovery는 상태 보존 경로로 유지한다.

- [x] Step 1: 선택 범위 high, high/low 항목으로 실행 경계 RED 테스트를 추가한다. 미설정도 before-edit/snapshot/seal 거부한다. 기존 백업 복원은 범위와 무관하게 유지되는 테스트를 쓴다.

```python
# 실제 state CLI의 종료코드와 상태 파일 내용을 검증한다.
self.assertNotEqual(outside_before_edit.returncode, 0)
self.assertEqual(inside_before_edit.returncode, 0)
self.assertEqual(after_edit_for_existing_work.returncode, 0)
self.assertEqual(status['inScopeResumeCandidates'], ['HIGH-1'])
```

- [x] Step 2: RED 후 scope helper로 경계를 적용하고 전체 회귀를 실행한다. 기존 state 테스트의 승인 fixture에 명시 범위를 넣고 미설정 fixture는 별도 검증한다.
- [x] Step 3: 기존 스킬 소비 baseline 한계를 확인한 뒤 사용자 요청→scope 저장→in-scope query→재개→전체/선택 집계의 안내를 보강한다. 입력 등록 전에 자료를 잘라내거나 낮은 등급을 오탐·deferred로 일괄 변경하지 않는다.
- [x] Step 4: 새로 읽는 독립 소비자가 동일 합성 상황에서 범위를 저장하고 혼합 그룹·미확인·부수 영향·선택 완료를 정확히 처리하는지 검토한다. human prose는 문자열 매칭 테스트 대신 실제 소비 결과로 확인한다.
- [x] Step 5: 실행·문서 변경을 자체 점검하고 보고한다. USAGE.html 생성은 통합 시 sync에 맡긴다.

### Task 3: 체크리스트 UI와 왕복 검증

**Files:**
- Modify: `skills/sast-remediation/toolkit/SECURITY_CHECKLIST.html`
- Modify: `skills/sast-remediation/toolkit/assets/checklist.js`, `assets/checklist.css`
- Modify: `skills/sast-remediation/toolkit/tools/test_dashboard.cjs`

**Interfaces:**
- `toolkitData.projectProfile.processingScope`를 읽는다. 구조/식별자/범위 검증을 Python과 맞춘다.
- 적용 요청에는 workspaceId/reportId/minRisk를 포함한다. 복사는 승인/저장이 아니며 정본에 반영 후 새로고침하도록 안내한다.

- [x] Step 1: 기존 VM/DOM harness로 실제 추천·요청 복사·상태 유지의 RED를 만든다.

```javascript
// high 선택은 두 낮은 등급과 info/unknown을 추천하지 않는다.
assert.deepEqual(recommendedIds, ['CRITICAL-1', 'VERY-HIGH-1', 'HIGH-1']);
assert.equal(storageAfterSelection, storageBeforeSelection);
assert.equal(copiedScopeRequest.includes('high'), true);
```

- [x] Step 2: 패널·선택값·미적용 상태·요청 복사·별도 집계를 추가한다. 일반 목록 필터와 초기화는 독립 유지한다. 범위 밖 AI 조치 요청은 버튼과 함수 양쪽에서 막고 읽기/기존결과 보존은 유지한다.
- [x] Step 3: 범위 확대·축소, 미설정/오류, 0대상, 백업/reload, 보기 필터와 독립, mixed그룹, 위험도 rank 오류에 대한 실제 함수 회귀를 실행한다. 기존 fixture는 기존 동작용 명시 범위를 부여한다.
- [x] Step 4: JS와 Python을 같은 합성 profile/findings에 실행해 분류·집계 일치를 검증한다. 전체 test_dashboard를 실행해 GREEN을 기록한다.
- [x] Step 5: 실제 브라우저 검증은 부모가 합성 임시 복사본에서 수행한다. 결과·한계를 보고하고 커밋은 부모에게 맡긴다.

### Task 4: 통합 검증·릴리스

**Files:** README.md, HANDOFF.md, SAST 두 plugin.json, generated mirrors, review record.

- [x] Step 1: 실제 HTML로 범위 미설정·high 적용·미적용 변경·필터 초기화·범위 밖 요청 차단·좁은 화면을 확인한다.
- [x] Step 2: SAST Python, state, usage, Node, Architect, packaging 회귀와 validate/syntax를 실행한다. 저장소에서 preflight/init을 실행하지 않는다.
- [x] Step 3: 버전 갱신 후 toolkit sync, `scripts/sync-plugins.sh`, `--check`, `scripts/check-versions.sh`를 실행한다.
- [x] Step 4: 독립 검토에서 명세 적합성과 코드 품질을 확인하고 발견한 결함은 회귀와 함께 수정한다. 적용한 범위·한계를 review/HANDOFF에 기록한다.
- Step 5 (Git 기록으로 확인): 관련 파일만 커밋하고 원격 main을 확인해 안전하게
  통합·일반 푸시한다. 기존 `.DS_Store`와 설치본은 보존한다. 이 커밋에 포함되는
  계획 문서는 자기 자신의 푸시를 증명할 수 없으므로 원격 main과 커밋 일치를 확인한다.

## 진행 기록

- 승인 전 관찰: 화면 riskFilter는 표 목록만 필터링하며 추천은 전체 findings를 사용한다. CLI --risk는 단일 등급 조회이고 차수별 처리 범위 정본은 없다.
- 독립 설계 검토: unknown 별도 집계, 범위 변경 시 분모 재계산, 혼합 그룹 부수 효과 자동 완료 금지, 보기 필터와 실행 범위 분리가 필요하다.
- 테스트 기준: 기존 Node 68개 통과. Python 기존 회귀 결과는 통합 기록에 추가한다.
- 통합 결과: 정본 210개, 배포 사본 Node 81개 통과. 독립 재검토의 수정 사항과
  실제 화면·소비 시험, 검증 한계는 `docs/reviews/2026-09-15-risk-processing-scope.md`에 기록했다.
