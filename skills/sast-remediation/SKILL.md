---
name: sast-remediation
description: Manage and remediate SAST findings you already have — input gate, source-to-report mapping, false-positive review, remediation execution with verification, current-code review of prior decisions, and evidence prepared for submission review. Accepts vendor PDF+spreadsheet reports or standard SARIF files (Semgrep, CodeQL, SonarQube). Use when the user asks to remediate/triage SAST results, review false positives, process a security scan report, or produce remediation evidence. | SAST(정적분석) 취약점 조치 워크플로우. 사용자가 SAST 결과 조치, 취약점 조치/검토, 시큐어코딩 점검 결과 처리, 오탐 검토, 취약점 증적 작성을 요청하거나 SAST PDF·검출 스프레드시트·SARIF 파일을 언급하면 사용. 사전 점검 게이트, 소스 대조 분석, 차수 이월, 조치·검증, 증적 생성 절차 포함.
---

# SAST 취약점 조치

이 스킬 디렉터리의 `toolkit/`에 여러 프로젝트에 복사해 사용하는 파일 기반 SAST 조치 툴킷이
동봉되어 있다. 아래 절차를 따른다.

## 1. 툴킷 배치

프로젝트 루트에 `sast-remediation-toolkit/` 디렉터리가 있는지 확인한다.

- **없으면**: 이 스킬 디렉터리(이 SKILL.md가 있는 곳)의 `toolkit/`을
  프로젝트 루트에 `sast-remediation-toolkit/` 이름으로 복사한다. 복사 후 사용자에게
  `input/`에 이번 차수의 SAST 자료를 넣어 달라고 요청하고 멈춘다.
  (벤더 PDF 1개 이상+스프레드시트 1개, 또는 표준 SARIF 파일 1개;
  SARIF 모드의 PDF는 선택)
- **있으면**: 기존 것을 그대로 사용한다. 진행 중인 차수의 산출물을
  덮어쓰지 않는다. 스킬의 toolkit이 더 최신이라도 사용자가 명시적으로
  업그레이드를 요청할 때만 진행한다. 먼저 **새로 설치된 스킬**의
  `toolkit/docs/VERSIONING.md`에서 「업그레이드 자산 정책」과 해당
  마이그레이션을 읽는다. 교체·보존·병합 대상의 정본은 그 목록 하나다.
  프로젝트 상태와 사용자 수정본을 보존하고, 도구와 새 안내를 함께
  갱신한 뒤 sync와 validate를 실행해 **에러와 경고 모두** 확인한다.
  구버전 입력 승인에 내용 해시가 없으면 00 사전 점검과 의미 대조를 다시
  수행한다. 필드/버전 경고마다 새 문서의 처리 규칙을 따르며, 경고 하나를
  일괄적으로 기존 산출물과 호환되지 않는 변경(breaking change)이라고 판단하거나
  에러 0건만으로 완료하지 않는다.

## 2. 워크플로우 수행

작업 규칙과 단계별 상세는 복사된 툴킷의 문서가 기준이다.

1. `sast-remediation-toolkit/SECURITY_SAST_WORKFLOW.md`를 읽는다.
2. `sast-remediation-toolkit/prompts/00-preflight.md`부터 시작한다.
   게이트가 READY가 아니면 어떤 분석·조치도 시작하지 않는다.
3. 이후 단계는 사용자의 요청에 맞는 프롬프트 파일을 따른다:
   01 초기 분석 → (06 차수 이월, 이전 차수 산출물이 있을 때) →
   02 정책 질문(필요할 때마다) → 03 조치 실행 → 04 대시보드 변경 흡수 →
   05 증적 생성. 새 세션에서 이어서 하면 07 재개.
4. 사용자가 "연속으로", "끝까지", "N개 그룹" 등 범위를 주면
   prompts/03의 연속 실행 모드로 진행한다. 작업 그룹은
   `grouping.workGroup`으로 묶은 분류 단위이고, 조치 실행은 이번 요청에서
   처리하도록 승인된 범위로 하나 이상의 작업 그룹을 포함할 수 있다. 작업
   그룹 사이에 확인을 묻지 않고, 정책 확인이 필요한 항목만 `needs-review`로
   보류해 `policyQuestions`에 기록한 뒤 병합 제시하며, 명시된 중단 조건에서만
   멈춘다.
5. 사용자가 특정 단계를 지정하면("조치 실행", "증적 만들어줘" 등)
   해당 프롬프트로 바로 진행하되, 게이트 READY 전제는 항상 지킨다.

## 선택: 등록된 작업 에이전트에 역할 분담

실행 환경이 서브에이전트 위임을 지원하고 sast-bulk-worker,
sast-remediator가 등록돼 있으면(Claude Code 플러그인 설치 시 동봉)
prompts/03의 위임 규칙을 따른다: 기계적 대량 작업은 bulk-worker,
승인된 가이드 범위의 소스 수정은 remediator, 결론 판정·정책·verified
승격은 메인 세션이 직접. 그 외 환경(Codex, Cursor, Grok 등)이나
서브에이전트가 없으면 같은 절차를 직접 수행한다. 품질·속도·비용은 실행 환경에서 확인한다.

## 3. 핵심 규칙 (툴킷 문서와 동일, 요약)

- `tools/sast_toolkit.py gate`가 READY를 반환하기 전에는 초기 분석이나
  현재 소스 파일 수정을 시작하지 않는다.
- 대상 프로젝트의 현재 작업 사본(이하 "현재 소스")이 동작의 기준이다.
  보고서 라인이 어긋나면 현재 소스에서
  검출 구문을 다시 찾는다.
- 코드와 소스 밖 증거(데이터·설정·프론트·로그)로 확인할 수 없는 정책만
  SECURITY_GRILL_GUIDE.md에 따라 한 번에 하나씩, 보안 용어가 아니라
  업무 사실로 질문한다. 관찰 방법이 적힌 미확인 기본안을 사용자가
  선택했고 변경 권한이 있을 때만 적용한다. 답변이나 권한이 없으면
  해당 항목을 보류한다. 결정은 `data/decisions.json`에 decidedBy와 함께
  기록하고 sync한다 — 미확인 기본안에 관찰 방법이 기록되지 않으면 validate 오류.
- 큰 findings.json은 읽지 않는다. `tools/sast_toolkit.py query`로 그룹·
  상태별 항목만 받고, 현황은 `query --summary`로 본다.
- 결과 정본은 `security-results/`다. `data/progress.json`은 결과와 일치해야
  하는 집계이며, 아직 결과가 없는 임시 진행상태·메모도 보관한다.
- 수정 전·후 `tools/sast_state.py checkpoint`, 검증 직전 `snapshot`, 실제
  검증 결과 작성 후 `seal-verification`을 사용한다. 재개는 07의 원본 상태
  검사·복구 미리보기부터 수행한다. status의 stale/unbound를 완료로 신뢰하지 않는다.
- 갱신 후 `sync`·`validate`·`sast_state.py status`를 확인한다. 체크포인트는
  소스 백업이나 자동 재시작 기능이 아니다. 공용 정본은 한 작성자가 담당한다.
- 이전 차수는 fingerprint로 오탐·예외 재사용 후보를 찾고 과거 검증·현재
  코드·정책·외부 조건을 대조한다. 새 차수 verified는 현재 소스에서 재검증한다 (06).
- 제출 전에는 `validate --strict`와 검증 신선도, 실제 검증·증적을 함께
  확인한다. 자동 검사 성공을 취약점 해소·사용자 승인으로 확대하지 않는다.
- 실행 권한은 현재 요청 또는 확인 가능한 사용자 승인 범위에서 판단한다.
  같은 승인 범위는 재사용하되 파일 기록만으로 권한을 만들지 않는다.
- 응답은 결론 → 근거 → 검증·한계 → 다음 작업 순서로 간결하게 쓴다.
  고정 응답 라벨·JSON 키·enum은 바꾸지 않고 설명만 읽기 쉽게 작성한다.

## 4. 산출물 위치

모든 산출물은 프로젝트의 `sast-remediation-toolkit/` 아래에 생성된다:
`project/`(분석·정책), `data/`(진행상태·재개 기록),
`security-guides/`·`security-results/`(항목별 기록),
`evidence/`(제출용 xlsx). 사용자 안내 문서는 `USAGE.md`(정본)와
거기서 생성되는 `USAGE.html`, 동작 원리 설명은 `docs/HOW_IT_WORKS.md`다. 사용자가
스킬의 동작 방식이나 원리를 물으면 이 문서를 기반으로 답한다.
