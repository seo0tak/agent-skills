---
name: sast-remediation
description: Manage and remediate SAST findings you already have — input gate, source-to-report mapping, false-positive review, remediation waves with verification, cross-round carry-over, and submission-ready evidence. Accepts vendor PDF+spreadsheet reports or standard SARIF files (Semgrep, CodeQL, SonarQube). Use when the user asks to remediate/triage SAST results, review false positives, process a security scan report, or produce remediation evidence. | SAST(정적분석) 취약점 조치 워크플로우. 사용자가 SAST 결과 조치, 취약점 조치/검토, 시큐어코딩 점검 결과 처리, 오탐 검토, 취약점 증적 작성을 요청하거나 SAST PDF·검출 스프레드시트·SARIF 파일을 언급하면 사용. 사전 점검 게이트, 소스 대조 분석, 차수 이월, 조치·검증, 증적 생성 절차 포함.
argument-hint: [단계 또는 요청]
---

# SAST 취약점 조치

이 스킬 디렉터리의 `toolkit/`에 범용 SAST 취약점조치 툴킷 전체가
동봉되어 있다. 아래 절차를 따른다.

## 1. 툴킷 배치

프로젝트 루트에 `sast-remediation-toolkit/` 디렉터리가 있는지 확인한다.

- **없으면**: `${CLAUDE_SKILL_DIR}/toolkit/`을 프로젝트 루트에
  `sast-remediation-toolkit/` 이름으로 복사한다. 복사 후 사용자에게
  `input/`에 이번 차수의 SAST 자료를 넣어 달라고 요청하고 멈춘다.
  (벤더 PDF 1개+스프레드시트 1개, 또는 표준 SARIF 파일 1개)
- **있으면**: 기존 것을 그대로 사용한다. 진행 중인 차수의 산출물을
  덮어쓰지 않는다. 스킬의 toolkit이 더 최신이라도 사용자가 명시적으로
  업그레이드를 요청할 때만 고정 자산(assets, prompts, schemas, tools,
  루트 가이드 문서)만 교체하고 `data/`, `project/`, `security-*`,
  `evidence/`, `input/`은 보존한다.

## 2. 워크플로우 수행

작업 규칙과 단계별 상세는 복사된 툴킷의 문서가 기준이다.

1. `sast-remediation-toolkit/SECURITY_SAST_WORKFLOW.md`를 읽는다.
2. `sast-remediation-toolkit/prompts/00-preflight.md`부터 시작한다.
   게이트가 READY가 아니면 어떤 분석·조치도 시작하지 않는다.
3. 이후 단계는 사용자의 요청에 맞는 프롬프트 파일을 따른다:
   01 초기 분석 → (06 차수 이월, 이전 차수 산출물이 있을 때) →
   02 정책 질문(상시) → 03 조치 웨이브 → 04 대시보드 변경 흡수 →
   05 증적 생성. 새 세션에서 이어서 하면 07 재개.
3-1. 사용자가 "연속으로", "끝까지", "N개 그룹" 등 범위를 주면
   prompts/03의 연속 실행 모드로 진행한다: 그룹 사이에 확인을 묻지
   않고, 정책 질문은 파킹 후 병합 제시하며, 명시된 중단 조건에서만
   멈춘다.
4. 사용자가 특정 단계를 지정하면("웨이브 진행", "증적 만들어줘" 등)
   해당 프롬프트로 바로 진행하되, 게이트 READY 전제는 항상 지킨다.

## 2-1. 모델 티어 위임

sast-bulk-worker, sast-remediator 서브에이전트가 사용 가능하면
prompts/03의 위임 규칙을 따른다: 기계적 대량 작업은 bulk-worker,
승인된 가이드 범위의 소스 수정은 remediator, 결론 판정·정책·verified
승격은 메인 세션이 직접. 서브에이전트가 없으면 전부 직접 수행한다.

## 3. 핵심 규칙 (툴킷 문서와 동일, 요약)

- `tools/sast_toolkit.py gate`가 READY를 반환하기 전에는 초기 분석이나
  운영 소스 수정을 시작하지 않는다.
- 현재 소스가 동작의 기준이다. 보고서 라인이 어긋나면 현재 소스에서
  검출 구문을 다시 찾는다.
- 코드로 확인할 수 없는 정책만 SECURITY_GRILL_GUIDE.md에 따라 한 번에
  하나씩 질문한다.
- 상태의 기준은 `security-results/`이며 `data/progress.json`은 이와
  일치해야 한다. 갱신 후 `sync`와 `validate`를 실행한다.
- 이전 차수 산출물이 있으면 fingerprint 기준으로 오탐·예외 결론을
  이월한다 (prompts/06).
- 제출 전에는 `validate --strict`가 OK여야 한다.

## 4. 산출물 위치

모든 산출물은 프로젝트의 `sast-remediation-toolkit/` 아래에 생성된다:
`project/`(분석·정책), `data/`(대시보드 데이터),
`security-guides/`·`security-results/`(항목별 기록),
`evidence/`(제출용 xlsx). 사용자 안내 문서는 `USAGE.md` /
`USAGE.html`, 동작 원리 설명은 `docs/HOW_IT_WORKS.md`다. 사용자가
스킬의 동작 방식이나 원리를 물으면 이 문서를 기반으로 답한다.
