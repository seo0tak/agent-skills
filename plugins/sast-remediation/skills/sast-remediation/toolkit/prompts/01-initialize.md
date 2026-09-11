# 초기 분석 요청문

````text
현재 프로젝트에서 SAST 취약점 조치 작업을 초기화해 주세요.

입력:
- 현재 프로젝트 소스 전체
- data/input-validation.json에서 이번 게이트가 확정한 입력 세트의 SAST 자료
  (PDF·스프레드시트 입력 모드: PDF 1개 이상 + 스프레드시트 1개 / SARIF 모드: .sarif 1개, PDF 선택)

먼저 다음 문서를 읽고 따르세요.
- sast-remediation-toolkit/SECURITY_SAST_WORKFLOW.md
- sast-remediation-toolkit/SECURITY_POLICY_BASELINE.md
- sast-remediation-toolkit/SECURITY_GRILL_GUIDE.md
- sast-remediation-toolkit/SECURITY_TEST_GUIDE.md
- sast-remediation-toolkit/docs/DETERMINATION_GUIDE.md

시작 조건:
- sast-remediation-toolkit/project/INPUT_VALIDATION.md의 게이트 상태가
  READY여야 합니다.
- sast-remediation-toolkit/data/input-validation.json의 status가
  ready여야 합니다.
- `sast-remediation-toolkit` 디렉터리에서
  `python3 tools/sast_toolkit.py gate`가 성공해야 합니다.

하나라도 충족하지 않으면 초기 분석을 시작하지 말고
prompts/00-preflight.md 절차로 돌아가 차단 원인을 보고하세요.

이번 단계에서는 운영 소스를 수정하지 않습니다.

수행할 작업:
1. 입력 검증에서 확정한 세트와 inputs.manifest에 기록된 파일 경로를 사용하고
   프로젝트·보고서 식별정보를 유지합니다. 파일명이나 수정 시각으로 다른
   “최신” 세트를 다시 고르지 않습니다.
2. 프로젝트의 모듈, 소스 루트, 계층, 공통 컴포넌트, 외부 연동,
   설정 경계, 빌드 및 테스트 방법을 분석합니다.
   SECURITY_SAST_WORKFLOW.md의 「소스 탐색 계약」에 따라 현재 프로젝트 루트,
   언어, 실제 탐색 기능과 인덱스 상태를 확인하고 목적별 탐색과 대체 절차를 사용합니다.
   탐색 수단이나 한계가 판단에 중요하면 PROJECT_ANALYSIS.md에 기록합니다.
   프로필의 validation.verificationMeans에 이 프로젝트에서 실제로
   사용 가능한 검증 수단을 선언합니다(예: build, lint, unit-test,
   scanner-recheck, runtime-smoke, manual-review). 로컬·개발 환경에서
   애플리케이션 기동이 가능한지도 이때 확인해 기록합니다. 테스트가 없는 영역이 있으면
   validation.limitations에 명시합니다.
3. 검출 목록을 표준 finding 형식으로 변환합니다.
   PDF·스프레드시트 입력 모드
   - 입력 범위: 스프레드시트의 전체 검출 항목을 사용합니다.
   - 위험도: 검사 도구의 위험도 등급을 표준 값으로 변환하고 매핑표를
     project-profile에 기록합니다. Sparrow 보고서의 기본 매핑:
     매우위험→critical, 위험→very-high, 높음→high, 보통→medium,
     낮음→low, 그 외/불명→unknown. 다른 SAST 검사 도구는 해당 도구의 등급
     정의를 확인해 별도로 매핑하고, Sparrow 매핑을 그대로 적용하지 않습니다.
     동일 차수 내에서 매핑은 하나만 사용합니다.
   - 도구 상태: Sparrow 기준으로 `유형`(신규/기존 등)은 재검출 판단의
     참고 정보로 기록합니다.
     `이슈 상태`와 `이슈 의견`에 수용·예외·오탐 처리 이력이 있으면
     해당 결론 후보(exception/false-positive)로 분류하고 근거에 도구
     상태를 기록합니다. `체커 타입`(보안/품질/코드 규칙)은 finding에
     분류로 보존해 증적에서 구분 집계할 수 있게 합니다.
   - 미확인 필드: 의미를 확인하지 못한 값은 `report.vendorAttributes`에
     원문 그대로 보존합니다(예: `{"A.S": "Y"}`). 값 분포를 보고하고
     사용자에게 의미를 확인합니다.
     확인 전에는 결론·승인·예외 판단에 사용하지 않습니다. 의미가 확인되면
     보존한 원문을 바탕으로 재분류할 수 있습니다.
     `A.S`처럼 의미가 불명확한 SAST 검사 도구 필드는 해당 보고서·버전에서 의미를
     확인하기 전까지 승인·예외 플래그로 사용하지 않습니다.
     특정 프로젝트에서 관찰한 값 분포를 다른 보고서의 공통 규칙으로 삼지 않습니다.
   도구의 기존 상태만으로 verified로 올리지 않으며, 현재 소스 대조는 모든
   항목에 수행합니다.
   SARIF 모드
   - 각 run의 results를 검출 항목으로 사용
     (ruleId → 체커 코드, locations → 파일·라인·검출 구문,
      level/rank → 위험도, partialFingerprints가 있으면
      sourceMapping.fingerprint의 기본값으로 사용)
4. 체커 설명과 해결 가이드를 체커별로 추출합니다.
   - PDF·스프레드시트 입력 모드: PDF에서 추출
   - SARIF 모드: 각 rule의 shortDescription, fullDescription, help에서
     추출. 내용이 부족한 체커는 일반 보안 지식으로 보완하되 출처를
     구분해 기록
   - 모든 체커의 plainDescription을 한두 줄로 작성합니다. 보안 배경지식
     없이도 이해할 수 있도록, 문제가 생기는 조건과 업무에 미치는 영향을
     설명합니다. 필요한 전문 용어에는 짧은 풀이를 덧붙입니다.
   - 체커 의미가 불분명하면 원본 보고서와 해당 제품·프레임워크의 1차 문서를
     확인합니다. 소스 주석이나 다른 AI의 요약은 확인할 가설로만 취급합니다.
5. 모든 검출 파일, 함수, 라인과 검출 코드를 현재 소스에 대조합니다.
   정의·구현·참조·타입·호출 관계는 최신 파일을 반영해 정상 응답하는 의미 탐색을
   우선합니다. 보고서의 검출 구문과 설정·동적 연결에는 텍스트 탐색도 사용합니다. 실패하거나
   참조가 0건인 결과만으로 not-found 또는 영향 없음으로 판정하지 않습니다.
   fingerprint가 기록된 항목에는 stableKey를 함께 부여합니다:
   SK- + sha1(fingerprint) 앞 8자리. 이 값이 차수를 넘는 고정
   식별자입니다. 보고서의 검출 ID는 차수에 따라 바뀔 수 있습니다.
6. 동일 원인과 충돌 파일을 기준으로 작업 그룹을 만듭니다.
   대표 항목과 별도로 각 멤버의 안전 전제, 핵심 호출자·입력 타입·설정과 잔존
   동적 경로를 확인합니다. 한 멤버의 원문 사용자 입력이 위험한 사용처에 도달하면
   단순 예방 조치로 낮추지 않습니다.
7. `DETERMINATION_GUIDE.md`에 따라 규칙 적용성, 실제 영향과 안전 전제·미확인,
   조치 필요성(`필수/예방/없음/미정`)을 먼저 기록한 뒤 초기 결론 후보를 수정,
   오탐, 운영 설정, 예외처리, 추가 검토로 분류합니다. 실제로 검토한 항목의
   작업 상태만 결론과 독립적으로 `analyzed`로 기록하고, 손대지 않은 항목을
   일괄 승격하지 않습니다.
8. 코드만으로 결정할 수 없는 정책 질문을 식별합니다.
9. 범용 HTML은 변경하지 않고 프로젝트별 data 파일만 생성합니다.

project/ 아래 마크다운 산출물은 다음 로컬 메타데이터 형식으로 시작합니다.
문서 정리 규약이며 외부 지식 형식과의 호환성을 인증하지 않습니다.

```yaml
---
type: sast/<종류>   # project-analysis | security-policy | decision-log | work-groups | input-validation
title: <문서 제목>
description: <한 줄 요약>
timestamp: <YYYY-MM-DDTHH:MM:SSZ, 마지막 갱신>
tags: [sast, <프로젝트명>]
---
```

결정 로그는 직접 쓰지 않습니다. 정본은 `data/decisions.json`이고
`project/DECISION_LOG.md`는 `sync`가 거기서 생성합니다(날짜별 그룹, 최신이
위, frontmatter 포함). 결정을 기록할 때는 decisions.json에 항목을 추가하고
sync를 실행합니다 — 필드는 schemas/decisions.schema.json.
project/index.md를 생성해 각 문서를 한 줄 설명과 함께 링크합니다
(프로젝트 문서 목록). frontmatter는 미래의 지식 수집·에이전트
소비를 위한 것이며, 없는 필드가 있어도 동작에는 영향이 없습니다.

생성 또는 갱신할 파일:
- project/index.md
- project/INPUT_VALIDATION.md
- project/PROJECT_ANALYSIS.md
- project/PROJECT_SECURITY_POLICY.md
- project/DECISION_LOG.md (sync가 data/decisions.json에서 생성)
- project/WORK_GROUPS.md
- data/input-validation.json 및 .js
- data/project-profile.json 및 .js
- data/findings.json 및 .js
- data/checker-guides.json 및 .js
- data/progress.json 및 .js
- data/decisions.json 및 .js (workspaceId를 프로필과 맞춤, decisions는 빈 배열로 시작)

tools/sast_toolkit.py validate를 실행해 결과 형식을 검증합니다.

마지막 보고:
- 입력 자료 일치 여부
- 프로젝트 기술 구성
- 전체 및 위험도별 검출 건수
- 현재 소스와 정확히 일치/이동/변경/미발견 건수
- 초기 결론 후보별 건수
- 설정 및 외부 규격 관련 분리 건수
- 추천 작업 그룹
- 사용자 확인이 필요한 첫 번째 정책 질문 하나(있을 때만)
- 생성한 산출물 경로
````
