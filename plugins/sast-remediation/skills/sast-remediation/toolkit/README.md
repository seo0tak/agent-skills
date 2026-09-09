# Universal SAST Remediation Toolkit

> **English summary** — This is not a scanner. It is a remediation
> management workflow for SAST results you already have: an input
> readiness gate, source-to-report mapping, one-question-at-a-time
> policy resolution, remediation waves with verification, cross-round
> carry-over of false-positive decisions (fingerprint-matched), a
> file-based dashboard, and submission-ready evidence workbooks.
> Inputs: a vendor PDF + findings spreadsheet, **or a standard SARIF
> file** (Semgrep, CodeQL, SonarQube, ...). Pair it with a scanning
> skill or CI SAST job: they find issues, this toolkit manages what
> happens next. Docs are currently in Korean.

현재 프로젝트 소스와 선택 보고서(PDF·스프레드시트 또는 SARIF)로 취약점
분석, 정책 확인, 소스 조치, 검증, 증적 정리를 반복 수행하기 위한
범용 패키지입니다.

이 패키지의 고정 파일에는 특정 조직, 프로젝트, 분석 번호, 패키지명,
프레임워크 또는 빌드 도구를 넣지 않습니다. 프로젝트마다 달라지는
정보는 초기 분석 단계에서 `project/`와 `data/` 아래에 생성합니다.

## 매번 준비할 입력

1. 현재 프로젝트 소스
2. 최신 SAST 검출 자료 — 다음 중 한 조합을 `input/`에 넣습니다.
   - **벤더 모드**: 상세 보고서 PDF 1개 이상(대용량 분할 허용) + 검출 스프레드시트 1개
   - **SARIF 모드**: 표준 `.sarif` 파일 1개 (Semgrep, CodeQL,
     SonarQube 등의 출력. PDF 선택)

파일명은 자유롭지만 같은 검사 차수의 자료여야 합니다.

리포트가 여러 벌이면(도구별·차수별) `input/` 바로 아래가 아니라
`input/<세트명>/` 폴더로 나눠 보관할 수 있습니다. 세트가 하나면 자동
선택되고, 여러 개면 `preflight --input-set <세트명>`으로 지정합니다.
한 차수에는 한 세트만 사용하며 세트 간 병합은 지원하지 않습니다.

이 툴킷은 **스캐너가 아닙니다**. 취약점을 찾는 도구가 아니라, 이미
받은 SAST 결과를 조치·오탐검토·검증·증적까지 관리하는 워크플로우입니다.
스캔 자체는 Semgrep 같은 도구나 스캔용 Claude 스킬로 수행하고, 그
출력(SARIF)을 이 툴킷의 입력으로 사용하면 됩니다.

실제 차수를 처리하는 순서별 상세 절차, 명령어 치트시트, 자주 겪는
상황은 `USAGE.md` 또는 브라우저용 `USAGE.html`을, 동작 원리는
`docs/HOW_IT_WORKS.md`를 참고합니다.

## 빠른 시작

1. 이 디렉터리 전체를 대상 프로젝트 안에 복사합니다.
2. 위 입력 조합 중 한 세트를 `input/`에 넣습니다.
3. AI에게 `prompts/00-preflight.md`의 요청문을 전달합니다.
4. 요청문은 `GATE: READY`인 경우 `prompts/01-initialize.md` 절차까지
   자동으로 계속합니다. `BLOCKED`이면 부족하거나 불일치한 입력을 먼저
   바로잡고 다시 실행합니다.
5. 생성된 `project/PROJECT_ANALYSIS.md`와
   `SECURITY_CHECKLIST.html`을 확인합니다.
6. AI가 코드와 증거로 결정할 수 없는 정책을 업무 사실로 질문하면 한
   번에 하나씩 답합니다("모르겠다"도 답입니다). 답변은
   `project/PROJECT_SECURITY_POLICY.md`와 `data/decisions.json`에
   누적되고, `project/DECISION_LOG.md`는 거기서 생성됩니다.
7. 이전 차수 산출물이 있으면 `prompts/06-carry-over.md`로 오탐·예외
   재사용 후보를 찾고 과거 근거·현재 적용 조건을 대조합니다.
   새 차수의 검증 완료는 현재 소스에서 다시 확인합니다.
8. 초기 분석을 확인한 후 `prompts/03-remediation-wave.md`로 실제 조치를
   시작합니다. 새 세션에서 이어서 할 때는 `prompts/07-resume.md`를
   사용합니다.
9. 처리 결과는 `security-results/`와 `data/progress.*`에 반영합니다.
   결과 정본은 `security-results/`입니다. progress에는 결과와 일치하는
   집계와 아직 결과가 없는 임시 상태·메모가 함께 있습니다.
10. 제출 전에는 `validate --strict`로 데이터 오류를 확인하고,
    `sast_state.py status`의 stale/unbound, 실제 검증 근거와 증적을 함께
    검토합니다. 어느 한 검사만으로 제출 승인이 되지는 않습니다.
    전체 실행 명령은 `tools/README.md`를 따릅니다.

사전 점검은 두 단계입니다. 도구가 소스 존재 여부와 파일 개수·형식을
기계적으로 확인한 뒤, AI가 현재 프로젝트와 선택 보고서의 프로젝트 식별정보,
검사 차수, 검출 건수와 소스 범위를 대조합니다. 두 단계가 모두 통과해야
`READY`가 됩니다.

## 디렉터리 역할

```text
sast-remediation-toolkit/
├── README.md
├── SECURITY_CHECKLIST.html
├── SECURITY_SAST_WORKFLOW.md
├── SECURITY_POLICY_BASELINE.md
├── SECURITY_GRILL_GUIDE.md
├── SECURITY_TEST_GUIDE.md
├── AGENTS_SNIPPET.md
├── input/                       # 이번 차수 PDF·스프레드시트 또는 SARIF
├── project/                     # 프로젝트 초기 분석과 확정 정책
├── data/                        # 대시보드가 읽는 프로젝트별 데이터
├── security-guides/             # 처리 전 항목별 실제 코드 검토
├── security-results/            # 처리 후 조치 및 검증 결과
├── evidence/                    # 제출용 결과 및 의견
├── prompts/                     # 단계별 재사용 요청문
├── schemas/                     # 표준 데이터 계약
├── examples/                    # 중립적인 작성 예시
├── assets/                      # 범용 대시보드 코드와 스타일
├── tools/                       # 동기화·검증·수동 재개
└── docs/                        # 설계와 유지보수 문서
```

## 고정 자산과 생성 자산

업그레이드의 교체·보존·병합 목록은
[`docs/VERSIONING.md`의 업그레이드 자산 정책](docs/VERSIONING.md#업그레이드-자산-정책)이
정본입니다. 새 설치본의 안내를 먼저 읽고, 도구와 문서를 함께 갱신하며
프로젝트 상태와 사용자 정의 템플릿은 보존합니다.

프로젝트별 생성 자산:

- `project/INPUT_VALIDATION.md`
- `project/PROJECT_ANALYSIS.md`
- `project/PROJECT_SECURITY_POLICY.md`
- `project/DECISION_LOG.md` (생성물 — 정본은 `data/decisions.json`)
- `project/WORK_GROUPS.md`
- `data/input-validation.json` 및 `.js`
- `data/project-profile.json` 및 `.js`
- `data/findings.json` 및 `.js`
- `data/checker-guides.json` 및 `.js`
- `data/progress.json` 및 `.js`
- `security-guides/<ID>.json` 및 `.js`
- `security-results/<ID>.json` 및 `.js`
- `evidence/` 아래 제출용 결과

`project/`의 문서는 type·title 등 로컬 메타데이터 규약을 사용합니다.
외부 수집 도구와의 호환성은 별도로 확인합니다. 상세는 `docs/HOW_IT_WORKS.md` 참고.

## 기준 자료 우선순위

판단이 충돌하면 다음 우선순위를 사용합니다.

1. 현재 소스의 실제 동작과 호출 관계
2. 프로젝트에서 확정한 정책과 외부 연동 규격
3. 선택 보고서의 검출 목록(스프레드시트 또는 SARIF results)
4. PDF·SARIF rules의 검출 코드와 체커 가이드
5. 이 패키지의 공통 보안 기준

PDF의 해결 예시는 특정 코드에 그대로 적용하는 패치가 아닙니다.
항목별 실제 파일, 함수, 타입, 호출부와 맞는지 먼저 검토합니다.

정책 질문은 답하는 사람이 보안이나 이 프로젝트를 잘 모른다는 전제로
설계되어 있습니다. 접근이 허용된 증거를 확인한 뒤 업무 사실만 묻습니다.
관찰 장치를 추가할 때도 실제 사용자 선택과 변경 범위가 필요합니다.
원리는 `docs/HOW_IT_WORKS.md`, 규칙은 `SECURITY_GRILL_GUIDE.md`를 따릅니다.

## 대시보드 실행

`SECURITY_CHECKLIST.html`을 브라우저에서 직접 엽니다. 프로젝트별 데이터는
`data/*.js`로 읽기 때문에 별도 서버가 없어도 기본 기능이 동작합니다.

대시보드는 열릴 때 `security-results/`의 항목별 결과를 자동으로
반영합니다(상태의 기준). `전체 결과 갱신`은 페이지를 새로고침하지 않고
파일 결과를 다시 읽을 때 사용합니다.

진행상태는 브라우저에도 임시 저장됩니다. 파일 상태와 브라우저 저장본이
다르면 항목별 `updatedAt`이 최신인 쪽을 반영하고, 충돌이 있으면 화면
상단에 경고 배너로 건수를 표시합니다. 브라우저에만 있는 변경은 반드시
`상태+결과 백업`으로 내려받아 04에서 출처·상태·상세 초안을 대조합니다. AI가 파일
기반 상태를 갱신하면 `전체 결과 갱신`으로 다시 읽을 수 있습니다.

## 중단과 재개

수정 전·후 체크포인트와 검증 전 스냅샷을 `sast_state.py`로 저장합니다.
재개 시 07에서 원본 상태·현재 소스부터 확인하고, 복구는 미리보기 후
`--apply`로 반영합니다. 자동 재시작·네트워크 감시·무승인 배포는 하지 않습니다.
저장되지 않은 정보는 복구할 수 없습니다. 명령과 한계는 `tools/README.md`,
`docs/HOW_IT_WORKS.md`를 참고하세요.

## 완료 기준

- 입력 적합성 게이트가 `READY`여야 합니다.
- 모든 검출 항목이 현재 소스와 대조되어야 합니다.
- 각 항목에는 조치 결론과 근거가 있어야 합니다.
- 수정 항목에는 실제 변경과 검증 결과가 있어야 합니다.
- 오탐 및 예외 항목에는 제출 가능한 간결한 의견이 있어야 합니다.
- 운영 설정 항목에는 필요한 설정, 담당 주체, 확인 방법이 있어야 합니다.
- 검증되지 않은 수정과 stale/unbound 결과는 검증 완료로 신뢰하지 않습니다.
- strict OK만으로 충분하지 않습니다. 실제 검증 근거·증적과 사용자 검토를 확인합니다.
