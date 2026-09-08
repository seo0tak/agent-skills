# Initial Project Analysis Prompt

```text
현재 프로젝트에서 SAST 취약점 조치 작업을 초기화해 주세요.

입력:
- 현재 프로젝트 소스 전체
- sast-remediation-toolkit/input/의 최신 SAST PDF 1개
- sast-remediation-toolkit/input/의 최신 SAST 스프레드시트 1개

먼저 다음 문서를 읽고 따르세요.
- sast-remediation-toolkit/SECURITY_SAST_WORKFLOW.md
- sast-remediation-toolkit/SECURITY_POLICY_BASELINE.md
- sast-remediation-toolkit/SECURITY_GRILL_GUIDE.md
- sast-remediation-toolkit/SECURITY_TEST_GUIDE.md

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
1. 확정된 입력 검증 결과를 읽고 프로젝트 및 보고서 식별정보를 유지합니다.
2. 프로젝트의 모듈, 소스 루트, 계층, 공통 컴포넌트, 외부 연동,
   설정 경계, 빌드 및 테스트 방법을 분석합니다.
3. 스프레드시트의 전체 검출 항목을 표준 finding 형식으로 변환합니다.
4. PDF의 체커 설명과 해결 가이드를 체커별로 추출합니다.
5. 모든 검출 파일, 함수, 라인과 검출 코드를 현재 소스에 대조합니다.
6. 동일 원인과 충돌 파일을 기준으로 작업 그룹을 만듭니다.
7. 초기 결론 후보를 수정, 오탐, 운영 설정, 예외처리, 추가 검토로 분류합니다.
8. 코드만으로 결정할 수 없는 정책 질문을 식별합니다.
9. 범용 HTML은 변경하지 않고 프로젝트별 data 파일만 생성합니다.

생성 또는 갱신할 파일:
- project/INPUT_VALIDATION.md
- project/PROJECT_ANALYSIS.md
- project/PROJECT_SECURITY_POLICY.md
- project/DECISION_LOG.md
- project/WORK_GROUPS.md
- data/input-validation.json 및 .js
- data/project-profile.json 및 .js
- data/findings.json 및 .js
- data/checker-guides.json 및 .js
- data/progress.json 및 .js

tools/sast_toolkit.py validate를 실행해 결과 형식을 검증합니다.

마지막 보고:
- 입력 자료 일치 여부
- 프로젝트 기술 구성
- 전체 및 위험도별 검출 건수
- 현재 소스와 정확히 일치/이동/변경/미발견 건수
- 초기 결론 후보별 건수
- 설정 및 외부 규격 관련 분리 건수
- 추천 작업 그룹
- 사용자 확인이 필요한 첫 번째 정책 질문 하나
- 생성한 산출물 경로
```
