# Input Readiness Gate Prompt

```text
현재 프로젝트의 SAST 작업 시작 가능 여부만 먼저 점검해 주세요.
이 단계에서는 검출 항목 분석이나 운영 소스 수정을 시작하지 않습니다.

입력 위치:
- 현재 프로젝트 소스 전체
- sast-remediation-toolkit/input/의 SAST PDF 1개
- sast-remediation-toolkit/input/의 SAST 스프레드시트 1개

수행 순서:
1. `sast-remediation-toolkit` 디렉터리에서
   `python3 tools/sast_toolkit.py preflight`를
   실행해 프로젝트 소스 존재 여부, 입력 개수, 파일 크기와 실제 파일
   형식을 검사합니다.
2. 기계적 점검이 BLOCKED이면 원인과 필요한 자료만 알려주고 멈춥니다.
3. 통과하면 현재 소스에서 프로젝트 식별 근거와 소스 범위를 찾습니다.
4. PDF와 스프레드시트에서 프로젝트명 또는 시스템 식별정보, 분석 번호,
   생성 시각, 전체 검출 건수와 검출 대상 경로를 확인하고, 체커 가이드와
   검출 목록의 필수 필드를 실제로 읽을 수 있는지 확인합니다.
5. 다음 네 조건을 각각 근거와 함께 판정합니다.
   - 현재 소스, PDF, 스프레드시트가 같은 프로젝트인지
   - PDF와 스프레드시트가 같은 검사 차수인지
   - 전체 검출 건수가 일치하거나 차이를 설명할 수 있는지
   - 보고된 소스 범위가 현재 프로젝트에 존재하는지
6. 결과를 project/INPUT_VALIDATION.md와
   data/input-validation.json에 기록하고 데이터 미러를 동기화합니다.
7. 모든 조건이 확인된 경우에만 네 matching 값을 모두 true로 기록하고,
   REPORT_CONTENT_READABLE과 SEMANTIC_MATCH 검사를 pass로 바꾸며 status를
   ready로 설정한 뒤
   같은 디렉터리에서 `python3 tools/sast_toolkit.py gate`를 실행합니다.
8. 하나라도 불일치하거나 확인 근거가 부족하면 status를 blocked로 두고
   이후 초기 분석과 소스 조치를 시작하지 않습니다.
9. 최종 게이트가 READY이면 별도 확인을 기다리지 말고
   prompts/01-initialize.md를 읽어 프로젝트 초기 분석과 산출물 생성을
   계속합니다. 이때도 운영 소스는 수정하지 않습니다.

마지막 보고:
- 게이트 결론: READY 또는 BLOCKED
- 확인한 프로젝트
- PDF와 스프레드시트 파일명
- 프로젝트 일치 근거
- 검사 차수 일치 근거
- 검출 건수 대조 결과
- 소스 범위 대조 결과
- 차단 사유 또는 초기 분석 결과와 다음 단계
```
