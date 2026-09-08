# Final Evidence Prompt

```text
현재 SAST 처리 결과를 제출 가능한 증적으로 정리해 주세요.

입력 기준:
- data/findings.json
- data/progress.json
- security-results/*.json
- project/PROJECT_SECURITY_POLICY.md
- project/DECISION_LOG.md

생성할 결과 (파일명은 data/project-profile.json의 evidence.outputs 설정을
우선 사용하고, 설정이 없으면 아래 기본값을 사용합니다):
1. evidence/SAST_전체조치결과.xlsx  (evidence.outputs.allResults)
2. evidence/SAST_오탐예외의견.xlsx  (evidence.outputs.falsePositiveOpinions)
3. evidence/SAST_운영설정필요.xlsx  (evidence.outputs.operationsRequired)
4. evidence/SAST_미검증추가검토.xlsx  (evidence.outputs.unverifiedReview)

전체 조치 결과 열:
- 검출 ID
- 위험도
- 체커 코드
- 체커명
- 파일
- 함수
- 보고 라인
- 현재 소스 위치
- 조치 결론
- 조치 내용
- 검증 결과
- 비고

오탐 및 예외 의견은 위험도 순서 후 ID 순서로 정렬합니다. 같은 파일, 함수,
체커와 동일 근거인 항목은 의견을 일괄 적용할 수 있도록 그룹을 표시합니다.
의견은 제출용으로 간결하게 작성하되 실제 타입, 호출 흐름, 외부 규격 등
검증 가능한 근거를 포함합니다.

마지막으로 전체, 위험도별, 결론별, 검증상태별 건수를 보고하고 데이터 간
불일치가 없는지 확인해 주세요.
```
