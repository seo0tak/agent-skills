# Dashboard Reconciliation Prompt

기계적 정합성(ID 유효성, 진행상태-결과 일치, 미러 드리프트)은
`tools/sast_toolkit.py validate`가 잡습니다. 이 단계는 **사람이
대시보드에서 바꾼 변경분을 파일 기록에 흡수하고, 근거의 품질을
보강**하는 데 집중합니다.

```text
대시보드 변경분을 흡수하고 결과 근거를 보강해 주세요.

1. 사용자가 [상태 백업]으로 내려받은 progress JSON이 있으면 전달받아
   반영합니다. 항목별 updatedAt이 더 최신인 쪽을 유지하고, 사람이
   내린 결론 변경은 security-results/<ID>.json에도 근거와 함께
   기록합니다(상태의 기준은 results).
2. 사람이 verified를 낮췄거나 결론을 바꾼 항목은 왜 바뀌었는지
   사용자에게 한 번 확인하고 reason에 남깁니다.
3. 오탐, 운영 설정, 예외처리 항목의 근거가 제출 가능한 수준인지
   검토합니다: 근거 코드 지점 명시, 결정 로그 참조, 2문장 이상.
   부족한 항목은 보강합니다.
4. 하나의 수정으로 함께 해소된 중복 ID들의 상태·근거를 동기화합니다.
5. tools/sast_toolkit.py sync와 validate를 실행하고, validate가
   보고한 불일치가 있으면 정리합니다.

보고: 흡수한 변경 건수, 근거를 보강한 항목, validate 결과.
```
