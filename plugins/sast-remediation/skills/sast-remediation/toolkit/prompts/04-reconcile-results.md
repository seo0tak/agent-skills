# Dashboard Reconciliation Prompt

```text
현재 소스와 sast-remediation-toolkit 산출물의 상태를 대조해 주세요.

1. data/findings.json의 모든 ID가 progress와 결과 파일에서 유효한지 확인합니다.
2. security-results의 수정 파일과 현재 소스가 일치하는지 확인합니다.
3. 검증 결과가 없는 수정 항목은 verified로 두지 않습니다.
4. 오탐, 운영 설정, 예외처리 항목의 근거가 비어 있지 않은지 확인합니다.
5. 하나의 수정으로 처리된 중복 ID의 상태를 함께 갱신합니다.
6. 기존 verified 상태를 근거 없이 낮추지 않습니다.
7. data/progress.json과 JavaScript 미러 및 결과 인덱스를 갱신합니다.
8. tools/sast_toolkit.py validate를 실행합니다.

변경된 상태 수와 불일치가 남은 ID를 보고해 주세요.
```
