# Checklist Prompt (방법론 체크리스트)

```text
이번 점검이 방법론 기준(예: OWASP WSTG)의 어떤 항목을 다뤘는지 기록해 주세요. 체크리스트는
무엇을 점검했고 결과가 어땠는지를 남기는 장부입니다. 시험 방법은 표준 문서를 따르며, 이
단계에서 새 시험을 실행하거나 시험 절차를 만들지 않습니다.

1. 기준 파일을 준비합니다.
   checklists/<이름>.json에 항목 ID·제목·표준 링크·필요 침습도·대상 종류를 둡니다
   (examples/checklists/wstg-sample.json 형식). 항목에 시험 단계나 입력값을 적지 않습니다.

2. 사용자와 이번 점검에서 다룰 항목을 고릅니다.
   data/checklist.json의 items에 고른 항목 ID를 넣고 처음 상태는 not-checked로 둡니다.
   python3 tools/assess_toolkit.py checklist
   필요 침습도가 스코프 상한을 넘거나 맞는 대상이 없는 항목은 out-of-scope로 계산됩니다.
   그 항목을 다루려면 스코프를 바꾸고 다시 authorize해야 한다고 알립니다.

3. 스캔 근거를 확인합니다.
   checklist 출력의 suggestedBy는 그 항목에 매핑된 어댑터가 이번 차수에 돌았다는 뜻입니다.
   제안일 뿐이므로, 그 실행 결과와 검출을 사용자와 함께 보고 확정합니다.

4. 결과를 기록합니다. 확정은 사용자가 합니다.
   - checked: 점검했고 문제 없음. reason에 무엇을 근거로 봤는지
   - issue-found: 결함을 찾음. reason과 evidence(검출 키 fingerprint:키 또는 메모 경로)
   - not-applicable: 이 대상에 해당하지 않음. reason에 이유
   세 상태 모두 decidedBy는 user입니다. 사람이 직접 확인한 항목은 운영자가 남긴 메모나
   첨부 경로를 evidence에 적습니다.

5. 마무리합니다.
   python3 tools/assess_toolkit.py validate
   python3 tools/assess_toolkit.py evidence
   표지 보고서의 「방법론 체크리스트」 표와 evidence/checklist.csv가 만들어집니다.

마지막 보고:
- 기준과 버전, 고른 항목 수
- 상태별 항목 수(범위 밖 · 미점검 · 점검함 · 결함 발견 · 해당 없음)
- 범위 밖 항목과 그 이유
- 미점검으로 남은 항목
```
