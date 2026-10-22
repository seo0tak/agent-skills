# Triage Prompt (판정)

```text
수집된 검출을 판정해 주세요. 판정은 소스와 근거로 하고, 공격 코드나 페이로드를
만들거나 대상에 새 요청을 보내지 않습니다.

1. 현황을 봅니다.
   python3 tools/assess_toolkit.py validate
   python3 tools/assess_toolkit.py dispositions
   validate에 에러가 있으면 판정을 시작하지 않고 에러만 보고합니다.

2. 판정 레코드가 없거나 unreviewed인 검출마다 data/findings.json의 위치를 엽니다.
   - 코드 위치: 그 파일·함수를 읽고 입력이 어디서 오는지, 검증·인코딩·바인딩이
     있는지 확인합니다.
   - URL 위치(웹 점검): 스캐너가 남긴 요청·응답 근거만 봅니다. 재현을 위해 새
     요청을 보내지 않습니다.
   - 여러 스캐너가 같은 검출을 냈으면(sources) 각 근거를 함께 봅니다.

3. data/dispositions.json에 'fingerprint:cwe' 키로 기록합니다.
   - disposition: confirmed | suspected | false-positive | out-of-scope | needs-review
   - stage: in-review(검토 중) | reviewed(확정)
   - reason: 확인한 위치(file:line)와 판단 근거. confirmed·false-positive·
     out-of-scope는 필수
   - decidedBy: ai(AI가 근거로 판정) | user(사용자가 확인)
   - updatedAt: 기록 시각

4. 누가 무엇을 확정하는지:
   - confirmed·suspected·needs-review는 AI가 근거와 함께 reviewed로 기록할 수
     있습니다(decidedBy: ai).
   - false-positive·out-of-scope는 위험을 닫는 판정이라 AI는 in-review로 제안만
     합니다(decidedBy: ai). 사용자가 확인하면 reviewed, decidedBy: user로 바꿉니다.
     validate는 ai가 이 두 판정을 reviewed로 확정한 레코드를 에러로 봅니다.
   - 근거가 부족하면 needs-review로 두고 무엇을 확인해야 하는지 reason에 적습니다.

5. 사용자에게 한 번에 묻습니다. 제안한 오탐·범위 밖과 needs-review 항목을
   위치·근거·제안과 함께 표로 보여 주고, 답을 받은 항목만 갱신합니다.

6. 기록을 마치면 차례로 실행합니다.
   python3 tools/assess_toolkit.py validate
   python3 tools/assess_toolkit.py bridge --dry-run
   bridge로 넘길 confirmed 코드 결함 건수를 보고하고, 사용자가 원하면 bridge와
   evidence를 실행합니다.

마지막 보고:
- 판정별·확인 단계별 건수(dispositions 출력)
- 확정한 주체별 건수: user / ai / 미기록
- 사용자 확인을 기다리는 제안(오탐·범위 밖)과 needs-review 목록
- sast-remediation으로 넘길 confirmed 코드 결함 수
```
