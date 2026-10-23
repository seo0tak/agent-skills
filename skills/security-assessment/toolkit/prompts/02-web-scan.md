# Web Scan Prompt (웹 스캔)

```text
인가된 웹 대상을 비파괴로 점검해 주세요. 기성 스캐너의 비파괴 설정만 쓰고, 공격 코드나
페이로드를 직접 만들거나 로그인이 필요한 표면을 스캔하지 않습니다.

1. 게이트와 판정을 확인합니다.
   python3 tools/assess_toolkit.py gate
   python3 tools/assess_toolkit.py adapters --direct
   READY가 아니면 차단 사유만 보고하고 멈춥니다. 웹 대상에 초당 요청 상한(rateLimit)이
   없으면 보수적 기본값이 쓰인다는 점과, 소유자가 동의한 상한이 있으면 scope.json에 적고
   다시 authorize해야 한다는 점을 알립니다.

2. 웹 어댑터마다 판정을 읽습니다.
   - run: 스킬이 직접 돌릴 수 있습니다. 3으로 갑니다.
   - operator: 요청 상한·범위 제어를 스캐너에 넘길 방법이 없거나 침습적입니다. scan이
     출력하는 운영자 명령과 들여오기 명령을 사용자에게 전합니다.
   - 거부: 대상 안의 제외 자산을 스캐너에 넘길 수 없습니다. 실행도 들여오기도 하지 않고,
     어댑터에 제외 방법을 선언하거나 제외 자산이 없는 대상으로 범위를 나누자고 제안합니다.

3. 직접 실행할 웹 스캔은 먼저 계획만 받습니다.
   python3 tools/assess_toolkit.py scan --direct
   출력된 계획(대상 URL, 초당 요청 상한, 최대 실행 시간, 제외 호스트·URL)과 확인 코드를
   그대로 사용자에게 보여 주고 이 실행을 진행할지 묻습니다. 확인은 이 계획 한 번에만
   유효합니다. 계획이 바뀌면 다시 묻습니다.

4. 사용자가 확인하면 같은 코드로 실행합니다.
   python3 tools/assess_toolkit.py scan --direct --confirm <확인 코드>
   코드가 현재 계획과 다르면 실행되지 않습니다. 실행 중 오류·시간 초과는 그대로 보고합니다.

5. 운영자가 돌린 출력은 들여옵니다. 방문 URL 목록이 있으면 함께 넘깁니다.
   python3 tools/assess_toolkit.py ingest --adapter <이름> --file <출력> --target <대상> --coverage <방문 URL 파일>

6. 수집이 끝나면 prompts/01-triage.md로 판정합니다. 웹 검출은 코드 결함이 아니라
   sast-remediation으로 넘기지 않고 증적에 남습니다.

마지막 보고:
- 대상별 실행 방식: 직접 실행 / 운영자 / 거부와 그 이유
- 실제 적용된 요청 상한·시간 상한·제외 자산
- 수집된 검출 수와 커버리지 방식(fixed-probes / url-list / 없음)
- 다음 차수에 해소를 판단할 수 없는 검출이 생길 수 있는 이유(커버리지 없음)
```
