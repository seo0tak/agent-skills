# Cross-Round Carry-Over Prompt

새 검사 차수를 시작할 때, 이전 차수 산출물이 있으면 01 초기화 직후에
이 프롬프트를 사용합니다. 이전 차수 산출물이 없으면 건너뜁니다.

```text
이전 검사 차수의 처리 결과를 새 차수 검출 목록에 이월해 주세요.

입력:
- 이전 차수의 data/findings.json, data/progress.json, security-results/*.json
  (이전 차수 툴킷 디렉터리 전체 또는 백업 경로를 알려주세요)
- 새 차수의 data/findings.json (01 초기화로 이미 생성됨)

매칭된 항목은 이전 차수의 stableKey를 그대로 유지합니다(지문이
같으므로 자연히 동일). 보고와 증적에서 차수 간 동일 항목은 stableKey로
지칭합니다.

매칭 규칙(순서대로 적용, 상위 규칙 매칭 시 종료):
1. sourceMapping.fingerprint가 동일
2. 체커 코드 + 현재 파일 + 현재 함수가 동일
3. 체커 코드 + 현재 파일 + 검출 코드 패턴이 동일

이월 규칙:
1. 이전 결론이 false-positive 또는 exception이고, 매칭된 위치의 현재
   소스 코드가 이전 차수와 실질적으로 동일하면: 이전 결론과 근거를
   승계하고 workflowStatus를 verified로 유지합니다. 승계 사실과 이전
   검출 ID를 결과의 reason과 evidenceNote에 명시합니다.
2. 매칭됐지만 해당 코드가 변경된 경우: 결론을 needs-review로 강등하고
   이전 결론을 참고로 기록합니다. 자동 승계하지 않습니다.
3. 이전 결론이 fix(수정 완료)였는데 같은 지문으로 재검출된 경우: 수정이
   반영되지 않았거나 회귀일 수 있으므로 needs-review로 두고 이전 변경
   내역을 함께 기록합니다.
4. 이전 결론이 operations인 항목: 운영 조치 완료 여부를 확인할 수
   없으므로 결론만 승계하고 workflowStatus는 analyzed로 둡니다.
5. 매칭되지 않은 새 검출: 이월하지 않고 신규 항목으로 둡니다.
6. 이전 차수에만 있고 새 차수에 없는 항목: 해소된 것으로 보고 목록에만
   기록하며 새 데이터에 추가하지 않습니다.

작업:
1. 위 규칙으로 매칭과 이월을 수행합니다.
2. 이월된 항목의 security-results/<ID>.json과 data/progress.json을
   생성·갱신합니다.
3. tools/sast_toolkit.py sync와 validate를 실행합니다.

마지막 보고:
- 새 차수 전체 건수와 매칭 성공 건수(규칙별)
- 결론 승계 / needs-review 강등 / 재검출(회귀 의심) / 신규 건수
- 이전 차수에서 해소된 검출 ID 목록
- 코드 변경으로 재검토가 필요한 항목 목록
```
