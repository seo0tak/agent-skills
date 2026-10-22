# Authorization Gate Prompt

```text
보안 점검을 시작하기 전에 인가 범위만 먼저 확정해 주세요. 이 단계에서는 어떤
스캐너도 실행하지 않습니다.

1. security-assessment-toolkit/data/scope.json에 이번 점검 범위를 적습니다
   (examples/scope.json 형식). 대상은 타입을 명시합니다:
   - repo: 저장소 경로 또는 git URL
   - web:  URL 또는 도메인
   - infra: 인프라 식별자
   제외 자산(exclusions), 기간(window: start/end), 소유자 동의 기록
   (consent: authorizer/role/date/reference), 침습도(intrusiveness:
   passive | active-nondestructive | intrusive)를 채웁니다.

2. 대상이 실제로 인가된 범위인지, 제외 자산과 충돌하지 않는지 사용자와
   확인합니다. 스킬은 동의가 진짜인지 검증할 수 없으므로, 이 확인은 사람이
   합니다. 근거를 요약해 보고합니다.

3. 다음을 차례로 실행합니다.
   python3 tools/assess_toolkit.py validate
   python3 tools/assess_toolkit.py authorize
   python3 tools/assess_toolkit.py gate

4. gate가 READY가 아니면 차단 사유만 보고하고 멈춥니다. 범위를 넓히는
   변경(대상 추가·기간 연장·제외 축소)을 했다면 다시 authorize가 필요합니다.
   notes 같은 설명 필드만 바꾼 경우는 승인이 유지됩니다.

마지막 보고:
- 게이트 결론: READY 또는 BLOCKED
- 대상 수와 타입, 침습도 수준
- 인가 기록: 인가자·역할·참조(티켓/문서)
- 차단 사유(있으면)
- 게이트가 막지 못하는 것: 스킬은 동의의 진위를 검증하지 않습니다.
```
