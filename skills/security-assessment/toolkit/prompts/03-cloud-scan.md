# Cloud Config Scan Prompt (클라우드 설정 점검)

```text
인가된 클라우드 계정의 설정을 읽기 전용으로 점검해 주세요. 리소스를 만들거나 바꾸지 않고,
자격증명의 비밀값(키·토큰·비밀번호)을 묻거나 파일에 적지 않습니다.

1. 스코프의 infra 대상을 확인합니다.
   - value: aws:<계정>처럼 제공자와 계정
   - regions: 점검할 리전 목록
   - credential.profile: 이 환경에서 쓸 프로파일·역할 이름(비밀값이 아님)
   - credential.readOnlyConfirmed: 사용자가 그 역할이 읽기 전용이라고 확인했으면 true
   사용자가 확인하지 않았으면 true로 적지 말고 먼저 묻습니다. 스킬은 권한이 정말 읽기
   전용인지 검증하지 못한다는 점을 알립니다. 바꿨으면 다시 authorize합니다.

2. 제외를 확인합니다.
   - 계정 전체: aws:<계정>, 리전: aws:<계정>:<리전> → 스캐너에 넘기는 리전 목록에서 빠집니다.
   - 개별 리소스: arn:... 같은 리소스 ID 접두사 → 결과와 기준 건수에서 빠집니다.

3. 판정을 보고 실행합니다.
   python3 tools/assess_toolkit.py gate
   python3 tools/assess_toolkit.py adapters --direct
   - run: python3 tools/assess_toolkit.py scan --direct
   - operator: 프로파일을 넘길 방법이 없는 어댑터입니다. scan이 출력하는 운영자 명령을 전하고,
     넘겨받은 출력은 ingest로 들여옵니다.
   - 거부: 리전을 스캐너에 넘길 방법이 없습니다. 어댑터에 리전 인자를 선언해야 합니다.

4. 결과를 확인합니다. 출력에 대상이 아닌 계정이나 허용하지 않은 리전의 결과가 있으면 scan은
   그 결과를 버리고, ingest는 들여오지 않습니다. 그 경우 스캐너 설정을 고쳐 다시 돌립니다.

5. prompts/01-triage.md로 판정합니다. 클라우드 설정 결함은 고칠 파일이 없어
   sast-remediation으로 넘기지 않고 증적에 남습니다. 저장소 IaC 결함(Checkov 등)은 파일이
   있어 confirmed면 넘깁니다.

마지막 보고:
- 계정과 실제로 점검한 리전, 쓴 프로파일 이름(비밀값 없음)
- 기준별 통과·실패·수동 건수(evidence 후 표지 보고서의 「기준 대조」)
- 제외된 리전·리소스와 그 때문에 빠진 결과
- 버리거나 거부한 결과가 있으면 그 이유
```
