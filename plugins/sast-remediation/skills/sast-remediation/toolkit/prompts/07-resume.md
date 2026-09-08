# Resume Prompt

새 세션에서 진행 중인 차수를 이어서 작업할 때 사용합니다.

```text
진행 중인 SAST 조치 작업을 이어서 진행해 주세요.

재개 절차 (이 순서로 현재 상태를 파악합니다):
1. `sast-remediation-toolkit` 디렉터리에서
   `python3 tools/sast_toolkit.py gate`를 실행합니다. READY가 아니면
   멈추고 차단 사유를 보고합니다(입력이 바뀌었을 수 있습니다).
2. `python3 tools/sast_toolkit.py query --summary`로 전체 진행 현황을
   파악합니다(상태별·결론별·위험도별·그룹별 건수). progress.json을
   직접 읽지 않습니다.
3. project/WORK_GROUPS.md에서 그룹별 완료 여부를 확인하고,
   security-results/index.json과 대조해 미완료 그룹을 찾습니다.
4. data/decisions.json과 project/PROJECT_SECURITY_POLICY.md를 읽어
   이미 확정된 정책을 파악합니다. 확정된 정책은 다시 묻지 않습니다.
   decidedBy=baseline-default인 결정은 reviewTrigger가 충족됐는지
   (관찰 로그가 찍혔는지) 확인할 수 있으면 확인하고 결정을 갱신합니다.
5. 직전 세션이 남긴 미해결 정책 질문(decidedBy=deferred, 또는 가이드의
   policyQuestions)이 있으면 그것부터 사용자에게 확인합니다.
6. `python3 tools/sast_toolkit.py validate`를 실행해 직전 세션의
   불일치(진행상태-결과 어긋남, fingerprint 누락 등)가 있으면 먼저
   정리합니다.
6-1. validate나 sync가 깨진 파일(중단으로 반쪽 저장)을 지목하면
   다음 규칙으로 복구합니다. 처음부터 다시 하지 않습니다.
   - security-results/<ID>.json → 그 항목만 재검토·재작성
   - security-guides/<ID>.json → 그 항목 가이드만 재작성
   - data/progress.json → security-results 전체에서 재생성
     (results가 상태의 기준이므로 손실 없음)
   - .js 미러 / index → sync가 자동 재생성
   복구 후 sync와 validate를 다시 실행합니다.

파악이 끝나면 다음을 보고하고 확인 후 진행합니다:
- 전체 대비 완료율 (상태별 건수)
- 남은 작업 그룹과 규모
- 미해결 정책 질문 (있으면)
- 이번 세션에서 진행할 다음 작업 그룹 제안

이후 조치는 prompts/03-remediation-wave.md 규칙을 그대로 따릅니다.
큰 findings.json은 전체를 다시 읽지 말고
`python3 tools/sast_toolkit.py query --group <WG> --status todo`로
이번에 다룰 작업 그룹의 항목만 받아 사용합니다.
```
