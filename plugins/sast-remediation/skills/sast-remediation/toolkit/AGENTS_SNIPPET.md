# Optional Agent Instruction

아래 내용을 대상 프로젝트의 에이전트 지침에 추가하면 새 작업에서도 같은
SAST 처리 규칙을 적용할 수 있습니다. 기존 프로젝트 지침을 덮어쓰지 말고
보안 작업 섹션으로 추가합니다.

```markdown
## SAST Remediation

- `sast-remediation-toolkit/tools/sast_toolkit.py gate`가 READY를 반환하기
  전에는 초기 분석이나 소스 조치를 시작하지 않는다.
- SAST 작업을 시작하기 전에
  `sast-remediation-toolkit/SECURITY_SAST_WORKFLOW.md`를 읽는다.
- 공통 판단 기준은
  `sast-remediation-toolkit/SECURITY_POLICY_BASELINE.md`를 따른다.
- 코드로 확인할 수 없는 정책만
  `sast-remediation-toolkit/SECURITY_GRILL_GUIDE.md`에 따라 질문한다.
- 최신 PDF, 최신 스프레드시트, 현재 소스를 서로 대조한다.
- 보고서 라인 번호가 달라졌으면 현재 소스에서 실제 검출 구문을 다시 찾는다.
- 초기 분석 승인 전에는 운영 소스를 수정하지 않는다.
- 수정 후에는 프로젝트에서 발견한 빌드 및 테스트 명령으로 검증한다.
- 처리 결과와 진행상태 산출물을 함께 갱신한다. 상태의 기준은
  `security-results/`이며 `data/progress.json`은 이와 일치해야 한다.
- 이전 차수 산출물이 있으면
  `sast-remediation-toolkit/prompts/06-carry-over.md`에 따라 fingerprint
  기준으로 오탐·예외 결론을 이월한다.
```
