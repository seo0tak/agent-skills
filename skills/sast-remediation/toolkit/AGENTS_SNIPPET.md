# 프로젝트 에이전트 지침 예시

아래 내용을 대상 프로젝트의 에이전트 지침에 추가하면 새 작업에서도 같은
SAST 처리 규칙을 적용할 수 있습니다. 기존 프로젝트 지침을 덮어쓰지 말고
보안 작업 섹션으로 추가합니다.

```markdown
## SAST 조치

- `sast-remediation-toolkit/tools/sast_toolkit.py gate`가 READY를 반환하기
  전에는 초기 분석이나 소스 조치를 시작하지 않는다.
- SAST 작업을 시작하기 전에
  `sast-remediation-toolkit/SECURITY_SAST_WORKFLOW.md`를 읽는다.
- 공통 판단 기준은
  `sast-remediation-toolkit/SECURITY_POLICY_BASELINE.md`를 따른다.
- 코드로 확인할 수 없는 정책만
  `sast-remediation-toolkit/SECURITY_GRILL_GUIDE.md`에 따라 질문한다.
- 선택 보고서(PDF 1개 이상+스프레드시트 1개 또는 SARIF 1개)와 현재 소스를 대조한다.
- 보고서 라인 번호가 달라졌으면 현재 소스에서 실제 검출 구문을 다시 찾는다.
- 초기 분석 승인 전에는 운영 소스를 수정하지 않는다.
- 수정 전·후 `tools/sast_state.py checkpoint`로 메모·대상·다음 작업을 저장한다.
- 검증 직전에 snapshot을 만들고 실제 빌드·테스트를 실행한 뒤 결과를
  seal-verification으로 연결한다. 도구가 테스트·권한을 대신 만들지 않는다.
- 중단 시 07 재개 절차로 원본·체크포인트·현재 소스부터 검사한다.
  복구는 미리보기 후 --apply로 반영하며 자동 재시작하지 않는다.
- 결과 정본은 `security-results/`다. progress는 결과와 일치해야 하며
  결과가 없는 임시 상태·비고도 보존한다. 공용 정본은 한 작성자가 갱신한다.
- sync·validate·sast_state.py status를 확인한다. stale/unbound를 검증 완료로
  신뢰하지 않고 자동 검사 성공과 실제 검증·사용자 승인을 구분한다.
- 이전 차수 산출물이 있으면
  `sast-remediation-toolkit/prompts/06-carry-over.md`에 따라 fingerprint
  기준으로 재사용 후보를 찾고 과거 근거·현재 적용 조건을 대조한다.
  새 차수의 verified는 현재 소스에서 재검증한다.
```
