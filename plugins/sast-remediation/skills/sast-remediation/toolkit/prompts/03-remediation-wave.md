# SAST 조치 실행 요청문

초기 분석 확인과 조치 범위 승인을 받은 뒤 사용합니다. 아래 요청문은
현재 작업 그룹만 처리합니다. 연속 실행은 사용자가 지정한 범위에 한합니다.

```text
초기 분석과 확정된 프로젝트 정책에 따라 다음 SAST 작업 그룹을 처리해 주세요.

시작 조건과 실행 범위
- 툴킷 디렉터리에서 python3 tools/sast_toolkit.py gate를 실행합니다.
  READY가 아니면 차단 사유를 보고하고 운영 소스를 수정하지 않습니다.
- python3 tools/sast_state.py status로 미완료 체크포인트와 검증 이후
  소스·근거의 변경 여부(검증 신선도)를 확인합니다. 손상이나 중간 수정이
  있으면 prompts/07 절차부터 수행합니다.
- 기존 승인 범위가 현재 작업에도 유효한지 확인합니다. 사용자 요청이나
  확인 가능한 승인 근거를 사용하며, 파일의 상태 이름만으로 권한을 추정하지 않습니다.
- "연속으로", "N개 그룹", "끝까지" 요청이면 그 범위 내에서 그룹 사이에
  재승인을 묻지 않습니다. 범위 밖 변경, 정책 결정, 공통 컴포넌트·외부 규격
  영향, 해결되지 않는 검증 오류, 안전한 저장 불가, 사용자 중단 요청에서는
  멈춥니다. 정책 질문은 해당 항목을 보류하고 독립적인 항목을 계속할 수 있습니다.
  보류된 질문이 5개 모이거나 범위를 완료하면 중복 질문을 합쳐 하나씩 제시합니다.

담당 분리
- 작업을 총괄하는 AI를 이하 "총괄 AI"라고 합니다.
- 병렬 그룹은 소스·공통 유틸리티·호출 관계·테스트가 겹치지 않아야 합니다.
- 공용 data/와 sync/validate는 지정된 한 작성자가 담당합니다. 도구의 잠금은
  도구를 사용하는 작성자끼리만 유효합니다. 에디터나 외부 프로세스까지 잠그지 않습니다.
- 등록된 sast-bulk-worker는 기계적 집계·대표 가이드를 참조하고 항목별 차이만
  적은 가이드·증적 행을,
  sast-remediator는 승인된 가이드 범위의 수정을 맡을 수 있습니다.
  결론·정책·verified 승격은 총괄 AI가 확인합니다. 해당 에이전트가 없으면
  총괄 AI가 같은 절차를 직접 수행하며, 실행 성능이나 비용이 같다고 가정하지 않습니다.

진행 순서
1. python3 tools/sast_toolkit.py query --group <WG>로 현재 그룹을 조회합니다.
   todo만 조회하면 in-progress·보류·재검토 항목을 놓칩니다. status의
   resumeCandidates와 함께 보고, 높은 위험도와 미완료 항목을 우선합니다.
   필요하면 --fields id,risk.level,checker.code,location,progress로 범위를 줄입니다.
2. 현재 소스와 선택 보고서의 검출 코드를 대조합니다. 항목별
   security-guides/<ID>.json에 분석·영향 범위·검증 계획을 먼저 작성합니다.
   같은 원인의 다른 항목은 groupGuideRef, summary, delta를 쓸 수 있지만,
   실제 차이가 큰 항목에는 전체 가이드를 작성합니다.
3. 수정 직전에 체크포인트를 저장합니다.
   python3 tools/sast_state.py checkpoint --id <ID> --phase before-edit
     --path <프로젝트 루트 기준 파일> --note "<현재 판단>"
     --next-action "<다음 작업>"
   명령은 한 줄로 실행하고, 관련 파일이 여럿이면 --path를 반복합니다.
   체크포인트 저장 실패 시 소스 수정을 시작하지 않습니다.
4. 승인된 범위에서 기존 동작을 보존하는 최소 수정을 합니다.
   중요한 미확인 정책은 needs-review와 policyQuestions에 남깁니다.
   사용자가 관찰 방법이 적힌 기본안을 선택했고 해당 변경이 승인 범위에
   있을 때만 baseline-default로 기록해 관찰 수단을 추가합니다.
   답변이나 변경 권한이 없으면 deferred로 두고 재개 조건만 기록합니다.
   비밀값을 로그에 남기지 않고 로그 양·성능·운영 영향도 확인합니다.
5. 수정 후 checkpoint --phase after-edit로 현재 판단과 다음 작업을 저장합니다.
   검증 직전에 대상 소스와 관련 설정·테스트 파일을 스냅샷으로 기록합니다.
   python3 tools/sast_state.py snapshot --id <ID> --path <관련 파일>
   관련 파일은 --path로 모두 지정합니다. 지정하지 않은 외부 서비스·DB·운영
   설정까지 해시가 보장하지 않으므로 적용 범위와 한계를 따로 기록합니다.
6. 위험과 영향 범위에 맞는 검증을 실제로 실행합니다.
   profile의 validation.verificationMeans에 선언된 수단을 사용하고,
   verification.method, commands, results, limitations와 실제 verifiedAt을
   결과에 남깁니다. 필요하고 사용 가능한 경우 변경 파일의 SAST 재검사도 합니다.
   도구 부재·실패·부분 검증을 passed로 바꾸지 않습니다.
7. security-results/<ID>.json을 작성합니다. 검증 통과 근거가 있는 항목만
   verified 후보로 두고 다음 명령으로 검증 근거와 소스를 연결합니다.
   python3 tools/sast_state.py seal-verification --id <ID>
   이 명령은 테스트를 실행하거나 상태를 승격하지 않습니다. 스냅샷 이후
   작성한 통과 근거, 시각, 소스 내용이 맞아야 연결됩니다. 실패하면 원인을
   확인해 스냅샷부터 검증을 다시 수행하며, 과거 passed 문구를 재사용하지 않습니다.
8. 지정된 작성자가 최신 data/progress.json을 다시 읽어 결과와 일치시킵니다.
   다른 항목의 상태·비고와 아직 결과가 없는 임시 진행상태를 보존합니다.
   python3 tools/sast_toolkit.py sync
   python3 tools/sast_toolkit.py validate
   python3 tools/sast_state.py status
   오류·stale·unbound가 남은 항목은 완료로 보고하지 않습니다.

운영 설정 조치는 소스 변경과 별도 그룹으로 관리합니다.
항목별 응답 라벨은 SECURITY_SAST_WORKFLOW.md의 형식을 그대로 사용합니다.

보고
- 이번에 완료한 범위와 아직 검증되지 않은 항목
- 실제 변경 파일, 결론, 실행한 검증과 확인 범위
- 저장한 체크포인트·결과, 중복으로 해소된 ID
- 남은 위험·정책 질문과 다음 작업
```
