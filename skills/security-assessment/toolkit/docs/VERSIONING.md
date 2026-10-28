# 버전·호환 정책

sast-remediation과 같은 원칙을 따른다.

- 패치(0.x.y): 버그 수정·문서. 산출물 형식 무변경.
- 마이너(0.x.0): 하위호환 추가(선택 필드·새 어댑터·새 프롬프트).
- 메이저(x.0.0): 스키마 breaking. schemaVersion 상향 동반.

스코프 스키마의 schemaVersion은 현재 `1.0`. 올릴 때는
`schemas/scope.schema.json`의 const와 `tools/assess_toolkit.py`의
`SCHEMA_VERSION`을 함께 바꾼다.

## 프로젝트 복사본 업그레이드

프로젝트의 `security-assessment-toolkit/`을 새 버전으로 올릴 때는 고정 자산만 교체한다:
`tools/`, `schemas/`, `prompts/`, `docs/`, `examples/`, `README.md`. 진행 중인 데이터는
보존한다: `data/`(범위·검출·판정·어댑터별 결과·보관 차수·체크리스트 기록), `adapters/`(프로젝트가 선언한
어댑터), `checklists/`(프로젝트가 둔 기준 파일), `evidence/`. 교체한 뒤 `validate`를 실행한다.

0.8.0으로 올릴 때 기존 `data/findings.json`은 첫 `scan`에서 `data/scans/_legacy.json`으로
한 번 옮겨져 보존된다. 이 보존 결과는 어떤 어댑터가 찾았는지 기록이 없어, 다음 차수에서
사라져도 해소가 아니라 재확인 안 됨으로 분류된다.

0.9.0으로 올릴 때 증적 워크북에 `decidedBy` 열이 추가된다. 이미 만든 `evidence/`가 있으면
validate가 드리프트를 에러로 보므로 `evidence`를 다시 실행한다. 주체가 없는 reviewed 판정은
경고로 남고, 기존에 false-positive·out-of-scope로 확정한 레코드에는 사용자 확인을 거쳐
`decidedBy: user`를 채운다.

0.10.0으로 올릴 때 스코프·어댑터·검출 파일은 그대로 읽힌다. 웹 대상에 `rateLimit`을 새로 적으면
인가 지문이 바뀌므로 다시 `authorize`한다(적지 않은 스코프의 기존 승인은 유지). 웹 어댑터를 쓰려면
`scope_control`·`rate_limit`·`coverage`를 선언한다(`examples/adapters/nuclei.json`). 이 선언이 없는
기존 dast 어댑터는 직접 실행되지 않고, 대상 안에 넘길 수 없는 제외 자산이 있으면 들여오기도 거부된다.
이전 차수에 쌓인 웹 검출은 지문 방식이 달라 새 차수에서 같은 결함이 새 지문으로 잡히고, 옛 검출은
커버리지가 없어 재확인 안 됨으로 남는다.

0.11.0으로 올릴 때 기존 스코프·검출·판정은 그대로 읽힌다. 소스·웹 검출의 묶음 키는 바뀌지 않는다.
`iac` 어댑터의 CWE 없는 검출은 키가 `지문:`에서 `지문:check:<점검 ID>`로 바뀌므로, 그런 검출에 남긴
판정은 다음 스캔 뒤 새 키로 다시 기록해야 한다(옛 키는 보관 차수를 가리키는 기록으로 남는다). 클라우드
계정을 점검하려면 infra 대상에 `regions`와 `credential`(프로파일 이름, `readOnlyConfirmed: true`)을
적고 다시 authorize한다.

0.12.0으로 올릴 때 기존 데이터는 그대로 읽힌다. 체크리스트를 쓰려면 기준 파일을 `checklists/`에,
고른 항목을 `data/checklist.json`에 둔다. 둘 다 프로젝트가 만든 데이터라 업그레이드 때 보존한다.
`data/checklist.json`이 생긴 뒤 `evidence`를 다시 실행하면 표지에 체크리스트 표가 더해진다.

0.12.1로 올릴 때 데이터 형식은 그대로다. 다음 `scan`·`ingest`부터 저장하는 URL의 쿼리 값과 메시지의
비밀값 모양 값이 가려진다. 이미 저장된 결과는 다시 스캔하거나 들여올 때 바뀐다. 수식 문자로 시작하는
CSV 셀이 있었다면 증적이 달라지므로 `evidence`를 다시 실행한다. 종료를 `T00:00:00Z`처럼 시각까지 적은
스코프는 이제 그 시각에 끝나므로, 그날 하루를 쓰려면 날짜만 적고 다시 authorize한다.

## 마일스톤

- M0: 인가 게이트 + validate + 테스트.
- M1a: 어댑터 선언 스키마 + 침습도 세 겹 실행 판정 + 검증.
- M1b: 'run' 어댑터 실제 실행 + SARIF 수집 + 지문/CWE 묶음 + findings 검증.
- M1c: 카테고리→대상 타입 매핑, JSON→SARIF 정규화기(OSV).
- M2a: 판정·확인 단계 레코드 + 검증.
- M2b: SARIF 다리 — confirmed 코드 결함을 sast-remediation으로.
- M2c: 증적 워크북(CSV)+표지 보고서(MD) 생성, 데이터와의 드리프트 검사.
- 0.8.0: 어댑터별 결과 저장(scan이 다른 결과를 지우지 않음), 제외 자산 적용,
  점검 차수(`new-round`)와 해소 판단, 첫 행동·경로 정리. skill-architect 점검의 결함 1~4.
- 0.9.0: 판정 절차 프롬프트(`01-triage.md`), 판정 주체(`decidedBy`, 오탐·범위 밖
  확정은 사용자만), 운영자 출력 들여오기(`ingest`), 출처의 대상·수집 주체 기록.
  skill-architect 점검의 개선 5.
- 0.10.0 M3: 웹(DAST, 비인증·비파괴). 어댑터 범위 제어·요청 상한·커버리지·시간 상한 선언,
  스코프 웹 대상 `rateLimit`, 웹 실행 계획과 확인 코드(`scan --confirm`), URL 지문 정규화, 커버리지
  기반 웹 해소, `ingest --coverage`, ZAP JSON 정규화기, 컨테이너 출력 자리표시(`{output_dir}`·
  `{output_name}`), 웹 스캔 프롬프트(`02-web-scan.md`). 설계 결정은 ADR 0003.
- 0.11.0 M4: IaC와 클라우드 설정(읽기 전용). infra 대상(`aws:<계정>`, 리전, 자격증명 참조),
  `cloud` 카테고리와 `cloud_args`(프로파일·리전·리소스 제외), 출력의 계정·리전 범위 검사, Prowler 정규화기,
  `output_file`, 통제 항목·점검 ID 묶음, 기준별 통과·실패·수동 건수와 표지 「기준 대조」, 클라우드 커버리지
  해소, 클라우드 설정 결함은 넘기지 않음, 프롬프트 `03-cloud-scan.md`, 예시 어댑터 checkov·prowler.
  설계 결정은 ADR 0004. 네트워크·호스트 스캔과 인증이 필요한 웹 스캔은 별도 설계가 필요하다.
- 0.12.0 M5: 방법론 체크리스트(점검 기록 장부). 기준 파일(항목 ID·제목·링크·필요 침습도·대상
  종류, 시험 단계 필드 거부), `data/checklist.json` 상태·근거, 범위 밖 계산, 어댑터 `checklist_items`
  매핑으로 스캔 제안, 사용자 확정(decidedBy user), `checklist` 명령, 표지 표와 `evidence/checklist.csv`,
  프롬프트 `04-checklist.md`. 설계 결정은 ADR 0005.
- 0.12.1 (현재): 저장소 전체 리뷰 반영. 저장하는 URL·메시지의 비밀값 정제, 여러 대상 중 일부만 성공할 때
  다른 대상 결과 보존, 코드 검출의 대상별 해소 판정, 출력 뼈대 검사로 오류 JSON 거부, 시각을 쓴 종료의
  연장 제거와 실행마다 기간 재확인, `new-round`의 체크리스트 보관·재개, CSV 수식 문자 무력화.
