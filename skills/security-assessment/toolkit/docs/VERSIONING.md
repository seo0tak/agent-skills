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
보존한다: `data/`(범위·검출·판정·어댑터별 결과·보관 차수), `adapters/`(프로젝트가 선언한
어댑터), `evidence/`. 교체한 뒤 `validate`를 실행한다.

0.8.0으로 올릴 때 기존 `data/findings.json`은 첫 `scan`에서 `data/scans/_legacy.json`으로
한 번 옮겨져 보존된다. 이 보존 결과는 어떤 어댑터가 찾았는지 기록이 없어, 다음 차수에서
사라져도 해소가 아니라 재확인 안 됨으로 분류된다.

0.9.0으로 올릴 때 증적 워크북에 `decidedBy` 열이 추가된다. 이미 만든 `evidence/`가 있으면
validate가 드리프트를 에러로 보므로 `evidence`를 다시 실행한다. 주체가 없는 reviewed 판정은
경고로 남고, 기존에 false-positive·out-of-scope로 확정한 레코드에는 사용자 확인을 거쳐
`decidedBy: user`를 채운다.

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
- 0.9.0 (현재): 판정 절차 프롬프트(`01-triage.md`), 판정 주체(`decidedBy`, 오탐·범위 밖
  확정은 사용자만), 운영자 출력 들여오기(`ingest`), 출처의 대상·수집 주체 기록.
  skill-architect 점검의 개선 5.
- 예정 M3~M4: 웹/API(DAST), 인프라 스캐너.
- 예정 M5: 방법론 체크리스트.
