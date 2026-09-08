# 버전·호환 정책

## 버전 규칙 (semver)

| 자리 | 의미 | 예 |
|---|---|---|
| 패치 (1.6.x) | 버그 수정, 문서, 대시보드 — 산출물 형식 무변경 | 부팅 반영 수정 |
| 마이너 (1.x.0) | **하위호환 추가** — 선택 필드·선택 기능·새 프롬프트 | SARIF 모드, stableKey |
| 메이저 (x.0.0) | 스키마 breaking — 필수 필드 추가·의미 변경·제거 | schemaVersion 상향 동반 |

## 하위호환 원칙

- 새 데이터는 항상 **선택 필드**로 추가한다. 기존 산출물이 신버전
  validate를 통과해야 한다.
- 필수화가 필요하면 한 버전은 경고(warn), 다음 메이저에서 에러로
  올린다. 현재 경고 단계인 것:
  - `verification.method` (workflowStatus=verified인데 비어 있을 때)
  - findings 항목·security-guides·security-results의 `schemaVersion`
- enum은 값 추가만 하위호환이다. 값 제거·의미 변경은 메이저다.

## schemaVersion 검사 수준

`validate`는 산출물마다 다른 강도로 검사한다. 초기화 시점부터 필드가
보장되는 단일 파일은 에러, 구버전 레코드가 남아 있을 수 있는 것은
경고다.

| 산출물 | 검사 수준 |
|---|---|
| `data/input-validation.json` | 에러 |
| `data/project-profile.json` | 에러 |
| `data/progress.json` | 에러 |
| `data/decisions.json` | 에러 (없으면 경고 — 1.9 이전 프로젝트) |
| `data/findings.json` (항목별) | 경고 |
| `security-guides/*.json` | 경고 |
| `security-results/*.json` | 경고 |
| `data/checker-guides.json` | **검사 없음** — 아래 참조 |

`checker-guides.json`은 `code -> guide` 맵이라 최상위에 `schemaVersion`을
둘 자리가 없다. 넣으려면 `{schemaVersion, guides}`로 감싸야 하는데 이는
breaking 변경이므로 다음 메이저까지 보류한다.

경고 단계 산출물은 업그레이드 후 validate가 **에러 없이 통과하더라도**
경고를 반드시 읽어야 한다. 경고가 곧 마이그레이션 대상 목록이다.

## 진행 중 차수와 업그레이드

| 패치 종류 | 차수 진행 중 적용 |
|---|---|
| 패치·마이너 (하위호환) | 안전 — "툴킷 업그레이드해줘"로 고정 자산만 교체, 산출물 보존, validate로 확인 |
| 메이저 (breaking) | 금지 — 차수 완료 후 다음 차수부터. 부득이하면 마이그레이션 절차를 먼저 수행 |

## breaking 변경 절차 (메이저)

1. 버전을 **두 곳** 함께 올린다 (예: 1.0 → 2.0)
   - `tools/sast_toolkit.py`의 `SCHEMA_VERSION` 상수
   - `schemas/*.json`의 `schemaVersion` const 값
   한쪽만 올리면 `validate`가 "schema ... const is X but validator
   SCHEMA_VERSION is Y" 에러로 막는다.
2. 경고 단계인 검사를 에러로 올린다
   (`report.schema_version(..., "warn")` → `"error"`)
3. 구버전 산출물 → 신버전 변환 규칙을 이 문서에 기록한다
4. 업그레이드 직후 validate를 돌린다. 에러 + 경고를 합쳐서 읽으면
   마이그레이션 대상이 드러난다 — 위 검사 수준 표대로 레코드류는
   경고로만 나오므로 에러 0건을 통과로 오해하면 안 된다

## 마이그레이션 기록

### 1.8 → 1.9: 결정 로그가 JSON 정본이 됨

- `project/DECISION_LOG.md`를 손으로 쓰던 방식에서 `data/decisions.json`
  정본 + sync 생성으로 바뀌었다. 하위호환: 손으로 쓴 DECISION_LOG.md는
  sync가 덮어쓰지 않고, validate가 경고만 낸다.
- 옮기는 법: 기존 md의 결정마다 `decisions.json`에 항목을 추가한다
  (`schemas/decisions.schema.json`). `결정 주체`가 없던 옛 결정은
  실제로 사용자가 확인했으면 `user`, 추천을 그대로 적용했으면
  `baseline-default`로 두고 관찰 장치·재검토 조건을 채운다. 옮긴 뒤 md를
  지우고 `sync`.
- `data/decisions.json`이 없으면 `init`이 만든다(다른 산출물은 건드리지
  않음).

## 배포·롤백

- 배포: 저장소 push → 각 PC `claude plugin marketplace update`
- 사전 검증: push 전에 `python3 -m unittest tools.test_toolkit`가 전부
  통과해야 하고, 로컬 경로 마켓플레이스로 설치 테스트
  (`claude plugin marketplace add <로컬경로>`)
- 롤백: `git revert` 후 push → update. 산출물은 하위호환 원칙 덕에
  구버전 툴킷으로도 읽힌다
