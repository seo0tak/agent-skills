# 버전·호환 정책

## 버전 규칙 (semver)

| 자리 | 의미 | 예 |
|---|---|---|
| 패치 (1.6.x) | 버그 수정, 문서, 대시보드 — 산출물 형식 무변경 | 부팅 반영 수정 |
| 마이너 (1.x.0) | **하위호환 추가** — 선택 필드·선택 기능·새 프롬프트 | SARIF 모드, stableKey |
| 메이저 (x.0.0) | 스키마 breaking — 필수 필드 추가·의미 변경·제거 | schemaVersion 상향 동반 |

## 하위호환 원칙

- 새 데이터는 원칙적으로 **선택 필드**로 추가한다. 기존의 유효한 산출물은
  신버전에서도 읽을 수 있어야 한다. 명시된 스키마를 어긴 입력에 대한
  검증 수정과, 유효성을 입증할 수 없는 과거 승인 재확인은 별도로 공지한다.
  1.11의 입력 내용 해시 도입은 아래 마이그레이션 절차를 따른다.
- 필수화가 필요하면 한 버전은 경고(warn), 다음 메이저에서 에러로
  올린다. 현재 경고 단계인 것:
  - `verification.method` (workflowStatus=verified인데 비어 있을 때)
  - `verification.sourceSnapshot` (옛 verified 결과에 없을 때; status에서는 unbound)
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
| `data/checker-guides.json` | 최상위 schemaVersion만 검사 대상 아님 — 내용·구조 검사는 별도 |

`checker-guides.json`은 `code -> guide` 맵이라 최상위에 `schemaVersion`을
둘 자리가 없다. 넣으려면 `{schemaVersion, guides}`로 감싸야 하는데 이는
breaking 변경이므로 다음 메이저까지 보류한다.

경고 단계 산출물은 업그레이드 후 validate가 **에러 없이 통과하더라도**
경고를 반드시 읽어야 한다. 경고가 곧 마이그레이션 대상 목록이다.

## 진행 중 차수와 업그레이드

| 패치 종류 | 차수 진행 중 적용 |
|---|---|
| 패치·마이너 (하위호환) | "툴킷 업그레이드해줘"로 아래 자산 정책 적용. 상태를 보존하고 공지된 승인 재확인·검증 수정을 처리한 뒤 validate로 확인 |
| 메이저 (breaking) | 금지 — 차수 완료 후 다음 차수부터. 부득이하면 마이그레이션 절차를 먼저 수행 |

## 업그레이드 자산 정책

**아래 표가 교체·보존·병합 목록의 정본**이다. 스킬 설치본 갱신은 이미
프로젝트에 복사된 툴킷을 바꾸지 않는다. 업그레이드할 때는 프로젝트의 옛
문서가 아니라 **새 설치본의 이 문서**를 먼저 읽는다.

| 처리 | 대상 | 방법 |
|---|---|---|
| 배포 자산 갱신 | `assets/`, `prompts/`, `schemas/`, `tools/`, `docs/`, `examples/`; 루트 `README.md`, `USAGE.md`, `SECURITY_SAST_WORKFLOW.md`, `SECURITY_POLICY_BASELINE.md`, `SECURITY_GRILL_GUIDE.md`, `SECURITY_TEST_GUIDE.md`, `AGENTS_SNIPPET.md`, `SECURITY_CHECKLIST.html` | 새 배포물의 해당 파일을 갱신. 기존 파일에 사용자 수정이 있으면 덮어쓰지 말고 아래 절차로 대조·병합 |
| 템플릿·지원 문서 대조 | `templates/`, `project/*.template.md`, `input/`, `data/`, `project/`, `security-guides/`, `security-results/`, `evidence/` 안의 배포 `README.md` | 이전 배포본과 같으면 새 기본본 적용 가능. 사용자 정의가 있거나 이전 기준을 확인할 수 없으면 보존하고 필요한 차이만 병합 |
| 프로젝트 상태 보존 | `input/`, `data/`, `project/`, `security-guides/`, `security-results/`, `evidence/`의 실제 입력·레코드·정책·결과와 그 외 사용자 추가 파일 | 새 배포물의 빈 데이터/샘플로 덮어쓰지 않음. 위에 특정한 지원 문서 외에는 자동 교체하지 않음 |
| 생성물 재생성 | `USAGE.html`, JSON에서 파생되는 `.js`·인덱스·`project/DECISION_LOG.md` | 보존한 프로젝트 정본으로 `sync`. 손으로 작성한 옛 결정 로그는 아래 1.8→1.9 절차로 이전 |

1. 현재 파일과 브라우저에만 있는 상태를 백업하고 교체 출처·대상 버전을
   확인한다. 배포 파일 목록에 없는 사용자 추가 파일은 유지한다.
2. 새 설치본의 마이그레이션을 읽고, 이전 배포본·현재 파일·새 배포본을
   비교한다. 템플릿과 사용자 수정은 보존·병합한다. 충돌이 실제 처리 방식에
   영향을 주고 근거로 해결할 수 없을 때 그 차이만 사용자에게 확인한다.
3. 도구·스키마·프롬프트와 `docs/`를 같은 버전으로 갱신한다. 디렉터리 전체를
   지우는 복사나 삭제 동기화를 하지 않는다. 폐기된 배포 파일은 새 버전에서
   명시한 경우에만 정확한 대상을 확인해 별도로 처리한다.
4. 보존된 정본으로 `python3 tools/sast_toolkit.py sync`, 이어
   `python3 tools/sast_toolkit.py validate`를 실행한다. `gate`가 막으면
   해당 마이그레이션/00 절차를 수행하며, READY 전 운영 작업은 재개하지 않는다.
5. 교체 파일·보존/병합한 사용자 파일·승인 재확인 여부와 남은 오류/경고를
   보고한다. 제출은 실제 증적 검토와 `validate --strict`가 모두 필요하다.

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

### 1.11 → 1.12: 수동 재개·소스 연결·상세 브라우저 백업

- schemaVersion 1.0과 기존 enum은 유지한다. 새 tools/sast_state.py,
  sast_io.py, usage_renderer.py도 tools/ 배포 자산으로 함께 갱신한다.
- data/resume-state.json과 progress.recovery-*.bak는 프로젝트 상태다.
  사용 중인 체크포인트·스냅샷·복구 원본·브라우저 백업을 빈 배포물로 덮어쓰지 않는다.
  .sast-write.lock은 도구의 협조 잠금이다. 작성 중인 잠금 파일을 삭제하지 않는다.
- 옛 verified 결과에 verification.sourceSnapshot이 없어도 읽기는 가능하다.
  validate 경고와 status의 unbound를 확인하고 현재 소스에서 snapshot → 실제 검증 →
  결과 시각·근거 기록 → seal-verification을 수행한다. 과거 passed에 해시만
  덧붙이지 않는다. 연결 후 소스·근거가 달라지면 stale 오류를 먼저 처리한다.
- 새 브라우저 백업은 선택 필드 draftResults에 전체 상세 초안을 담는다.
  옛 백업의 상태·비고는 유지하지만 원래 저장하지 않은 상세 결과는 복원할 수 없다.
  다운로드만으로 정본 반영을 완료하지 않고 04에서 출처·근거를 대조한다.
- 손상 progress는 recover-progress로 미리보기 후 --apply로 복구한다.
  모호한 충돌이나 자료에 없는 메모는 임의로 채우지 않는다.
- 자동 재시작·감시·배포는 추가되지 않았다. 수동 재개와 도구의 검증 범위를
  실제 소스·외부 환경·사용자 권한 확인과 구분한다.

### 1.10 → 1.11: 입력 내용 연결과 기존 스키마 검증 보강

- `inputs.manifest`에 실제 입력 파일 전체의 `{path, size, sha256}`를
  기록한다. 분할 PDF도 개별 파일을 포함하며 경로순으로 정렬한다.
  기존 `inputs.pdf/spreadsheet/sarif` 요약과 `schemaVersion: "1.0"`은 유지한다.
- 과거 READY 승인에 manifest가 없거나 현재 목록·내용 해시가 달라지면
  `gate`와 strict가 차단한다. 파일 크기가 같아도 내용 동일성은 보장되지 않는다.
  산출물을 삭제하지 말고 `preflight` → `prompts/00-preflight.md`의 의미 대조
  → 새 기록에 근거와 승인 → `gate` 순서로 다시 확인한다. 옛 matching=true를
  새 해시에 자동 복사하거나 해시만 덧붙여 승인한 것으로 처리하지 않는다.
- 기존 스키마에 이미 명시된 필수 필드·타입 검사를 실제 적용한다. 누락된
  변경/검증 증적은 당시 근거로 보완하며, 확인할 수 없으면 완료 판정을
  재검토한다. 검증하지 않은 내용을 빈 값·가짜 명령으로 채우지 않는다.
- `change-complete`, `verified` 상태 또는
  `fix/false-positive/operations/exception` 결론에는 결과 레코드가 필요하다.
  완료 progress만 있고 결과를 잃었다면 해당 항목을 복구·재검토한다.
  초기 `todo/in-progress`와 `unreviewed/needs-review` 조합, 분석·정책 파킹인
  `analyzed/needs-review`, `deferred/unreviewed`, `deferred/needs-review`는
  결과 없이 가능하다.
- `verification.method`와 레코드 `schemaVersion`의 기존 경고 정책은 유지한다.
  경고와 오류의 원인을 구분하고, `sync`·`validate`·`gate`를 다시 확인한다.
- 대시보드는 원본 workspaceId가 현재 프로젝트와 같은 옛 브라우저 저장만
  새 저장 키로 이전하고 옛 키는 삭제하지 않는다. 다른 workspace 또는
  workspaceId가 없는 백업은 자동 병합하지 않으므로 원본을 보존해
  `prompts/04-reconcile-results.md`로 출처를 대조한다.

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

- 플러그인 배포는 카탈로그 갱신과 **설치본 갱신**이 별개다. Claude Code의
  user scope 예: `claude plugin marketplace update 0tak` 후
  `claude plugin update sast-remediation@0tak --scope user`와
  `claude plugin update skill-architect@0tak --scope user`. 다른 scope에
  설치했다면 그 범위를 사용하고 재시작 또는 지원되는 `/reload-plugins`로 반영한다.
  제삼자 마켓의 자동 업데이트는 기본 비활성화다
  ([공식 안내](https://code.claude.com/docs/en/discover-plugins#configure-auto-updates)).
- 다른 하네스의 설치 명령은 저장소 README와 해당 버전 CLI 도움말을 따른다.
  카탈로그 버전만 보고 설치 성공으로 판단하지 말고 설치된 플러그인 버전을
  확인한다. 프로젝트 복사본에는 별도로 위 업그레이드 자산 정책을 적용한다.
- 사전 검증: push 전에 `python3 -B -m unittest tools.test_toolkit tools.test_sast_state tools.test_usage_renderer`와
  `node --test tools/test_dashboard.cjs`가 전부
  통과해야 하고, 로컬 경로 마켓플레이스로 설치 테스트
  (`claude plugin marketplace add <로컬경로>`)
- 롤백: 되돌릴 배포를 확정해 버전과 변경 요약을 준비한 뒤 설치본을 갱신한다.
  진행 프로젝트는 백업과 호환 규칙을 확인한다. 보안 검증을 완화한 구버전의
  성공을 새 버전에서 발견된 오류의 해결로 보지 않는다.
