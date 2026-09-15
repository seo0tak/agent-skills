# 위험도 처리 범위

처리 범위는 한 검사 차수의 전체 검출 목록을 보존하면서 사용자가 승인한
위험도만 상세 분석·조치·검증하기 위한 실행 경계입니다. 입력 게이트, 전체 항목
등록과 보고서 건수 대조는 범위와 관계없이 수행합니다. 범위 설정은 검사 범위를
다시 정의하거나 범위 밖 위험을 수용한 기록이 아닙니다.

## 정본 계약

정본은 `data/project-profile.json`의 선택 필드 `processingScope`입니다.

```json
{
  "workspaceId": "sample-workspace",
  "reportId": "sample-report",
  "minRisk": "high",
  "updatedAt": "2026-09-15T00:00:00Z",
  "updatedBy": "user",
  "reason": "이번 차수는 높음 이상 처리"
}
```

- `workspaceId`는 프로필의 `workspaceId`, `reportId`는 프로필의 `report.id`와
  일치해야 합니다.
- `minRisk`는 `critical`, `very-high`, `high`, `medium`, `low` 중 하나입니다.
  순서는 `critical` → `very-high` → `high` → `medium` → `low`이며 보고서의
  숫자 rank로 다시 판정하지 않습니다.
- `updatedAt`, `updatedBy`, `reason`은 누가 언제 어떤 이유로 범위를 설정했는지
  남깁니다. 미초기화·빈 식별자, 잘못된 등급·시각·기록자·사유는 거부합니다.
- 이 기록은 확인 가능한 사용자 승인 참조입니다. 파일만으로 소스 변경·배포·
  연속 실행 권한을 새로 만들지 않습니다.
- 이 선택 필드가 없는 1.12.x 이하 프로필도 읽을 수 있지만 처리 범위는
  `미설정`입니다. 상세 분석·조치 전에 범위를 기록하며 전체로 자동 확대하지
  않습니다.

기존 `schemaVersion: "1.0"`, finding/result 형식, 결론과 `workflowStatus`
enum, 증적 열은 바꾸지 않습니다. 범위는 기존 항목 상태를 나타내는 새 enum이
아니며, 범위 설정·변경만으로 progress, 결과 또는 검증 근거를 바꾸지 않습니다.

## 분류

| 분류 | 기준 | 처리 |
|---|---|---|
| `in-scope` | 5단계 위험도가 `minRisk` 이상 | 상세 분석·조치·검증 대상 |
| `out-of-scope` | 5단계 위험도가 임계값 미만이거나 `info` | 원본·기존 상태 보존 |
| `unknown` | 위험도 `unknown` 또는 등급 누락 | 별도 미확인; 낮은 위험도로 간주하지 않음 |
| `unconfigured` | 유효한 처리 범위가 없음 | 상세 실행 중단; 전체 자동 선택 금지 |

`info`와 `unknown`은 서로 다릅니다. `info`는 5단계 밖의 안내 등급이어서
범위 밖이고, `unknown`·누락은 분류 근거가 부족하므로 별도 보고합니다.

작업 그룹에는 여러 분류가 섞일 수 있습니다. 그룹 전체가 아니라 항목별로
`in-scope` 여부를 확인합니다. 선택 항목의 공통 수정이 범위 밖 항목에 영향을
주더라도 그 하위·중복 항목의 결론, 진행상태 또는 검증 완료를 자동으로 올리지
않습니다. 영향과 회귀 검증은 확인하되 별도 근거와 승인 없이 상세 조치 대상으로
확대하지 않습니다.

## CLI

툴킷 디렉터리에서 실행합니다.

```text
python3 tools/sast_toolkit.py scope
python3 tools/sast_toolkit.py scope --min-risk high --set-by user --reason "이번 차수는 높음 이상 처리"
python3 tools/sast_toolkit.py query --scope in-scope
python3 tools/sast_toolkit.py query --scope in-scope --group WG-001
python3 tools/sast_toolkit.py query --scope out-of-scope
python3 tools/sast_toolkit.py query --scope unknown
python3 tools/sast_toolkit.py query --scope all
```

`scope`만 실행하면 정본과 전체·대상·범위 밖·미확인, 대상 검증 완료·남은
건수를 읽기 전용으로 보여줍니다. 설정 명령은 게이트 READY와 현재 작업공간·
차수를 확인하고 프로필만 원자적으로 갱신한 뒤 sync합니다. 결과, progress,
findings와 입력 원본은 수정하지 않습니다.
프로필·상태 구조, 작업공간·차수 identity와 입력 게이트는 설정의 필수 조건입니다.
sourceSnapshot 구조, evidenceDigest와 검증 시각 연결은 유효하지만 현재 소스가
변경돼 오래된(stale) 검증은 scope 설정·조회·sync를 막지 않고 validate·status의
전체 진단과 재검증 후보에 보존합니다. sourceSnapshot의 명시적 null·구조 손상,
evidenceDigest 불일치나 잘못된 검증 시각은 계속 오류로 차단합니다. 옛 결과에
sourceSnapshot 필드 자체가 없는 unbound는 기존 레거시 경고 계약을 따릅니다. 완료 판단과
현재 소스 재검증은 선택 항목에 수행하며, 범위 밖 stale을 없애려고 처리 범위를
확대하지 않습니다.

`query`는 기존 감사·복구 흐름을 위해 전체 조회가 기본입니다. `--scope all`도
같은 전체 조회입니다. 상세 작업에는 `--scope in-scope`를 명시합니다.
`--scope`는 `--ids`, `--group`, `--status`, `--risk` 등 기존 필터와
교집합으로 적용됩니다. 범위가 미설정이거나 손상됐으면 `in-scope` 조회는
실패하며 일반 전체 조회를 실행 범위로 해석하지 않습니다.

## 설정에서 실행까지

1. `gate`가 READY인지 확인하고 입력 원본 파일을 변경·절단하지 않은 채 보고서의
   모든 항목을 등록해 전체 건수와 식별정보를 대조합니다. 낮은 등급·`info`·
   `unknown`을 입력에서 제거하거나 일괄 오탐·보류 처리하지 않습니다.
2. `scope`로 현재 설정을 읽습니다. 미설정이면 사용자의 임계값과 이유를 확인해
   설정 명령을 실행합니다. 범위를 정할 수 없으면 전체 등록 결과만 보고하고
   상세 분석·조치 전에 멈춥니다.
3. `query --scope in-scope`로 상세 대상만 조회합니다. 그룹 작업에서도
   `query --scope in-scope --group <WG>`를 사용해 혼합 그룹을 항목별로 나눕니다.
4. 선택 항목만 가이드 작성, `before-edit` 체크포인트, 수정, snapshot, 실제 검증,
   결과 기록과 seal-verification을 수행합니다. 도구는 미설정·범위 밖 항목의
   `before-edit`, `snapshot`, `seal-verification`을 거부합니다.
5. `after-edit` 체크포인트는 이미 발생한 작업을 잃지 않도록 범위 변경 뒤에도
   저장할 수 있습니다. 이는 추가 수정 권한이 아닙니다. 범위에서 빠진 항목은
   현재 변경을 보존·보고한 뒤 새 수정을 중단합니다.

범위를 넓히거나 좁혀도 기존 분석·결론·결과·백업은 그대로 둡니다. 새로 포함된
항목은 현재 소스에서 정상 절차로 시작하고, 빠진 항목은 자동 강등·삭제하지
않습니다. 이미 생긴 부수 효과만으로 범위 밖 항목을 완료 처리하지 않습니다.

## 재개와 복구

재개할 때는 다음 순서를 사용합니다.

```text
python3 tools/sast_toolkit.py gate
python3 tools/sast_state.py status
python3 tools/sast_toolkit.py validate
python3 tools/sast_toolkit.py scope
python3 tools/sast_toolkit.py query --scope in-scope
```

`status`의 `resumeCandidates`는 복구 누락을 막기 위해 모든 항목의 기존 후보를
유지합니다. `processingScope`는 현재 범위와 분리 집계, `inScopeResumeCandidates`는
그중 현재 상세 실행 대상인 후보입니다. 먼저 전체 후보·체크포인트·stale/unbound를
보존·복구한 뒤 선택 후보를 실행합니다. `recover-progress`와 `after-edit`는
범위 밖이거나 범위가 바뀐 기존 작업도 보존합니다. 복구 성공이나 과거 파일 기록은
추가 수정 권한이 아닙니다.

범위의 형식이나 작업공간·차수 ID가 손상돼도 `status`는 전체
`resumeCandidates`, checkpoints와 verification을 반환합니다. 이때
`status.processingScope.error`에 원인을 적고 scope는 `configured: false`로,
알려진 등급은 `unconfigured`, 위험도 미확인은 `unknown`으로 집계합니다.
`status.inScopeResumeCandidates`는 빈 목록, 최상위
`status.selectedReadyForCompletion`은 false입니다. 이 status 성공은 복구 정보가
읽혔다는 뜻일 뿐 범위가 유효하다는 뜻이 아닙니다. 독립 `scope` 명령,
`query --scope in-scope`와 선택 실행 경계는 손상된 범위를 계속 거부합니다.

독립 `scope` 출력에서는 `selectedComplete`와 `completionBasis`가 최상위입니다.
`status` 출력에서는 같은 집계가 `status.processingScope.selectedComplete`와
`status.processingScope.completionBasis`에 있고, 값은 선택 항목의
`workflowStatus`만 센 `workflow-status-only` 집계입니다.
`status.selectedReadyForCompletion`은 status 출력의 최상위 필드이며,
선택 대상이 1건 이상이고 모든 선택 항목의 progress와 정본 결과가 일치하며,
검증 연결이 fresh이고 미완료 체크포인트가 없을 때만 참입니다. 전자는 단계 집계,
후자는 완료 보고 전 기계적 준비 조건이며 둘 다 테스트 충분성·정책 타당성·제출
승인을 대신하지 않습니다.
독립 `scope` 출력 최상위 `allComplete`와 `status.processingScope.allComplete`도
같은 상태 라벨 기반이며, 유효한 범위가 있고
전체가 비어 있지 않으며 미확인이 0건이고 모든 항목이 verified일 때만 참입니다.

범위 정본의 작업공간·차수가 현재 프로필과 다르거나 범위가 손상됐으면 전체 복구
정보는 보존하되 선택 실행을 재개하지 않습니다. 같은 차수의 유효한 범위와 확인 가능한 사용자 승인이 있으면 세션이
바뀌었다는 이유만으로 다시 설정하지 않습니다. 현재 요청이나 승인 근거를 확인할
수 없으면 파일만 보고 실행 권한을 추정하지 않습니다.

## 집계와 완료 보고

`scope`와 `status.processingScope`를 기준으로 다음 수치를 분리합니다.

- 전체 항목과 전체 검증 완료
- 선택 범위 항목, 선택 범위 검증 완료와 남은 항목
- 범위 밖 항목(`info` 포함)
- 미확인 항목(`unknown`·등급 누락)

선택 대상이 0건이면 100% 완료가 아닙니다. `selectedComplete`만으로 완료를
선언하지 않고 최상위 `status.selectedReadyForCompletion`, 실제 검증 내용과
한계를 함께 검토합니다. 이를 통과해도 전체 완료·전체 위험 해소·제출 승인을 뜻하지 않습니다.
예: 전체 7건, 대상 3건이 모두 정본 일치·fresh verified이고 미완료 체크포인트가
없으면 `선택 범위 3/3 완료 준비됨; 전체 3/7 검증 완료; 범위 밖 3건; 미확인
1건`으로 보고합니다. 범위 밖과 미확인은 전체 목록과 전체 증적에 계속 남깁니다.

## 레거시와 차수 이월

- `processingScope`가 없는 기존 프로젝트는 읽기·전체 감사·복구가 가능하지만
  `미설정`입니다. 기존 결과와 상태를 보존하고 새 상세 실행 전에 범위를 설정합니다.
- 처리 범위는 검사 차수별 기록입니다. 새 `report.id`로 바뀌면 이전 범위를
  자동 이월하거나 현재 프로필 ID에 맞춰 고쳐 쓰지 않습니다. 새 차수의 전체 항목을
  등록·대조한 뒤 사용자에게 새 범위를 확인합니다.
- 이전 결론·정책·결과는 기존 이월 규칙에 따라 후보로 대조할 수 있습니다.
  새 차수의 대상 여부는 새 차수 범위로 다시 판정하며, 범위 밖 과거 결과도 삭제·
  강등하지 않습니다. 새 차수 verified는 현재 소스에서 선택 대상만 재검증합니다.

## HTML 선택은 적용이 아닙니다

`SECURITY_CHECKLIST.html`의 처리 범위 패널은 적용된 정본을 읽고 사용자가 고른
값으로 AI 요청을 복사합니다. 브라우저는 `data/project-profile.json`을 저장할 수
없으므로 선택·복사만으로 범위가 적용되지 않습니다. 미적용 표시를 확인하고 AI가
설정 명령을 실행한 뒤 sync·새로고침하여 정본을 다시 읽습니다.

위험도·검색·언어 등 목록 필터와 `필터 초기화`는 화면 표시만 바꾸며 처리 범위를
설정·해제하지 않습니다. localStorage와 기존 상태+결과 백업도 처리 범위 정본을
덮어쓰지 않습니다. 추천 작업과 항목별 AI 작업 요청은 적용된 `in-scope` 항목에만
사용하며, 범위 밖 항목의 기존 결과 열람과 전체 목록 감사는 계속 가능합니다.
