# 선택적 개선 기록과 수동 재개

사용자가 개선 이력이나 장기 검토 재개를 원할 때 읽는다. 한 번의 검토만
요청한 경우에는 별도 개선 기록 디렉터리를 만들지 않는다. 이 절차는 발견과 개선 결과를 연결하는 로컬
기록 방식이다. 자동 학습·자동 실행 플랫폼이 아니며 모델 자체를 학습시키지 않는다.

## 기록과 실제 작업의 경계

`scripts/improvement_tracker.py`는 Python 3 표준 라이브러리만 사용한다.
모든 명령은 사용자가 지정한 로컬 개선 기록 디렉터리의 JSON만 작성하거나 읽는다.
대상 경로, 후보 변경문, 평가 명령처럼 보이는 문자열, 근거 링크는 **데이터**다.
이 기록 도구는 대상 파일이나 링크를 열지 않으며 명령·패치·테스트를 실행하지 않는다.

`approved`는 권한 참조가 형식상 연결되었다는 뜻이다. JSON을 작성할 수 있는
누구나 참조를 입력할 수 있으므로 사용자 신원·실제 승인·자료 진위를 인증하지
못한다. 실제 변경 전에 대화의 사용자 요청, 범위, 현재 대상과 후보를 확인한다.
이미 받은 권한이 적용되면 같은 허락을 다시 묻지 않는다. 새로운 권한이 필요한
범위만 사용자에게 확인한다. 기록을 만드는 행위가 실행 권한을 만들지는 않는다.

## 최소 운영 순서

1. `capture`로 문제·재현·검토 맥락을 남긴다. 중단 전 `checkpoint`에 완료한
   검토, 남은 검토, 판단 메모와 다음 행동을 적는다. 아직 평가하지 않은 결과는
   미완료로 둔다. 개선 기록에는 스킬 개선 자료만 두고 SAST 고객 업무 자료는 넣지 않는다.
2. `proposed`에 변경 전 동작(`baseline`), 정확한 변경안(`candidate`), 프로젝트 상대 대상 경로와
   변경 전 SHA256, 복구 버전·방법을 기록한다. SHA256은 실제 파일에서 별도로
   계산한다(예: `shasum -a 256 skills/example/SKILL.md`). 디렉터리나 여러 파일이면
   정렬된 상대 경로와 각 파일 SHA256을 포함하는 스냅샷 명세의 SHA256을 사용하고
   계산 방법·파일 목록을 baseline 재현 설명에 남긴다. 모든 변경 대상이 포함되어야 한다.
3. 실제 업무 자료와 분리한 테스트 입력·환경(fixture)에서 변경 전과 변경 후를 각각
   평가하고 관찰 결과, 근거, 기존 동작 회귀 결과를 `evaluated`로 남긴다. 평가 실행 자체는 별도 작업이다.
4. 평가·회귀가 모두 `pass`일 때 실제 사용자 권한의 출처와 적용 범위를 `approved`로
   연결한다. 후보·대상이 같아도 평가 내용을 바꾸면 해당 평가에 맞는 참조가 필요하다.
5. 실제 파일과 권한을 다시 확인하고 승인 범위 안에서 별도로 변경한 뒤 `applied`를
   기록한다. 변경 직전 대상 SHA256, 변경 후 SHA256, 적용 버전과 근거를 남긴다.
   변경 전 `checkpoint`를 남겨 중단 시 파일 수정 여부부터 대조할 수 있게 한다.
6. 적용 후 실제 파일의 SHA256·버전을 확인하고 회귀 테스트를 실행한다. 회귀 성공
   근거와 복구 사본의 가용성을 확인한 기록이 있어야 `verified`로 진행한다.
   설치·배포는 별도 권한과 해당 저장소 절차를 따른다.

기록 도구는 입력된 SHA256과 결과의 정합성을 검사한다. 파일이 실제로 바뀌었는지,
테스트를 실행했는지, 근거와 사용자 권한이 유효한지는 작업을 수행하는 에이전트가
현재 사용자 요청의 범위 안에서 별도로 확인해야 한다.

## CLI와 저장 계약

명령 경로는 스킬 루트 기준이다. `--store`는 명시적으로 고른 프로젝트별 로컬
디렉터리이며 기본값·전역 기록 디렉터리는 없다. `--data`는 해당 작업의 입력 객체만
담은 JSON 파일이다. 아래 표의 `data` 필드를 파일의 최상위에 적는다.
`schemaVersion/id/revision/events`가 포함된 전체 저장 레코드를 전달하는 옵션이 아니다.

예를 들어 `capture.json`에는 다음 입력 객체를 저장한다.

```json
{
  "problem": "빈 입력이 정상 검토 완료로 표시된다.",
  "reproduction": "분리된 테스트 환경에서 빈 SKILL.md를 입력한다.",
  "context": "합성 입력으로 스킬 입력 검증을 검토한다."
}
```

`proposal.json`과 `checkpoint.json`도 아래 필드 표에 맞춰 별도로 준비한다.
다음 명령은 각 입력 파일을 준비한 뒤 실행하는 순서 예시다.

```bash
python3 scripts/improvement_tracker.py --store /path/to/project/improvements capture --id empty-input --data capture.json
python3 scripts/improvement_tracker.py --store /path/to/project/improvements transition --id empty-input --to proposed --data proposal.json --expected-revision 1
python3 scripts/improvement_tracker.py --store /path/to/project/improvements checkpoint --id empty-input --data checkpoint.json --expected-revision 2
python3 scripts/improvement_tracker.py --store /path/to/project/improvements validate --id empty-input
python3 scripts/improvement_tracker.py --store /path/to/project/improvements summary --id empty-input
```

`transition --to`는 `proposed`, `evaluated`, `approved`, `applied`, `verified`,
`rejected`, `rolled-back` 중 하나다. 모든 변경은 이력을 추가하며, `capture`는
기존 ID를 덮어쓰지 않는다. ID는 소문자·숫자로 시작하는 소문자·숫자·하이픈
1~64자다. 저장 파일은 `<store>/<id>.json` 하나이며 전체 이력이 정본이다.

다음은 `capture` 후 도구가 저장하는 전체 레코드 예시이며 `--data` 입력이 아니다.

```json
{"schemaVersion":"1.0","id":"empty-input","revision":1,"events":[
  {"action":"captured","at":"2026-09-09T09:00:00+09:00","data":{
    "problem":"빈 입력을 정상 감사 완료로 표시한다.",
    "reproduction":"분리된 테스트 환경에서 빈 SKILL.md를 감사한다.",
    "context":"로컬 스킬 입력 검증 개선; 실제 고객 자료 없음."
  }}
]}
```

`revision`은 이벤트 수다. 기존 상태 필드를 따로 저장하거나 인덱스를 신뢰하지
않으며 읽을 때 전체 이력을 재검증한다. 각 이벤트는 `action`, 시간대가 있는
ISO 날짜 `at`, 해당 작업의 `data`를 갖는다. 아래 필드는 모두 필수이며 추가
필드·빈 문자열·잘못된 타입·중복 JSON 키를 거부한다.

| 작업/상태 | `data` 필드 |
|---|---|
| capture → captured | `problem`, `reproduction`, `context`: 문자열 |
| proposed | `baseline`: `{reproduction, observed}`; `target`: `{path, sha256}`; `candidate`: `{summary, change}`; `rollback`: `{version, plan}` — 각 값은 문자열 |
| evaluated | `binding`, `result`, `baselineObserved`, `candidateObserved`, `evidence`, `regressionResult`, `regressionEvidence` |
| approved | `binding`, `evaluationDigest`, `reference`, `scope` |
| applied | `binding`, `evaluationDigest`, `authorityReference`, `preApplyTargetSha256`, `resultingTargetSha256`, `version`, `evidence` |
| verified | `binding`, `resultingTargetSha256`, `version`, `regressionResult`, `regressionEvidence`, `rollbackChecked` |
| rejected | `reason` |
| rolled-back | `reason`, `restoredVersion`, `evidence` |
| checkpoint | `completed`, `remaining`: 문자열 배열; `notes`, `nextAction`: 문자열 |

표에서 별도 타입을 지정하지 않은 값은 문자열이다. 평가의 `result`와
`regressionResult`는 `pass` 또는 `fail`; `verified.regressionResult`는 `pass`다.
SHA256은 소문자 16진수 64자다. `target.path`는 `..`, 역슬래시, URL·절대 경로를
허용하지 않는 프로젝트 상대 POSIX 경로다. 기록 도구가 이 경로의 파일을 열지는 않는다.

`binding`은 proposed 데이터 **전체**의 정렬된 키·공백 없는 UTF-8 JSON SHA256이다.
`evaluationDigest`는 evaluated 데이터 전체를 같은 방식으로 계산한 값이다.
직접 조립하지 말고 직전 응답 `summary.binding`과 `summary.evaluationDigest`를
복사한다. `authorityReference`는 approved의 `reference`와 정확히 일치해야 한다.

순서는 captured → proposed → evaluated → approved → applied → verified다.
적용 전에는 proposed로 되돌아가 후보를 수정할 수 있고 이전 평가·권한 참조는
현재 상태에서 제거된다(과거 이력은 보존). 변경된 후보·대상은 새 평가가 필요하다.
기존 실제 권한이 새 범위에도 적용되면 그 근거를 다시 연결할 수 있다.
failed 평가 후에는 새 proposed로 재평가하거나 rejected를 기록한다.
적용 전 rejected, 적용 후 rolled-back은 종료 상태다. 실제 복구가 끝나지 않았으면
rolled-back으로 표시하지 말고 checkpoint에 실패·남은 작업을 남긴다.
다음 개선은 새 ID를 사용한다. checkpoint는 어느 상태에서도 기록 가능하고
상태를 전진시키지 않는다. 다음 상태로 바뀌면 현재 checkpoint는 해제되며 이력에 남는다.

성공 stdout은 `{"ok":true,"summary":{...}}`, 실패는
`{"ok":false,"error":"..."}` 한 JSON이며 종료 코드는 각각 0, 2다.
`--help`만 일반 텍스트다. summary는 ID·revision·상태·문제·binding·평가 digest·
권한 참조·최신 checkpoint·평가/회귀 결과·버전·복구 버전·다음 행동을 제공한다.
`nextAction`은 최신 checkpoint의 구체적인 다음 행동이 있으면 그 값을 표시하고,
없으면 현재 상태의 일반 안내를 표시한다. `lifecycleNextAction`은 상태의 일반
안내를 항상 유지한다. checkpoint 안내는 상태 전이나 권한을 부여하지 않는다.
항상 `authorityAuthenticated:false`와 실제 권한 확인 안내를 포함한다.
`verified`도 기록된 과거 결과이며 현재 파일 검증을 대신하지 않는다.

## 재개와 중단 복구

먼저 `validate` 또는 `summary`를 실행한다. 손상·필수 항목 누락·과거 후보와 평가
불일치는 실패로 끝나며 기록을 초기화하지 않는다. 유효한 백업과 원본을 보존하고
문제가 생긴 이벤트와 실제 파일을 대조한다. 기록으로 복구할 수 없는 대화나
메모는 유실/미확인으로 명시한다. 없는 평가·권한을 채워 완료 상태를 만들지 않는다.

유효한 기록은 checkpoint와 이력을 읽고 실제 작업 디렉터리를 확인한다. applied
이전이어도 파일 수정은 이미 시작됐을 수 있다. 실제 변경이 기록과 다르면 먼저
수정 범위·후보·권한을 대조한다. 전 상태 SHA256이나 평가 근거를 확인할 수 없으면
완료를 기록하지 않고 checkpoint에 미확인을 남긴다. 승인 범위 밖의 변경은 따로 다룬다.
현재 대상·후보가 달라졌으면 새 proposed로 되돌려 평가·적용 가능 권한을 다시 연결한다.
이미 applied/verified이면 과거 기록을 고치지 말고 새 개선 기록에서 후속 변경을 다룬다.

쓰기에는 개선 기록 디렉터리당 `.write-lock`을 배타적으로 만들고, 고유 임시 파일에
기록·flush·fsync한 뒤 원자 교체한다. `--expected-revision`이 다르면 최신 기록부터
재개한다. 중단·출력 오류로 성공 응답을 못 받았어도 교체가 끝났을 수 있으므로
재시도 전에 JSON과 revision을 확인한다. 동시 쓰기나 중단으로 lock이 남으면
자동 삭제하지 않는다. 복구 담당자가 작성 중인 프로세스가 없음을 확인하고
기존 JSON을 검증한 뒤 해당 lock만 제거한다.
읽기는 교체 전/후 완전한 기록을 본다. 강제 종료 시 `.record-*.tmp`는 미완료
후보이며 정본으로 승격하지 않는다. 검증·대조 후 해당 임시 파일만 정리한다.
협조하는 로컬 작성자 간 계약이며 악의적 동시 파일 변경, 분산 파일시스템,
전원 장애 시 디렉터리 메타데이터 지속성까지 보장하지 않는다.

## 재현 가능한 사용 예와 평가 판단

[improvement-example.json](improvement-example.json)은 후보 평가가 아직 끝나지
않은 입력 검증 개선의 기록이다. 실제 승인이나 평가 성공을 넣지 않은 합성 예다.
스킬 루트에서 임시 기록 디렉터리에 복사해 재개 요약을 볼 수 있다.

```bash
example_store=$(mktemp -d)
cp references/improvement-example.json "$example_store/empty-input.json"
python3 scripts/improvement_tracker.py --store "$example_store" summary --id empty-input
```

후속 평가는 빈 입력·공백 입력·정상 입력을 각각 실행한다. 예를 들어 baseline은
빈 입력을 exit 0으로 수락하고, 후보는 exit 2로 거부하면서 정상 입력 결과를
유지했다면 재현 개선을 `pass`로 기록할 수 있다. 기존 정상 입력이 깨지면
`regressionResult:fail`이며 approved로 갈 수 없다. 평가 출처에는 실제 명령,
fixture 위치·조건, 관찰한 결과와 미확인 범위를 남긴다. 명령 문자열은 기록용이다.
독립 평가나 반복 압박 테스트를 하지 않았다면 그렇게 적는다. 합성 테스트 성공을
실제 업무 환경의 품질이나 수행하지 않은 반복 모델 평가의 성공으로 확대하지 않는다.
평가 횟수와 환경은 실제 실행 기록대로 적는다.

최종 보고는 결과·검증과 한계·미완료 작업·다음 행동 순서다. 예: “변경안은 빈 입력을
거부했지만 기존 정상 입력 테스트가 실패했습니다. 아직 적용하지 않았으며,
변경안을 수정한 뒤 같은 사례를 다시 평가해야 합니다.” 기록 파일 경로·revision을 연결해 다음 세션에서 이어간다.
