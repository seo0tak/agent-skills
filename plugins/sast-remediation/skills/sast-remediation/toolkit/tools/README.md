# 툴킷 명령

툴킷 디렉터리에서 실행합니다. Python 표준 라이브러리만 사용하며,
프로젝트가 다른 위치에 있으면 각 명령의 `--project-root <경로>`를 지정합니다.
세부 인수는 `--help`로 확인하세요.

## 입력·생성·검사·조회

| 명령 | 역할 |
|---|---|
| `python3 tools/sast_toolkit.py preflight` | 소스·선택 입력 세트·파일 형식과 해시 점검 |
| `python3 tools/sast_toolkit.py gate` | 의미 대조 승인과 현재 입력을 확인 |
| `python3 tools/sast_toolkit.py init` | READY 이후 없는 프로젝트 기록을 초기화 |
| `python3 tools/sast_toolkit.py sync` | JSON에서 JS 미러·index·문서 생성 |
| `python3 tools/sast_toolkit.py validate` | 산출물과 스키마·미러·상태 정합성 검사 |
| `python3 tools/sast_toolkit.py validate --strict` | 입력·초기화 누락도 오류로 보는 제출 전 검사 |
| `python3 tools/sast_toolkit.py query --summary` | 도구가 findings·progress를 읽어 집계 |
| `python3 tools/sast_toolkit.py query --group WG-003` | 그룹의 모든 진행상태 조회 |
| `python3 tools/sast_toolkit.py query --ids A,B --fields id,location,progress` | 필요한 ID·필드만 조회 |

query의 표준 출력은 JSON입니다. 오류·경고를 JSON에 섞지 않습니다.
`ERROR`는 해결할 오류, `WARN`은 원인과 제한을 확인할 경고입니다.
성공 종료 코드는 0이며, 오류는 0이 아닌 값입니다.
검사 성공은 실제 테스트 실행이나 제출 승인이 아닙니다.

## 중단 지점과 소스 검증 연결

다음 명령의 `<ID>`, `<파일>`, 메모를 실제 값으로 바꿉니다.
경로는 현재 프로젝트 루트 기준이며 툴킷 밖의 해당 소스 파일을 가리킵니다.
관련 파일이 여럿이면 `--path`를 반복합니다.

```text
python3 tools/sast_state.py checkpoint --id <ID> --phase before-edit --path <파일> --note "<현재 판단>" --next-action "<다음 작업>"
python3 tools/sast_state.py checkpoint --id <ID> --phase after-edit --path <파일> --note "<수정 후 판단>" --next-action "<검증 계획>"
python3 tools/sast_state.py snapshot --id <ID> --path <파일>
```

스냅샷 다음에 검증을 실제로 실행합니다. 결과에 방법·성공 여부·출력과 실제
verifiedAt을 남긴 뒤 아래 명령으로 근거를 연결합니다.

```text
python3 tools/sast_state.py seal-verification --id <ID>
python3 tools/sast_state.py status
```

연결 명령은 테스트를 실행하거나 verified로 승격하지 않습니다.
상태 의미와 검증 범위의 한계는 `docs/HOW_IT_WORKS.md`를 참고하세요.

## 진행상태 복구

```text
python3 tools/sast_state.py recover-progress
python3 tools/sast_state.py recover-progress --backup <백업파일>
```

위 명령은 미리보기입니다. 내용을 확인한 뒤 같은 명령에 `--apply`를
붙여야 반영합니다. 출처가 다른 백업·모호한 충돌·잘못된 데이터는 먼저 해결합니다.
복구 전 원본과 백업을 보존하며, 상세 브라우저 초안을 정본 결과로 만들지 않습니다.
전체 절차는 `prompts/07-resume.md`를 따릅니다.

sast_state.py의 stdout은 JSON이며 정상 명령은 0, 거부·입력 오류는 2입니다.
status의 `ok`와 후보·오류 목록도 함께 확인하세요. 종료 코드만으로 완료를 판단하지 않습니다.

## 저장과 회귀 검사

공용 정본은 지정한 한 작성자가 갱신합니다. 도구의 협조 잠금은
이를 따르지 않는 에디터·외부 프로세스의 동시 쓰기를 막지 않습니다.
JSON 정본을 확인한 뒤 sync → validate 순서로 실행합니다.

```text
python3 -B -m unittest tools.test_toolkit tools.test_sast_state tools.test_usage_renderer
node --test tools/test_dashboard.cjs
```

테스트는 임시 작업공간을 사용합니다. 배포용 빈 툴킷 자체에서
preflight나 init을 실행해 프로젝트 기록을 만들지 마세요.
