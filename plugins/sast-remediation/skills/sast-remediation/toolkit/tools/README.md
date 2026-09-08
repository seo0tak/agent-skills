# Toolkit Commands

`sast_toolkit.py`는 외부 라이브러리 없이 동작합니다.

작업 시작 전 입력 파일과 프로젝트 소스 확인:

```text
python3 tools/sast_toolkit.py preflight
```

현재 프로젝트가 다른 위치라면 `--project-root <path>`를 함께 사용합니다.
AI가 프로젝트와 두 보고서를 대조해 입력 상태를 `ready`로 확정한 뒤 최종
게이트를 검사합니다.

```text
python3 tools/sast_toolkit.py gate
```

`GATE: READY`가 아니면 초기 분석이나 소스 조치를 시작하지 않습니다.

초기 디렉터리 준비:

```text
python3 tools/sast_toolkit.py init
```

JSON에서 로컬 HTML용 JavaScript 미러와 인덱스 생성:

```text
python3 tools/sast_toolkit.py sync
```

산출물 구조와 데이터 일관성 검사:

```text
python3 tools/sast_toolkit.py validate
```

초기 분석 완료 후 빈 값까지 오류로 검사:

```text
python3 tools/sast_toolkit.py validate --strict
```

항상 JSON을 먼저 수정한 뒤 `sync`, `validate` 순서로 실행합니다.
