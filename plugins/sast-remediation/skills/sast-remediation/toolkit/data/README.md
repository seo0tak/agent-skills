# 프로젝트 데이터

JSON에는 보고서와 프로젝트 정보를 공통 형식으로 정리해 저장합니다.
JavaScript 파일은 이 JSON 내용을 로컬 HTML에서 읽을 수 있게 생성한
사본(미러)입니다.

- `input-validation.json`: 프로젝트와 입력 보고서의 적합성 및 시작 게이트
- `project-profile.json`: 프로젝트 구조와 보고서 메타데이터
- `findings.json`: 전체 검출 목록과 현재 소스 매핑
- `checker-guides.json`: PDF 또는 SARIF rules에서 추출한 체커 공통 자료
- `progress.json`: 결과 집계와 아직 결과가 없는 임시 진행상태·비고
- `decisions.json`: 정책 결정 정본; DECISION_LOG.md는 생성물
- `resume-state.json`: 필요할 때 생성되는 중단 지점·파일 스냅샷(화면 미러 없음)
- `progress.recovery-*.bak`: 복구 적용 전 원본; 프로젝트 상태로 보존

JSON을 변경한 작성자는 툴킷 루트 디렉터리에서 다음 명령을 실행해 JavaScript
미러를 갱신하고 검사합니다.

```text
python3 tools/sast_toolkit.py sync
python3 tools/sast_toolkit.py validate
```

배포의 초기 데이터는 비어 있습니다. 실제 프로젝트에서 이미 만든 상태를
배포용 빈 데이터로 덮어쓰지 않습니다.
