# Dashboard Data

이 디렉터리의 JSON은 프로젝트별 정규화 데이터이며 JavaScript 파일은 로컬
HTML 실행용 미러입니다.

- `input-validation.json`: 프로젝트와 입력 보고서의 적합성 및 시작 게이트
- `project-profile.json`: 프로젝트 구조와 보고서 메타데이터
- `findings.json`: 전체 검출 목록과 현재 소스 매핑
- `checker-guides.json`: PDF에서 추출한 체커 공통 자료
- `progress.json`: 작업 상태와 조치 결론

JSON을 변경한 뒤 다음 명령으로 JavaScript 미러를 갱신합니다.

```text
python3 tools/sast_toolkit.py sync
python3 tools/sast_toolkit.py validate
```

초기 파일은 비어 있으며 첫 프로젝트 분석에서 교체됩니다.
