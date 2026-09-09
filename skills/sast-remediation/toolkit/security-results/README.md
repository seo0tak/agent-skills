# 항목별 결과 정본

처리 결과는 `<finding-id>.json`으로 작성합니다. `.js` 파일과 `index.js`는
`tools/sast_toolkit.py sync`가 생성합니다.

결과에는 다음을 포함합니다.

- 조치 결론과 판단 이유
- 진행 상태
- 실제 변경 파일과 위치
- 적용 내용
- 기존/수정 코드 비교
- 선택 보고서 가이드 대비 실제 조치
- 영향 범위
- 검증 명령과 결과
- 중복 처리 항목
- 제출용 비고 문구

형식은 `schemas/result.schema.json`과 `examples/result.json`을 참조합니다.
예시는 합성 데이터이며 실제 검증 근거로 복사하지 않습니다.
현재 검증은 prompts/03의 snapshot → 실제 검증 → 결과 기록 → seal-verification을
거칩니다. status에서 stale/unbound이면 현재 소스의 검증 완료로 신뢰하지 않습니다.
