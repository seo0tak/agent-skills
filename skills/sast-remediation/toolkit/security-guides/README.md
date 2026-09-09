# 항목별 검토 가이드

항목별 검토 가이드는 `<finding-id>.json`으로 작성합니다. 같은 내용의 `.js`
파일은 `tools/sast_toolkit.py sync`가 생성합니다.

가이드는 PDF 또는 SARIF의 공통 해결 예시를 그대로 복사하는 문서가 아닙니다.
현재 소스와 호출 관계를 확인한 뒤 해당 항목에서 실제로 봐야 할 범위를 지정합니다.

전체 가이드의 필수 내용:

- 검출 ID와 보고서 순번
- 현재 소스 매핑 결과
- 실제 코드 분석
- PDF 또는 SARIF 공통 가이드 적용 판단
- 조치 또는 오탐 검토 포인트
- 호출부와 영향 범위
- 검증 계획
- 중복 처리 그룹
- 필요한 프로젝트 정책

그룹 대표 가이드를 참조하는 항목별 차이 가이드도 `schemaVersion`, `id`,
`sequence`, `title`, `sourceMapping`, `summary`의 기본 필수 필드를 유지합니다.
`groupGuideRef`로 대표 가이드를 가리키고, 대표 가이드와의 차이를 `summary`에
요약하며 필요한 경우 `delta`에 추가로 기록합니다. 대표 본문은 복제하지 않습니다.

형식은 `schemas/item-guide.schema.json`과 `examples/item-guide.json`을
참조합니다.
