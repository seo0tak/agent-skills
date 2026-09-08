# Item Guide Records

항목별 검토 가이드는 `<finding-id>.json`으로 작성합니다. 같은 내용의 `.js`
파일은 `tools/sast_toolkit.py sync`가 생성합니다.

가이드는 PDF의 공통 해결 예시를 복사하는 문서가 아닙니다. 현재 소스와 호출
관계를 확인한 뒤 해당 항목에서 실제로 봐야 할 범위를 지정합니다.

필수 내용:

- 검출 ID와 보고서 순번
- 현재 소스 매핑 결과
- 실제 코드 분석
- PDF 공통 가이드 적용 판단
- 조치 또는 오탐 검토 포인트
- 호출부와 영향 범위
- 검증 계획
- 중복 처리 그룹
- 필요한 프로젝트 정책

형식은 `schemas/item-guide.schema.json`과 `examples/item-guide.json`을
참조합니다.
