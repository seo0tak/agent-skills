# 버전·호환 정책

sast-remediation과 같은 원칙을 따른다.

- 패치(0.x.y): 버그 수정·문서. 산출물 형식 무변경.
- 마이너(0.x.0): 하위호환 추가(선택 필드·새 어댑터·새 프롬프트).
- 메이저(x.0.0): 스키마 breaking. schemaVersion 상향 동반.

스코프 스키마의 schemaVersion은 현재 `1.0`. 올릴 때는
`schemas/scope.schema.json`의 const와 `tools/assess_toolkit.py`의
`SCHEMA_VERSION`을 함께 바꾼다.

## 마일스톤

- M0: 인가 게이트 + validate + 테스트.
- M1a (현재): 어댑터 선언 스키마 + 침습도 세 겹 실행 판정(순수 함수, 도구 미실행) + 검증.
- M1~: 소스 측 스캐너 어댑터(SAST/SCA/시크릿) → SARIF 정규화.
- M2~: 판정·증적·SARIF 다리.
- M3~M4: 웹/API, 인프라.
- M5: 방법론 체크리스트.
