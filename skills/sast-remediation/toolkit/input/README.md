# Input Files

이 디렉터리에는 현재 검사 차수의 입력 파일만 둡니다.

- SAST 상세 보고서 PDF 1개
- SAST 검출 목록 스프레드시트 1개

여러 차수의 자료가 함께 있으면 AI가 최신 자료를 잘못 선택할 수 있으므로
이전 차수 자료는 별도 보관합니다. PDF와 스프레드시트의 분석 번호, 생성
시각, 총 검출 건수가 일치하는지 초기 분석에서 확인해야 합니다.

작업 시작 전 `python3 tools/sast_toolkit.py preflight`로 파일 개수와 실제
형식을 검사합니다. 이후 현재 소스와 두 보고서가 같은 프로젝트와 검사
차수를 가리키는지 대조하고 `python3 tools/sast_toolkit.py gate`가
`GATE: READY`를 반환해야 다음 단계로 진행할 수 있습니다.
