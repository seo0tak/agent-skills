# 제출 증적 요청문

```text
현재 SAST 처리 결과를 검토 가능한 제출 증적으로 정리해 주세요.

먼저 툴킷 디렉터리에서 다음을 실행합니다.
- python3 tools/sast_toolkit.py gate
- python3 tools/sast_toolkit.py validate --strict
- python3 tools/sast_state.py status
오류나 stale/unbound 검증을 숨기거나 새 passed로 바꾸지 않습니다.
재검증하지 못한 항목은 미검증·추가 검토 워크북에 제한과 함께 남깁니다.
최종 제출 판단은 자동 검사 외에 실제 근거와 사용자 검토가 필요합니다.

입력 기준:
- data/findings.json
- data/progress.json
- security-results/*.json
- project/PROJECT_SECURITY_POLICY.md
- data/decisions.json (결정 근거 참조 ID의 정본)

컬럼 구성과 정렬은 `templates/evidence-columns.md` 정의를 그대로
따릅니다. 임의로 컬럼을 추가·삭제·재배치하지 않습니다.

생성할 결과 (파일명은 data/project-profile.json의 evidence.outputs 설정을
우선 사용하고, 설정이 없으면 아래 기본값을 사용합니다):
1. evidence/SAST_전체조치결과.xlsx  (evidence.outputs.allResults)
2. evidence/SAST_오탐예외의견.xlsx  (evidence.outputs.falsePositiveOpinions)
3. evidence/SAST_운영설정필요.xlsx  (evidence.outputs.operationsRequired)
4. evidence/SAST_미검증추가검토.xlsx  (evidence.outputs.unverifiedReview)

전체 조치 결과와 나머지 워크북의 열·정렬은 위 템플릿을 단일 기준으로
사용합니다. 프로젝트가 수정한 템플릿이 있으면 그 정의와 결정 근거를
확인합니다. 같은 파일, 함수, 체커와 동일 근거인 항목은 템플릿이 허용하는
의견 셀에 공통 근거를 간결히 적을 수 있습니다.
의견은 제출용으로 간결하게 작성하되 실제 타입, 호출 흐름, 외부 규격 등
검증 가능한 근거를 포함합니다. 기존 검증 결과 셀에 기록 결과와 소스 연결
상태를 함께 씁니다(예: passed / unbound — 현재 재검증 필요).
열은 바꾸지 않으며 stale/unbound는 미검증·추가 검토 목록에도 포함합니다.

마지막으로 전체, 위험도별, 결론별, 검증상태별 건수를 보고하고 데이터 간
불일치가 없는지 확인해 주세요. 실행한 검사와 미확인 범위, 남은 조치도 보고합니다.
```
