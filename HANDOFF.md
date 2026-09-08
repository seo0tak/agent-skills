# HANDOFF — 개발 세션 인수인계 (2026-09-08 기준, v1.10.0)

새 세션은 이 문서와 저장소 루트 README.md를 읽으면 이어서 작업할 수 있다.
원리는 `skills/sast-remediation/toolkit/docs/HOW_IT_WORKS.md`,
버전·호환 규칙은 같은 곳의 `docs/VERSIONING.md`.

## 현재 상태

- sast-remediation **v1.10.0**, skill-architect **v0.2.0** — `955b527`까지 push 완료,
  working tree clean
- 실물 Sparrow 산출물로 검증된 마지막 버전은 **1.6.x**. 1.7~1.10은 단위 테스트(22건)와
  오류 주입으로만 검증했고 실물 차수는 아직 안 돌렸다 (아래 미결 3)
- 실물 파일 위치: `~/Downloads/issues_lheep-comn-frontend-master_1903.xls`(2,361건),
  `..._1903_01.pdf`(1,906p, 분석 ID 1903)

## 버전별 주요 이력 (전부 하위호환)

| 버전 | 내용 |
|---|---|
| 1.1.x | SARIF 입력 모드, 실물 Sparrow 검증(위험도 5등급 매핑), 분할 PDF, 건수불일치 지침 |
| 1.2.x | input/<세트명>/ 폴더 세트(--input-set), 프로젝트 일치 구체검증, 대시보드 부팅 시 결과 자동반영 |
| 1.3.0 | 그룹 대표 가이드+멤버 delta, 07-resume, verification.method, evidence-columns, Grill 상시화 |
| 1.4.0 | 대시보드 페이지네이션·언어 필터·검색 디바운스, docs/HOW_IT_WORKS.md |
| 1.5.x | 모델 티어 서브에이전트(bulk-worker=haiku, remediator=sonnet), stableKey, 원자 쓰기, 깨진 파일 지목 |
| 1.6.x | 연속 실행 모드(중단조건 5개)+정책 질문 파킹, OKF 부분채택, docs/VERSIONING.md |
| 1.7.0 | schemaVersion 검사 커버리지 — SCHEMA_VERSION 상수, 레코드류 경고 검사, 스키마↔검증기 const 교차검증 |
| 1.8.0 | **모르는 사람이 써도 안전한 Grill** — 소스 밖 증거 수집, 업무 사실 질문, "모르겠다" 선택지, 미확인 시 동작 보존 기본값+관찰 장치, 결정 주체, checker plainDescription (원리 9) |
| 1.9.0 | skill-architect 감사 결과 적용 — `data/decisions.json` 정본+DECISION_LOG.md 생성, validate가 미확인 결정의 관찰 장치 강제, `query` 명령(원리 10), `tools/test_toolkit.py` 22건, USAGE.html을 USAGE.md에서 생성 |
| 1.10.0 | `report.vendorAttributes` — 정의 모르는 벤더 컬럼 원문 보존, A.S 조사 결과 반영 |

저장소 쪽: marketplace.json에 skill-architect 등록(이전엔 설치 불가였음), version 필드 제거
(plugin.json이 정본), 루트 README 관문화. 이후 **멀티 에이전트 재편**(TASK-multi-agent):
마켓플레이스 name `0tak`, 정본을 루트 `skills/`로 승격하고 `plugins/*/skills`는
`scripts/sync-plugins.sh` 사본(Codex가 심링크를 빈 디렉터리로 복사해 심링크 불가),
Codex 카탈로그 `.agents/plugins/marketplace.json` + `.codex-plugin/plugin.json`,
SKILL.md 중립화. 저장소는 `seo0tak/agent-skills`로 개명 완료(2026-09-08), GitHub 소스 설치를 Claude·Codex 양쪽에서 실기 확인 — 규약은 CLAUDE.md.

## 핵심 설계 원칙 (변경 시 지킬 것)

1. 게이트 선행 — 입력 바뀌면 승인 자동무효
2. security-results가 canonical, progress는 집계 — validate가 정합성 강제
3. **정본은 JSON, 읽기용은 생성물** — data/*.js, DECISION_LOG.md, USAGE.html은 sync가 만든다.
   직접 편집 금지, 편집은 정본(JSON / USAGE.md)에
4. 오탐/예외/운영설정은 reason+evidenceNote 없으면 validate 에러
5. 차수 간 매칭은 fingerprint, 소통은 stableKey
6. 저비용 티어는 판정·소스수정·verified 승격 금지
7. 스키마 변경은 선택 필드 추가만 — VERSIONING.md. 하드코딩 버전은 SCHEMA_VERSION 한 곳
8. **규칙은 문서가 아니라 도구가 강제** — 새 규칙을 넣으면 validate가 잡는지 먼저 묻는다.
   문서 규칙만이면 skill-architect 감사에서 "부분"이다
9. **알면 안전한 쪽, 모르면 동작을 보존하는 쪽** — 미확인 결정(decidedBy=baseline-default)은
   observation+reviewTrigger 없으면 기록 자체가 안 된다
10. 큰 findings.json은 읽지 않는다 — `sast_toolkit.py query`

## 미결 사항 (PENDING)

1. **A.S 컬럼** — 실물로 확인한 것: 수용 플래그 **아님**(Y 46건 전부 상태 미확인·담당자
   없음·의견 없음), 위험도 안 바꿈, null 역참조 체커 3종에서만 Y, PDF엔 없음. Y/N 규칙은
   미확정. 현재는 vendorAttributes로 보존만. **Sparrow에 물어볼 것**: "이슈 내보내기 엑셀의
   A.S 컬럼(Y/N) 정의가 무엇인가요? 널 역참조 체커에서만 Y가 나옵니다." 답 오면
   vendorAttributes 값으로 재분류
2. **저장소 안에서 툴킷 명령 실행 금지 가드** — 이번 세션에서 회귀 확인용 `preflight`를 저장소에서
   돌렸다가 로컬 절대 경로가 산출물에 섞여 amend로 되돌렸다. `.gitignore`나 "툴킷 부모가 저장소
   루트면 preflight/init 거부" 가드 검토
3. **1.7~1.10 실물 검증** — 다음 실전 차수에서 통과시킬 것: `query --summary`, 결정 로그
   흐름(decisions.json → sync → DECISION_LOG.md), 미확인 결정 validate 에러, 1.8 이전 손으로
   쓴 DECISION_LOG.md 마이그레이션 경고
4. 결정 로그 대시보드 표시 — `data/decisions.js` 미러는 생성되지만 대시보드는 아직 안 읽는다
5. (아이디어) README 전체 영문판, SARIF 샘플 examples

## 검증 습관

- `cd toolkit && python3 -m unittest tools.test_toolkit` — 22건, 배포·업그레이드 전 필수
  (VERSIONING.md 사전 검증에 명시). 오류 주입 시나리오는 여기 고정돼 있다
- `python3 tools/sast_toolkit.py validate` (OK + 입력 없음 경고 1건이 정상),
  `node --check assets/checklist.js`
- USAGE.md·decisions.json 수정 후 반드시 `sync` — 안 하면 validate가 생성물 드리프트 에러
- 실물 파일 재현 테스트 (위 xls/pdf)

## 이 세션에서 배운 주의점

- `marketplace.json`에 version 쓰지 않는다 — plugin.json이 정본, README 표는 수동 갱신
- 문서 변경 후 USAGE.md·USAGE.html·SECURITY_SAST_WORKFLOW·SKILL.md·README 요약이 새 규칙과
  모순되는지 훑는다 (1.8.0에서 세 군데 고쳤음)
- 설계 논의 결과는 HOW_IT_WORKS(왜)와 해당 가이드(어떻게)에 반드시 적는다 — 이유 없는 규칙은
  다음 사람이 형식으로 보고 지운다
- skill-architect는 이 세션 스킬 목록에 없으면 SKILL.md와 ARCHITECTURE_CHECKLIST.md를 직접 읽고
  절차대로 수행하면 된다

## 배포

```bash
git push origin main
claude plugin marketplace update 0tak   # 각 PC
```

진행 중인 차수가 있는 프로젝트는 업그레이드 후 `validate`를 돌리고 **경고까지** 읽는다.
