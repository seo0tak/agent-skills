# HANDOFF — 개발 세션 인수인계 (2026-09-09, v1.12.1 / v0.4.1)

새 세션은 이 문서와 저장소 루트 README.md, CLAUDE.md(저장소 규약)를 읽으면
이어서 작업할 수 있다. 원리는 `skills/sast-remediation/toolkit/docs/HOW_IT_WORKS.md`,
버전·호환 규칙은 같은 곳의 `docs/VERSIONING.md`.

## 최신 작업 기준 (2026-09-09 문구 교정)

- 배포 파일 버전: sast-remediation **v1.12.1**, skill-architect **v0.4.1**.
  문구 교정 브랜치: `codex/editorial-copy-polish`.
  직전 구현 커밋 `0e21db3`은 main에 반영·푸시된 상태에서 시작했다.
  이번 교정은 사용자 요청에 따라 검증 후 main 반영·푸시하는 범위다.
  실제 원격 반영 상태는 `git log`와 `git ls-remote origin refs/heads/main`으로 확인한다.
  설치본 갱신은 별도이며, 마지막 설치 확인 버전 1.10.1/0.2.1과 구분한다.
- 문구 교정의 변경 범위와 검증 결과:
  `docs/reviews/2026-09-09-editorial-copy-polish.md`.
  아래 1.12.0/0.4.0 테스트 수는 이전 구현 당시 기록이다.
- 저장소는 **`seo0tak/agent-skills`** (claude-skills에서 개명, 로컬 디렉터리도
  `~/Project/Source/seo0tak/agent-skills`). 마켓플레이스 name **`0tak`**.
  이 PC에는 Claude Code·Codex 양쪽에 `sast-remediation@0tak`,
  `skill-architect@0tak`이 GitHub 소스로 설치돼 있다. 진행 프로젝트의
  업그레이드·입력 승인 재확인 절차는 새 버전 `docs/VERSIONING.md`를 따른다.
- 실제 Sparrow 보고서로 검증된 마지막 버전은 **1.6.x**. 이후 변경은 단위
  테스트와 합성 오류 주입으로 검증했고 실제 업무 차수는 아직 실행하지 않았다 (아래 미결 3).
  1.11의 기본 회귀는 Python 43건·Node 29건이었다. 1.12 최종 정본 테스트는
  151개(SAST 82·Architect 24·브라우저 44·패키징 1) 모두 통과했다.
  배포 사본 브라우저 44개도 별도로 통과했고 정본·사본과 버전 일치를 확인했다.
  독립 리뷰 후 수정·재검증 결과와 한계는
  `docs/reviews/2026-09-09-resilient-skills-implementation.md`가 기준이다.
  실제 HTML 열기는 브라우저 로컬 파일 URL 정책에 차단돼 렌더링·반응형
  실측·스크린리더 검증을 완료한 것으로 보고하지 않는다.
- 실물 파일 위치: `~/Downloads/issues_lheep-comn-frontend-master_1903.xls`(2,361건),
  `..._1903_01.pdf`(1,906p, 분석 ID 1903)

## 1.12.0 / 0.4.0 구현 범위 (당시 기록)

- SAST: 수정 전·후 체크포인트, 검증 직전 소스 스냅샷, 실제 근거와 연결,
  읽기 전용 status와 복구 미리보기/--apply, 협조 잠금·고유 임시 파일 쓰기.
- 브라우저: 상태+상세 초안 저장/백업, 정본 반영 대기와 저장 실패 구분,
  정확한 가져오기 건수, 읽기 쉬운 결과·코드·좁은 화면 매핑.
- 문서: 입력 조합, 상태 종류, 복구·검증 한계, 권한과 기본안, 이월·제출 규칙 정렬.
- Architect: 선택적 로컬 개선 기록과 재개. 평가·승인 참조·적용·회귀 검증을 연결한다.
  기록 도구는 실제 권한을 인증하거나 명령·패치·배포를 실행하지 않는다.
- 당시 범위에 포함하지 않은 작업: 자동 재시작·네트워크 감시·무승인 자체 수정·배포,
  설치본/프로젝트 복사본 업그레이드, commit/push. 이후 커밋·푸시 상태는 위 최신 기준을 따른다.
- 상세 계획과 진행 기록: `docs/superpowers/specs/2026-09-09-resilient-skills-design.md`,
  `docs/superpowers/plans/2026-09-09-resilient-skills.md`.

## 버전별 주요 이력 (당시 기록; 현재 규칙은 현행 가이드 기준)

| 버전 | 내용 |
|---|---|
| 1.1.x | SARIF 입력 모드, 실물 Sparrow 검증(위험도 5등급 매핑), 분할 PDF, 건수불일치 지침 |
| 1.2.x | input/<세트명>/ 폴더 세트(--input-set), 프로젝트 일치 구체검증, 대시보드 부팅 시 결과 자동반영 |
| 1.3.0 | 그룹 대표 가이드+멤버 delta, 07-resume, verification.method, evidence-columns, Grill 상시화 |
| 1.4.0 | 대시보드 페이지네이션·언어 필터·검색 디바운스, docs/HOW_IT_WORKS.md |
| 1.5.x | 모델 티어 서브에이전트(bulk-worker=haiku, remediator=sonnet), stableKey, 원자 쓰기, 깨진 파일 지목 |
| 1.6.x | 연속 실행 모드(중단조건 5개)+정책 질문 파킹, OKF 부분채택, docs/VERSIONING.md |
| 1.7.0 | schemaVersion 검사 커버리지 — SCHEMA_VERSION 상수, 레코드류 경고 검사, 스키마↔검증기 const 교차검증 |
| 1.8.0 | 정책 확인이 어려운 상황의 질문·보류 절차 보강 — 소스 밖 근거 수집, 업무 사실 질문, "모르겠다" 선택지, 미확인 시 동작 보존 기본안과 관찰 방법, 결정 주체, checker plainDescription (원리 9) |
| 1.9.0 | skill-architect 감사 결과 적용 — `data/decisions.json` 정본+DECISION_LOG.md 생성, validate가 미확인 결정의 관찰 장치 강제, `query` 명령(원리 10), `tools/test_toolkit.py` 22건, USAGE.html을 USAGE.md에서 생성 |
| 1.10.0 | `report.vendorAttributes` — 정의 모르는 벤더 컬럼 원문 보존, A.S 조사 결과 반영 |
| 1.10.1 / 0.2.1 | 멀티 에이전트 재편(기능 무변경, 패치) — 정본 `skills/` 승격, SKILL.md 중립화(`${CLAUDE_SKILL_DIR}` 제거) |
| 1.11.0 / 0.3.0 | 전체 입력 SHA-256 manifest, 결과 유실/필수 필드/null 감사/경량 참조 검사, 백업 격리·시각·코드 diff 보존, 목록·키보드·저장 안내 개선. Architect는 근거 수준/미확인/조건별 적용/로컬 지식 규약 보강 |
| 1.12.0 / 0.4.0 | 수동 재개·소스 검증 연결·상세 초안 보존·가독성 정리. Architect 선택적 승인 범위 개선 기록. 자동 실행·배포 없음 |
| 1.12.1 / 0.4.1 | 소개·가이드·요청문·UI·CLI 문구 교정. 입력 조건, 저장·검증·권한 설명과 실제 동작 정렬. 데이터 형식·상태 전이 유지 |

저장소 쪽: marketplace.json에 skill-architect 등록(이전엔 설치 불가였음), version 필드 제거
(plugin.json이 정본), 루트 README를 설치·사용 안내의 시작 문서로 재구성. 이후 **멀티 에이전트 재편**(TASK-multi-agent):
마켓플레이스 name `0tak`, 정본을 루트 `skills/`로 승격하고 `plugins/*/skills`는
`scripts/sync-plugins.sh` 사본(Codex가 심링크를 빈 디렉터리로 복사해 심링크 불가),
Codex 카탈로그 `.agents/plugins/marketplace.json` + `.codex-plugin/plugin.json`,
SKILL.md 중립화. 실측: `npx skills add ./`로 두 스킬 발견·설치(`~/.agents/skills/`),
Claude·Codex 모두 GitHub 소스 설치 확인. 규약은 CLAUDE.md.

## 핵심 설계 원칙 (변경 시 지킬 것)

1. 작업 전 입력 확인 — 전체 입력 목록·크기·SHA-256이 바뀌면 승인 무효. 이전 승인에
   manifest가 없으면 preflight와 의미 대조 후 재승인하며 해시만 덧붙이지 않는다
2. 결과 정본은 security-results. progress는 결과 집계와 결과 없는 임시 상태·비고,
   resume-state는 체크포인트·스냅샷. results만으로 임시 상태를 전부 복구할 수 없다
3. **정본은 JSON, 읽기용은 생성물** — data/*.js, DECISION_LOG.md, USAGE.html은 sync가 만든다.
   직접 편집 금지, 편집은 정본(JSON / USAGE.md)에
4. 오탐/예외/운영설정은 reason+evidenceNote 없으면 validate 에러
5. 검사 차수 사이의 동일 항목 대조에는 fingerprint를, 사용자와 항목을 지칭할 때는 stableKey를 사용한다
6. bulk-worker는 판정·소스 수정·verified 승격 금지. remediator는 승인된 가이드 범위의
   소스 수정·검증을 맡고 최종 결론·verified 승격은 총괄 AI가 판단한다
7. 하위호환 스키마 변경은 선택 필드 추가만 — VERSIONING.md. 메이저 변경 시
   validator·schemas·상태 도구·브라우저 등 모든 생성자와 읽는 도구의 버전 처리를 대조한다
8. **지침·구현·재현을 구분** — 데이터 검사와 의미 판단·실제 검증·사용자 권한은 별개다.
   문서 규칙의 적정 강제 수준은 스킬 목적과 영향에 따라 판단한다
9. 미확인 기본안도 사용자 선택·변경 범위가 필요하다. observation/reviewTrigger
   누락은 validate 오류지만 실제 관찰·권한을 도구가 인증하지는 않는다
10. 대용량 findings.json은 전체를 대화에 넣지 않고 `sast_toolkit.py query`로 필요한 범위를 조회한다

## 미결 사항 (PENDING)

1. **A.S 컬럼** — 실물로 확인한 것: 수용 플래그 **아님**(Y 46건 전부 상태 미확인·담당자
   없음·의견 없음), 위험도 안 바꿈, null 역참조 체커 3종에서만 Y, PDF엔 없음. Y/N 규칙은
   미확정. 현재는 vendorAttributes로 보존만. **Sparrow에 물어볼 것**: "이슈 내보내기 엑셀의
   A.S 컬럼(Y/N) 정의가 무엇인가요? 널 역참조 체커에서만 Y가 나옵니다." 답 오면
   vendorAttributes 값으로 재분류
2. **저장소 안에서 툴킷 명령 실행 금지 가드** — 이전 개발 세션에서 회귀 확인용 `preflight`를 저장소에서
   돌렸다가 로컬 절대 경로가 산출물에 섞여 당시 amend로 되돌렸다. `.gitignore`나 "툴킷 부모가 저장소
   루트면 preflight/init 거부" 가드 검토
3. **1.7~1.12 실제 보고서 검증** — 다음 실전 차수에서 확인할 것: `query --summary`, 결정 로그
   흐름(decisions.json → sync → DECISION_LOG.md), 미확인 결정 validate 에러, 1.8 이전 손으로
   쓴 DECISION_LOG.md 마이그레이션 경고
4. 결정 로그 대시보드 표시 — `data/decisions.js` 미러는 생성되지만 대시보드는 아직 안 읽는다
5. **하네스 중립 문서** — 1.12에서 정리함. Claude 전용 에이전트가 없는 환경은
   메인이 같은 절차를 수행하되 품질·비용·속도 동일성을 주장하지 않는다
6. 동봉된 Claude 전용 역할을 사용할 수 없는 하네스에서 sast-remediation 실전 1회는 미실행
7. (아이디어) README 전체 영문판, SARIF 샘플 examples
8. HTML 실제 브라우저 수동 검증 — 긴 한글 경로, 390/1024/1440px·확대,
   키보드 왕복, 실제 백업 불러오기/다운로드 및 저장 불가 환경.
   상세 결과 초안 저장은 1.12에서 구현했다. 원문 답변 입력창 자체의 장기 저장,
   백업 차이 미리보기·정책 질문 패널·상세 이전/다음 등은 별도 후보다.

## 검증 습관

- 툴킷에서 `python3 -B -m unittest tools.test_toolkit tools.test_sast_state tools.test_usage_renderer`
- 루트에서 `python3 -B -m unittest discover -s skills/skill-architect/scripts -p 'test_*.py'`
  및 `python3 -B -m unittest scripts.test_packaging`
- `python3 tools/sast_toolkit.py validate` (OK + 입력 없음 경고 1건이 정상),
  `node --check assets/checklist.js`
- `node --test tools/test_dashboard.cjs` — 실제 함수/이벤트를 VM에서 실행하는
  저장소·파서·키보드 회귀. 실브라우저 시각/E2E 검증은 별도다
- USAGE.md·decisions.json 수정 후 반드시 `sync` — 안 하면 validate가 생성물 드리프트 에러
- 실물 파일 재현 테스트 (위 xls/pdf)
- 저장소 레벨: `scripts/sync-plugins.sh --check`(정본↔사본), `scripts/check-versions.sh`
  (claude·codex 매니페스트·README 표) — 커밋 전 둘 다 통과
- 설치 경로 검증은 사용자가 설치 테스트를 승인한 별도 작업에서 수행한다.
  기존 설치를 일괄 제거하거나 캐시를 삭제하지 않는다. 이번 작업은 설치하지 않았다.

## 유지보수 주의점

- `marketplace.json`에 version 쓰지 않는다 — plugin.json이 정본, README 표는 수동 갱신
- 문서 변경 후 USAGE.md·USAGE.html·SECURITY_SAST_WORKFLOW·SKILL.md·README 요약이 새 규칙과
  모순되는지 훑는다 (1.8.0에서 세 군데 고쳤음)
- 설계 논의 결과는 HOW_IT_WORKS(왜)와 해당 가이드(어떻게)에 기록한다.
  규칙의 목적과 변경 시 영향을 이해할 수 있도록 근거를 함께 남긴다
- skill-architect는 이 세션 스킬 목록에 없으면 SKILL.md와 ARCHITECTURE_CHECKLIST.md를 직접 읽고
  절차대로 수행하면 된다 (지금은 플러그인으로 설치돼 있어 스킬 목록에 뜬다)
- 스킬 편집은 `skills/`에서만. `plugins/*/skills`를 고치면 다음 sync에 덮인다
- 배포 사본에 심링크를 쓰지 않는다 — 당시 Codex CLI 설치에서 빈 디렉터리로 복사됨을 확인했다.
  Claude Code의 설치 결과만으로 Codex 설치 호환성을 판단하지 않는다
- `.codex-plugin/plugin.json`에도 version이 있다. 올릴 때 check-versions.sh
- Claude Code 메모리 디렉터리는 경로 키라 디렉터리를 옮기면 `~/.claude/projects/<경로키>/memory`도 옮긴다

## 배포 (별도 사용자 요청이 있을 때만)

아래는 참고 명령이다. 현재 브랜치의 검토·커밋·통합 방식을 먼저 정하며,
이 문서를 읽었다는 이유로 main push나 설치를 실행하지 않는다.

```bash
scripts/sync-plugins.sh --check && scripts/check-versions.sh
git push origin main
claude plugin marketplace update 0tak     # Claude Code
claude plugin update sast-remediation@0tak --scope user
claude plugin update skill-architect@0tak --scope user
codex plugin marketplace upgrade 0tak     # Codex 카탈로그 갱신
codex plugin list                         # 설치 버전 확인, 필요 시 앱/CLI 설치본 갱신
npx skills add seo0tak/agent-skills       # 범용 (재실행)
```

Claude는 실제 설치 scope를 사용하고 재시작 또는 지원되는 `/reload-plugins`로
반영한다. Codex도 카탈로그 갱신을 설치 캐시 갱신 완료로 가정하지 않는다.
진행 중 프로젝트는 새 설치본의 `docs/VERSIONING.md` 자산 정책을 적용한 뒤
`validate`를 돌리고 **경고까지** 읽는다. 설치본 갱신만으로 프로젝트 복사본은
자동 교체되지 않는다.
