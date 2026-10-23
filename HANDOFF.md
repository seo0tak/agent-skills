# HANDOFF — 개발 세션 인수인계 (2026-10-23, sast-remediation v1.18.2 / skill-architect v0.5.3 / security-assessment v0.12.0)

새 세션은 이 문서와 저장소 루트 README.md, CLAUDE.md(저장소 규약)를 읽으면
이어서 작업할 수 있다. 원리는 `skills/sast-remediation/toolkit/docs/HOW_IT_WORKS.md`,
버전·호환 규칙은 같은 곳의 `docs/VERSIONING.md`.

## 최신 작업 기준 (2026-10-23)

배포 버전: sast-remediation **v1.18.2**, skill-architect **v0.5.3**, security-assessment **v0.12.0**.
최신 커밋은 `git log -1`로 확인. 이 문서를 갱신한 시점까지 전부 push 완료(`f27722b`).

### 남은 일

- security-assessment 계획(M0~M5)은 끝났다. 남은 것:
  - 인증이 필요한 웹 스캔, 네트워크·호스트 스캔: 자격증명·트래픽·침습성 규칙을 따로 설계해야 한다.
  - 실제 스캐너 출력 검증: nuclei·ZAP·Prowler·Checkov의 예시 출력은 형식에 맞춘 표본이다. 출력 구조와
    파일 이름(`output_file`)을 실제 버전으로 확인해야 한다. 실제 대상에 요청을 보내는 확인은 사용자가
    인가한 대상·계정에서만 한다.
- sast-remediation 진행률 패널:
  - 1.18.1은 사용자 Windows 화면에서 확인됨(체커 탭 집계 스크립트, 머리 띠, 지금 탭 알약). 1.18.2 반응형은
    패널을 넓히고 좁혀 보는 화면 확인이 아직이다.
  - 설치본으로 불러오는 확인과 Codex 설치본이 `hooks/`를 무시하는지는 아직이다 — 설치 시험은 실제
    마켓플레이스 이름(0tak)으로 하지 말 것(메모리 규칙).
  - 체커 집계 스크립트는 턴마다 findings.json 전체를 읽는다. 검출이 수만 건이면 느려질 수 있어 필요하면
    캐시(파일 수정 시각 기준)를 검토.

### security-assessment (v0.12.0, M0~M5 완료)

- 인가 기반 오케스트레이터. 기성 스캐너를 조율하고 검출을 묶어 판정·증적을 만들며, 공격 코드·페이로드·
  시험 절차를 만들지 않는다. 인가 게이트는 선언 범위 밖 실수를 막고 인가 주장을 기록하지만 동의 진위는
  검증하지 못한다(SKILL.md 명시). 설계 정본: `CONTEXT.md`, `docs/adr/0001~0005`, 계획
  `docs/superpowers/plans/2026-10-14-security-assessment.md`.
- 단계: M0 게이트(0.1.0) → M1 어댑터·수집·묶음·정규화(0.2~0.4) → M2 판정·SARIF 다리·증적(0.5~0.7) →
  기준 점검 결함 1~4(0.8.0) → 개선 5: 판정 주체·판정 프롬프트·`ingest`(0.9.0) → M3 웹(0.10.0) →
  M4 IaC·클라우드(0.11.0) → M5 방법론 체크리스트(0.12.0). 각 단계 앞에 설계 점검을 하고 결정은 모두
  사용자가 고른 권장안이다.
- 데이터 흐름: `data/scope.json`(인가) → `scan`(직접) 또는 `ingest`(운영자 출력) → `data/scans/<어댑터>.json`
  → `data/findings.json`(묶음, 제외 자산 뺌) → `data/dispositions.json`(판정·확인 단계·주체) → `bridge` →
  `data/handoff.sarif`(confirmed 코드 결함만) / `evidence` → `evidence/findings.csv`·`cover.md`·
  `checklist.csv`(생성물, 드리프트는 validate 에러). `new-round`가 차수를 닫고, 해소는 같은 어댑터 재실행
  (웹·클라우드는 커버리지까지)으로만 인정한다.
- 판정 주체(ADR 없음, 0.9.0): false-positive·out-of-scope를 reviewed로 확정하는 것은 user만.
- M3 웹(ADR 0003): 어댑터 `scope_control`·`rate_limit`·`coverage`·`max_seconds`, 스코프 웹 대상 `rateLimit`,
  `scan --direct`는 계획과 확인 코드만 내고 `--confirm <코드>`일 때 실행, 넘길 수 없는 제외 자산이 걸린 대상은
  실행·들여오기 거부, URL 지문(메서드·정규화 경로·파라미터 이름), ZAP 정규화기, 컨테이너 출력 자리표시.
- M4 인프라(ADR 0004): infra 대상 `aws:<계정>` + `regions` + `credential`(프로파일 이름·읽기 전용 확인, 비밀값
  거부), `cloud` 카테고리와 `cloud_args`, 출력이 다른 계정·허용 밖 리전을 읽었으면 버리거나 거부, Prowler
  정규화기, iac·cloud는 CWE가 없으면 통제 항목·점검 ID로 묶음, 기준별 통과·실패·수동(제외 자산 뺌) →
  표지 「기준 대조」, 클라우드 설정 결함은 넘기지 않음.
- M5 체크리스트(ADR 0005): 점검 기록 장부. 기준 파일 `checklists/<이름>.json`(시험 단계 필드 거부),
  `data/checklist.json` 상태·근거, 범위 밖은 계산, 확정은 user + reason(issue-found는 evidence), 어댑터
  `checklist_items`로 스캔 제안만, 표지 표와 `evidence/checklist.csv`.
- 프롬프트: `00-authorize`, `01-triage`, `02-web-scan`, `03-cloud-scan`, `04-checklist`.
- 툴킷 원본 상태에서 `validate`는 빈 템플릿 `scope.json` 때문에 에러 7건이 정상이다.
- 업그레이드 주의는 `toolkit/docs/VERSIONING.md`(0.9.0 증적 열 추가, 0.11.0 iac 묶음 키 변경 등).

### sast-remediation 진행률 패널 (v1.18.2, Claude Code 전용)

- 위치: `plugins/sast-remediation/hooks/register.tsx`(+ `hooks.json`, `types/index.d.ts`, `tests/pane.test.tsx`).
  `skills/` 정본이 아니라 플러그인 쪽이 원본(agents/와 같은 위치). mod API는 Claude Code 미리 보기 기능.
  타입 정의는 plugin-authoring 스킬의 `types/claude-code.d.ts`(Image·Raster·Box backgroundColor 등 확인 가능).
- 열리는 조건: 프로젝트에 `sast-remediation-toolkit/`이 있으면 세션 시작 시, 없으면 이 스킬이 실행될 때
  (`skill.prompt`). 그 전에는 패널·상태 줄 모두 없음. `/sast-progress`로 즉시 열기·새로 고침. 높이 22줄.
- 지금 화면(E안 = 띠 머리 + 아이콘, 사용자 선택. 시안 B·C·D·E는 설계안 아티팩트 KdE2ACe1hwuh83NghDPTEL):
  - 머리 띠: `Box backgroundColor="suggestion"` 안 Text 한 줄 `🔍 SAST 진행률   68%  15 / 22`(왼쪽 정렬 — 오른쪽
    정렬은 Windows에서 잘렸다).
  - 요약: `🎯 처리 범위  위험도 … 이상, 남음 N, 📦 전체 a / b`, 작업 단계 칸 막대(전체 기준), 아이콘 범례
    `✅ 29 검증 완료` 등(📥 시작 전 · ⏳ 작업 중 · 🔎 분석 · 🔧 수정 완료 · ✅ 검증 완료 · 💤 보류).
  - 탭: 지금 탭은 반전 Text 알약(` 1 📋 체커 `), 나머지는 Button(단축키 2·3). 버튼으로 두면 단축키 색이 띠
    색과 같아 묻혔다.
  - 체커: 한 줄씩 `🔴 CODE  [칸 막대]  남음 N  검증/전체`, 신호등 🔴 5건 이상 · 🟠 3~4 · 🟡 1~2 · 🟢 0. 비면 안내 문구.
  - 토큰·범위 탭은 줄마다 아이콘(🧠 💰 📨 📚 🔁 ⌛ 📅 🎯), 범위 밖 위험도 줄은 들여쓰기만.
  - 바닥 줄: `🧠 ctx 7%   💰 $0.74   🕒 17:42 갱신`(2분 넘으면 오래됨).
  - 반응형(1.18.2): `bodyColumns`·`bodyRows`로 그리고, 크기가 바뀌면 엔진이 다시 그린다. 단계 막대는 폭 전체,
    체커 목록은 높이 - 12줄. 체커 줄은 50칸 미만이면 막대·검증/전체 없음, 보통은 이름 26칸, 90칸 이상이면 44칸,
    막대는 남는 폭(최대 40). 숫자 열은 오른쪽 맞춤. 사용자 Windows 화면에서 1.18.1 체커 탭이 정상으로 나온 것 확인.
  - 데스크톱·VS Code·모바일은 같은 배치에 링·막대를 Svg로. 상태 줄 `SAST 15/22 범위, 29/48 전체 | ctx 41% | $18.42`.
- 터미널 규칙(1.17.4에서 배운 것): 화면 종류는 `e.surface`로 가른다(`$.ui.resolve`가 터미널에도 Svg를 빈 조각으로
  채움). 폭이 모호한 문자(·, ●, █, │, 상자 테두리, ⚠ ⏸ ★, FE0F가 필요한 이모지)와 borderStyle을 쓰지 않는다 —
  한글 글꼴 터미널이 두 칸으로 그려 줄이 잘린다. 아이콘은 Emoji_Presentation 문자만(항상 두 칸), 아이콘 뒤 한 칸.
  막대는 backgroundColor 칠한 빈칸. 테스트가 터미널 트리를 검사한다.
- 데이터: `query --summary`(처리 범위가 있으면 `--scope in-scope`도)를 읽기만 한다. 요약에 `byChecker`가 없는
  옛 툴킷(1.15.0 이전)은 `python -c CHECKER_COUNT_SCRIPT`로 findings.json·progress.json을 읽어 체커별만 출력한다
  (`query` 전체 행은 검출 수천 건에서 4 MiB 출력 한도를 넘어 잘렸다, 1.18.1). 파이썬은 `python3` → `python` →
  `py -3` 순(Windows Store 바로가기 대응).
- 이력: 1.17.0 패널 → 1.17.1 요약 카드+탭(A안) → 1.17.3 Windows 파이썬 → 1.17.4 터미널 잘림 → 1.17.5 체커 대안 →
  1.18.0 E안 → 1.18.1 큰 프로젝트 체커·띠·탭 대비 → 1.18.2 반응형. 자세한 건 `toolkit/docs/VERSIONING.md`.
- 확인: `claude plugin validate plugins/sast-remediation`, `claude plugin test plugins/sast-remediation`(9건),
  타입 검사(엔진이 타입을 깔기 전에는 스크래치 tsconfig로 plugin-authoring 타입 + hooks + types를 묶어 tsc).

### 문서와 다이어그램 체계

- README는 스킬 수·범주에 독립적(유형 열 보안/메타, 버전은 마지막 칸, 스킬별 관련 문서).
  루트 README에는 그림을 두지 않는다. 사용자 문서에는 대화·날짜·개발 단계 표시를 넣지 않는다
  (CLAUDE.md 문서 규칙). skill-architect는 감사 도구가 아니라 "스킬 설계 기준"(0.5.0).
- 도구(사용자 선택, `296c0e9`): 흐름도는 README 안 mermaid, 구조도는 D2, 시퀀스·상태도는
  PlantUML. D2·PlantUML 원본은 각 스킬 `docs/diagrams/*.d2|*.puml`, SVG를 함께 커밋.
- 현재 그림:

| 스킬 | 흐름도 (README) | 구조도 (HOW_IT_WORKS) | 시퀀스·상태도 |
|---|---|---|---|
| sast-remediation | 승인 지점을 "사용자:"로 표시 | 위→아래 dagre, 1171px | HOW_IT_WORKS 시퀀스, ACTIVITY_LOG 기록 순서 |
| security-assessment | 사용자 단계·확정 복귀·new-round 고리 | 세 줄(인가와 수집 / 검출과 판정 / 넘김과 증적), 1578px | HOW_IT_WORKS 시퀀스(직접·운영자 실행 분기) |
| skill-architect | 세 갈래(새 스킬·점검·개선 이력) | ELK 좌→우, 1473px | improvement-workflow.md 상태도 |

- 규칙(CLAUDE.md): 승인 지점이 있는 스킬은 HOW_IT_WORKS에 시퀀스, 순서·상태 전이가 핵심인 절차
  문서는 그 문서에 시퀀스·상태도. 동작을 바꾸면 흐름도·시퀀스·구조도·USAGE 텍스트 흐름이 같은
  순서와 승인 지점을 보이는지 함께 대조한다.
- `scripts/render_diagrams.py`가 SVG를 만들고 끝에 원본 해시를 남긴다. `--check`는 도구 없이
  해시만 비교하며 `scripts.test_packaging`에 포함. d2가 빼먹는 루트 width/height를 viewBox로
  채운다. 원본에 `vars.d2-config.layout-engine`이 있으면 그 엔진, 없으면 ELK.
- d2·plantuml은 이 컴퓨터에 **설치되어 있지 않다**(세션 임시 폴더에 받아 썼음). 그림을 고치려면
  `brew install d2 plantuml` 또는 `D2`·`PLANTUML_JAR`·`JAVA` 환경 변수로 경로를 준다. PlantUML은
  Java 8에서 실패했고 Homebrew openjdk(25)로 돌렸다.
- 시인성 기준: GitHub 본문 폭은 약 1000px. 구조도가 2000px를 넘으면 글자가 절반 이하로 줄어
  읽기 어렵다(처음 2200~2400px였던 것을 위 배치로 줄임). D2의 컨테이너별 direction은 TALA에서만
  먹으므로 줄 나누기는 `grid-rows`, 긴 체인은 병렬 경로로 단계 수를 줄인다.
- 이미지는 `[![..](x.svg)](x.svg?raw=true)`로 감싸 누르면 raw 원본 크기로 열린다(GitHub 기본 링크는
  작은 미리보기 페이지로 감). 넓은 구조도 아래에 "이미지를 누르면 원래 크기로 열립니다" 안내.
- sast-remediation 흐름도는 D2 `docs/diagrams/flow.d2` 하나로 README와 USAGE가 같이 쓴다(1.16.0). USAGE
  렌더러(`tools/usage_renderer.py`)가 툴킷 안 상대 경로 .svg/.png 이미지만 그리도록 확장했다(원격·
  절대·`..` 거부, 테스트 포함). 텍스트 화살표 흐름은 없앴다. 나머지 두 스킬 흐름도는 README mermaid.
- PlantUML 메시지의 `--a ... --b`는 취소선이 된다. 옵션은 `~--`로 이스케이프한다.
- 마지막 점검(`3a80baa` push 후): 마크다운 93개 파일의 링크·이미지 48개 깨짐 없음, Mermaid 3개
  렌더 오류 없음, GitHub에서 그림 6개 로드 확인(넓은 화면 시인성은 로컬 1000px 렌더로 확인).
- 시인성 재점검(1.17.2·0.11.1·0.5.3): Mermaid 자동 줄바꿈이 단어 중간을 끊던 라벨을 `<br/>`로 나눴다.
  검사는 렌더 후 라벨별 줄 수가 `<br/>` 수+1을 넘는지 센다. 코드 블록 안 100칸 넘는 명령은 `\` 줄 이음으로
  나눴고, USAGE.html `pre`는 좁은 화면에서 접힌다. 규칙은 CLAUDE.md 문서 규칙에 있다.

## 이전 작업 기준 (2026-10-14 체커별 진행)

- 배포 버전은 sast-remediation **v1.15.0**, skill-architect **v0.4.3**이다.
  1.15.0은 대시보드 "분포 및 추천 작업 보기" 안에 "체커별 진행" 패널과
  `query --summary`의 `byChecker` 집계를 더했다. 완료=workflowStatus `verified`만,
  보류(deferred)는 남음에 포함해 따로 표시, 비율은 내림(1건이라도 남으면 100% 아님),
  현재 필터 기준, 체커 이름 클릭 시 체커 필터 연동. 작업 커밋 `a5b7c5b`(main),
  `290e8af..a5b7c5b` 푸시 완료. 새 테스트 4건(node 3·python 1), 전체 재검증 통과.
  아래는 그 이전 작업(사용자 작업 이력 분리) 기록이다.
  기본 작업 이력은 작업·상태 변화 중심으로 표시하고, 내부 처리는 접힌 시스템
  운영 기록, 원본 기술 정보는 행별 진단 상세로 제공한다. 항목 상세도 같은 구조다.
  시작점은 `6c2b08f`, 작업 브랜치는 `codex/activity-audience-views`다.
  구현 커밋 `9e2d122`의 main 병합·전체 재검증·푸시와 원격 SHA 일치를 확인했다.
  이후 완료 기록만 갱신하며 최종 상태는 Git 기록으로 확인한다.
- 원본 이벤트·백업·스키마·저장 명령은 유지한다. 별도 디버그 수집·외부 전송·
  자동 삭제는 추가하지 않는다. 이 분류는 접근 통제가 아닌 조회 방식이다.
  설치본·고객 소스·프로젝트 툴킷 갱신은 사용자가 별도로 진행한다.
- 같은 작업의 시작·종료·재시도를 묶되 시도별 결과를 보존한다. 종료 미확인은
  별도로 남기며 과거 완료가 이를 숨기지 않는다. 시작·종료에 공통인 필드만
  전후 변화로 표시하고 한쪽에만 있는 값은 해당 시점의 관측으로 표시한다.
  단순 상태 변경과 실제 수정, 명령 성공과 검증 완료를 구분한다.
- 중요한 정본 변경은 의미 있는 필드로 판별한다. 기준 관측·해시·시각만의 변화는
  시스템 기록에 남기고 분류가 불명확한 옛 기록도 삭제하지 않는다.
- 정본 288개(SAST Python 134, Node 129, Architect 24, 패키징 1), 배포 사본
  263개(Python 134, Node 129) 검사와 독립 재검토가 통과했다. 합성 입력 실제
  브라우저 1440/390px, 사용자·시스템 필터 독립성, 전후 표시·재시도·종료 미확인,
  키보드·내부 스크롤, 저장·새로고침 후 이력 보존을 확인했다.
- 사용 계약: `skills/sast-remediation/toolkit/docs/ACTIVITY_LOG.md`.
  근거와 한계: `docs/reviews/2026-09-15-activity-audience-views.md`.

## 이전 작업 기준 (2026-09-15 누적 작업 이력)

- 배포 버전은 sast-remediation **v1.14.0**, skill-architect **v0.4.3**이다.
  기존 상태 정본과 별도로 시작·종료·실패·차단·중단·재시도·변경 관측을
  누적 보존하며 체크리스트의 전체/항목별 작업 로그에서 확인한다.
  작업 브랜치는 `codex/durable-activity-log`, 시작점은 `37f4abf`다.
  구현 커밋 `7cd250c`의 main 병합·재검증·푸시와 원격 SHA 일치를 확인했다.
  이후 완료 기록만 갱신하며 최종 상태는 Git 기록으로 확인한다.
- `data/activity/YYYY-MM/<eventId>.json`이 파일 이력 정본이고,
  `data/activity.js`는 생성물이다. 브라우저 이력은 상태+결과 백업의 선택 필드
  `activityEvents`로 보존한다. 가져오기는 이력 보관이지 결과 반영이나 승인·검증이 아니다.
- 시작만 남은 시도는 **종료 미확인**이다. 강제 종료 원인·시각이나 현재 실행 여부를
  추측하지 않는다. 재개 시 현재 소스·근거·작업자와 대조한다. 외부 소스 수정·
  테스트는 명시적 start/finish가 필요하며 모든 프로세스를 감시하는 기능은 아니다.
- 초기화된 프로젝트 또는 명시적으로 기록을 시작한 툴킷에서 변경 명령을 자동
  기록한다. 미초기화 배포물 검사로 실제 로그를 만들지 않는다. 기록 저장 실패는
  완료 보고를 막고 이미 적용된 변경 여부를 확인한다. 로그는 자동 삭제하지 않는다.
- 사용 계약: `skills/sast-remediation/toolkit/docs/ACTIVITY_LOG.md`.
  검토·검증 기록: `docs/reviews/2026-09-15-durable-activity-log.md`.
  설치본과 고객 소스·복사된 툴킷은 이번 범위에 포함하지 않는다.
- 정본 269개(SAST Python 134, Node 110, Architect 24, 패키징 1), 배포 사본
  244개(Python 134, Node 110) 검사를 통과했다. 독립 리뷰의 관측 기준 위조·
  작업 ID 혼합·복구 경로의 검사 누락을 수정·재검토했고, 합성 입력의 실제 브라우저 1440/390px,
  백업 재가져오기·잘못된 이력 거절·키보드 스크롤을 확인했다.

## 이전 작업 기준 (2026-09-15 위험도 처리 범위)

- 배포 파일 버전은 sast-remediation **v1.13.0**, skill-architect **v0.4.3**이다.
  사용자 승인에 따라 5단계 위험도의 최소 처리 등급을 선택·저장하는 기능을
  추가했다. 작업 브랜치는 `codex/risk-processing-scope`, 시작점은 `98f50d5`다.
  통합·푸시 대상은 main이며 실제 원격 반영은 Git 기록으로 확인한다.
- `data/project-profile.json.processingScope`가 차수별 범위 정본이다. 전체
  입력과 상태를 보존하고 선택 범위만 상세 분석·조치·검증한다. `unknown`은
  별도 미확인, `info`는 5단계 밖 안내로 범위 밖에 남긴다. 기존 프로젝트의
  미설정 범위를 자동으로 전체 처리로 해석하지 않는다.
- HTML의 위험도 필터와 처리 범위는 별개다. 선택·요청 복사는 저장이 아니며
  AI의 범위 설정 명령과 sync 후 새로고침해야 적용된다. 추천·AI 요청·새 작업
  시작·재개 후보·완료 집계에서 같은 범위를 사용한다.
- 범위 밖 기존 수정과 복구 후보는 보존한다. 범위 기록이 손상돼도 status는
  전체 복구 진단을 반환하고 선택 실행은 차단한다. 소스 변경으로 오래된 검증은
  범위 설정·조회·sync를 막지 않지만 경고로 남고 validate에서는 오류다.
  선택 범위 완료와 전체 완료·제출 승인을 구분한다.
- 설치본과 고객 프로젝트 소스·복사된 툴킷은 변경하지 않았다. 지난 설치 확인은
  2026-09-11의 **1.12.4 / 0.4.3**이며 이번 저장소 배포 버전과 구분한다.
- 사용 계약: `skills/sast-remediation/toolkit/docs/PROCESSING_SCOPE.md`.
  검토·검증 기록: `docs/reviews/2026-09-15-risk-processing-scope.md`.
- 정본 테스트 210개(SAST Python 104, Node 81, Architect 24, 패키징 1)와
  배포 사본 Node 81개를 통과했다. 독립 재검토와 합성 입력의 실제 브라우저
  980px·390px 배치·요청 복사·필터 독립 동작 확인을 완료했다.

## 이전 작업 기준 (2026-09-11 판정·작업 상태 분리)

- 로컬 배포 파일 버전: sast-remediation **v1.12.4**, skill-architect **v0.4.3**.
  사용자 요청에 따라 두 스킬의 판정 기준·응답 추출·예시·검토 기준을 보강한다.
  고객 소스 수정, 검사 범위의 적절성 판단, 프로젝트 복사본 갱신은 제외한다.
  구현 검증 후 사용자 승인에 따라 구현 커밋 `564de68`의 main 푸시를 확인했다.
  Claude Code·Codex의 `0tak` 설치본도 각각 **1.12.4 / 0.4.3**으로 갱신했다.
  설치 목록과 배포 대상 파일 186개(두 실행 환경 합계)의 내용 일치를 확인했다.
  새 지침 사용 시 Claude Code는 재시작하고 Codex는 새 세션을 연다.
- JSON 형식·enum은 유지한다. 규칙의 적용 여부·현재 영향·조치 필요성은 기존
  근거 필드에 구분해 쓰고, 결론과 실제 작업 단계를 독립적으로 기록한다.
  `작업 상태:`가 없는 답변의 새 추출은 analyzed이며, fix만으로 변경 완료가
  되지 않는다. 오탐과 승인된 예방 수정 완료는 함께 기록할 수 있다.
- 부정문·모호하거나 중복된 결론/상태는 추출하지 않는다. 텍스트를 붙여넣는
  것만으로 verified를 만들지 않고 기존 JSON 결과를 자동 재분류하지 않는다.
- 위 배포 확인은 2026-09-11 시점의 기록이다. 이후 실제 반영 여부는 Git 상태와
  설치된 버전에서 다시 확인한다. 아래 이전 작업의 승인·검증 결과를 새로운
  작업의 권한이나 검증 근거로 재사용하지 않는다.
- 검증: 정본 테스트 176개(SAST Python 83, Architect 24, 패키징 1, Node 68),
  배포 사본 Node 68개 통과. 실제 브라우저에서는 합성 입력으로 새 파서의
  상태·거부·새로고침 동작을 확인했다. 상세 범위·한계는
  `docs/reviews/2026-09-11-judgment-and-action-separation.md`를 따른다.

## 이전 작업 기준 (2026-09-10 추천 목록 스크롤)

- 배포 파일 버전: sast-remediation **v1.12.3**, skill-architect **v0.4.2**.
  작업 브랜치: `codex/recommendation-list-scroll`.
  직전 소스 탐색 지침 커밋 `f065d76`은 main에 반영·푸시된 상태에서 시작했다.
  이번 변경은 사용자 요청에 따라 검증 후 main 반영·푸시하는 범위다.
  실제 원격 반영 상태는 `git log`와 `git ls-remote origin refs/heads/main`으로 확인한다.
  설치본 갱신은 별도이며, 마지막 설치 확인 버전 1.10.1/0.2.1과 구분한다.
- 이번 변경의 범위·검증 결과·미확인 사항:
  `docs/reviews/2026-09-10-recommendation-list-scroll.md`.
  이전 소스 탐색 지침 기록은 `docs/reviews/2026-09-09-source-navigation-guidance.md`.
  이전 문구 교정 기록은 `docs/reviews/2026-09-09-editorial-copy-polish.md`.
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
| 1.12.2 / 0.4.2 | 두 스킬의 LSP 가용성·목적별 탐색·대체 절차·참조/진단·재개 시 색인 확인 지침. Sparrow 보고서와 일반 입력 형식의 용어 구분. 데이터 형식·실행 코드 유지 |
| 1.12.3 / 0.4.2 | 추천 목록 최대 높이·내부 스크롤·키보드 접근, 개수 변경 시 처음으로 이동, 재렌더 시 스크롤 위치 유지. Architect·데이터 형식은 변경 없음 |
| 1.12.4 / 0.4.3 | 판정 근거와 실제 작업 상태 분리, 답변 추출의 부정·모호·중복 판정 거부, 오탐과 승인된 예방 수정 병행 안내 |
| 1.13.0 / 0.4.3 | 차수별 위험도 처리 범위, 선택 대상 실행·추천·재개·집계, 범위 밖 상태 보존. 범위 미설정/손상과 오래된 소스 검증의 복구 경계 분리 |
| 1.14.0 / 0.4.3 | 누적 작업·실행·변경 이력, 종료 미확인 진단, 브라우저 이력 보존과 전체/항목별 로그 조회. 기존 결과·상태 정본과 검증 권한 분리 |
| 1.14.1 / 0.4.3 | 사용자 작업 이력·시스템 운영 기록·진단 상세 분리. 시도별 전후 변화·종료 미확인 보존, 조회용 분류와 가독성 개선. 원본 형식·보관 유지 |
| 1.15.0 / 0.4.3 | 체커별 진행 — 대시보드 패널(단계별 막대, 남은 순, 체커 필터 연동)과 `query --summary`의 `byChecker`. 완료=verified만, 보류는 남음에 포함. 데이터 형식 무변경 |

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
11. 의미 기반 소스 탐색은 현재 환경에서 사용 가능한 LSP를 우선한다. 미지원·실패·
    불완전한 색인·정상 조회 0건을 구분하고, 대체 탐색의 한계와 현재 소스 기준을 남긴다.
    문구·설정값에는 텍스트 검색을 사용하며 탐색 도구의 진단을 보안 검증 완료로 보지 않는다
12. 처리 범위는 전체 입력을 잘라내는 기준이 아니다. 범위 밖 상태는 그대로 남기고,
    상세 실행에는 `query --scope in-scope`를 쓴다. 전체 조회·복구·sync의 성공을
    선택 완료나 검증 신선도로 확대하지 않는다
13. 현재 상태를 갱신해도 누적 이력은 덮어쓰거나 자동 삭제하지 않는다. 종료 미확인과
    실제 실패를 구분하고, 변경 발견 시각을 실제 수정 시각으로 표현하지 않는다

## 미결 사항 (PENDING)

1. **A.S 컬럼** — 실물로 확인한 것: 수용 플래그 **아님**(Y 46건 전부 상태 미확인·담당자
   없음·의견 없음), 위험도 안 바꿈, null 역참조 체커 3종에서만 Y, PDF엔 없음. Y/N 규칙은
   미확정. 현재는 vendorAttributes로 보존만. **Sparrow에 물어볼 것**: "이슈 내보내기 엑셀의
   A.S 컬럼(Y/N) 정의가 무엇인가요? 널 역참조 체커에서만 Y가 나옵니다." 답 오면
   vendorAttributes 값으로 재분류
2. **저장소 안에서 툴킷 명령 실행 금지 가드** — 이전 개발 세션에서 회귀 확인용 `preflight`를 저장소에서
   돌렸다가 로컬 절대 경로가 산출물에 섞여 당시 amend로 되돌렸다. `.gitignore`나 "툴킷 부모가 저장소
   루트면 preflight/init 거부" 가드 검토
3. **1.7~1.14 실제 보고서 검증** — 다음 실전 차수에서 확인할 것: `query --summary`, 결정 로그
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
9. **security-assessment M3 이후** — 웹/인프라 스캐너(M3~M4), 방법론 체크리스트(M5).
   gitleaks(시크릿)는 출력에 실제 시크릿이 담겨 샘플·저장에 주의 필요. scan의
   카테고리→대상은 고정 표(infra 타입은 아직 매핑 카테고리 없음). 어댑터가 대상 타입을
   직접 선언하는 오버라이드는 YAGNI로 보류. 판정 레코드는 단일 파일(원자 쓰기)이라
   검출이 아주 많아지면 sast처럼 항목별 파일을 검토. 실제 스캐너로의 실물 차수 점검은
   아직 없음(합성 샘플·가짜 어댑터로만 검증).

## 검증 습관

- 툴킷에서 `python3 -B -m unittest tools.test_toolkit tools.test_sast_state tools.test_usage_renderer tools.test_activity`
- 루트에서 `python3 -B -m unittest discover -s skills/skill-architect/scripts -p 'test_*.py'`
  및 `python3 -B -m unittest scripts.test_packaging`
- `python3 tools/sast_toolkit.py validate` (OK + 입력 없음 경고 1건이 정상),
  `node --check assets/checklist.js`, `node --check assets/activity.js`
- `node --test tools/test_dashboard.cjs tools/test_activity_dashboard.cjs` — 실제 함수/이벤트를 VM에서 실행하는
  저장소·파서·키보드 회귀. 실브라우저 시각/E2E 검증은 별도다
- USAGE.md·decisions.json 수정 후 반드시 `sync` — 안 하면 validate가 생성물 드리프트 에러
- 실물 파일 재현 테스트 (위 xls/pdf)
- 저장소 레벨: `scripts/sync-plugins.sh --check`(정본↔사본), `scripts/check-versions.sh`
  (claude·codex 매니페스트·README 표) — 커밋 전 둘 다 통과
- 설치 경로 검증은 사용자가 설치 테스트를 승인한 별도 작업에서 수행한다.
  기존 설치를 일괄 제거하거나 캐시를 삭제하지 않는다.
- security-assessment: 툴킷에서 `python3 -B -m unittest tools.test_assess`(108건).
  CLI 왕복은 저장소 밖 임시 사본에서(저장소 안에서 scan·evidence를 돌리지 않는다).
- mermaid를 고치면 브라우저에서 렌더링해 파싱 오류 0을 확인한다(문법 오류가 조용히 남는다).
- 구조도(D2)·시퀀스(PlantUML)는 `docs/diagrams/` 원본을 고치고 `python3 scripts/render_diagrams.py`로
  SVG를 다시 만든다. `--check`(도구 불필요, 원본 해시 비교)는 `scripts.test_packaging`에 포함.
  d2는 SVG 루트 크기를 빼먹어 `<img>`에서 300px로 줄어드므로 스크립트가 viewBox로 채운다.
  D2의 컨테이너별 direction은 TALA에서만 먹으므로, 긴 흐름은 `grid-rows`로 줄을 나눈다.

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
- **사고 기록(2026-10-22)**: 로컬 설치 스모크 테스트를 실제 마켓과 같은 이름 `0tak`으로
  `claude plugin marketplace add ./` 한 뒤 "원복"으로 `marketplace remove 0tak`과
  `~/.claude/plugins/cache/0tak` 삭제를 해서, GitHub 소스로 설치돼 있던 실제 `0tak` 마켓과
  sast-remediation·skill-architect 설치까지 지웠다. 같은 날 재등록·재설치로 복구(현재 최신
  버전). 교훈: 실제 마켓 이름과 겹치는 로컬 테스트를 하지 않는다. 필요하면 먼저 현재 설치
  상태를 기록하고, 사용자 승인 아래 하며, 끝나면 기록과 대조해 되돌린다.
- 문서를 스크립트로 치환할 때는 매번 일치 여부를 assert한다. `str.replace`는 문구가
  어긋나도 조용히 아무것도 안 해서, security-assessment 툴킷 README가 M0 문구로 여러
  마일스톤 남아 있었다(M2c에서 발견·재작성).

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
