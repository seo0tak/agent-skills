# 0tak agent-skills

여러 작업을 돕는 `SKILL.md` 형식 에이전트 스킬 모음입니다. 스킬은 하나씩
늘어나며, 각 스킬의 상세는 그 스킬 디렉터리(`skills/<이름>/`)의 문서에 있습니다.
이 README는 공통 설치·업데이트·구조와 스킬 목록만 다룹니다.

[스킬](#스킬) · [설치](#설치--에이전트별) · [사용 시작](#사용-시작) ·
[업데이트](#설치본-업데이트) · [관련 문서](#관련-문서) · [새 스킬 추가](#새-스킬-추가)

모든 스킬은 `SKILL.md` 형식을 지원하는 에이전트에서 쓸 수 있습니다. 설치 방식과
사용 가능한 도구·전용 에이전트는 환경에 따라 다릅니다. 공통 설계 원칙은
[왜 이렇게 만들었나](#왜-이렇게-만들었나)에 있습니다.

## 스킬

| 스킬 | 유형 | 버전 |
|---|---|---|
| **sast-remediation** | 보안 | 1.17.3 |
| **security-assessment** | 보안 | 0.11.2 |
| **skill-architect** | 메타(스킬 설계 기준) | 0.5.3 |

각 스킬의 작업 흐름과 구조 그림은 [관련 문서](#관련-문서)의 스킬별 문서에 있습니다.

- **sast-remediation** — 기존 SAST 보고서(PDF·스프레드시트 또는 SARIF)의
  검토·조치·검증 근거를 관리합니다. 저장된 기록으로 작업을 수동 재개하고,
  브라우저에서 추출한 결과 초안을 백업할 수 있습니다. 작업·오류·변경 이력을
  누적 보존합니다. 체크리스트는 작업 내용·상태 변화 중심의 이력을 제공하고,
  시스템 운영 기록과 진단 상세를 별도로 조회할 수 있습니다. Claude Code에서는
  채팅 옆 패널에 조치 진행률과 세션 토큰·비용을 보여 줍니다(선택 기능).
- **skill-architect** — 이 저장소의 스킬 설계 기준(트리거·입력·상태·복구·검증 등
  10개 범주)을 제공하고, 그 기준으로 새 스킬을 설계하거나 기존 스킬을 점검합니다.
  요청하면 개선 이력도 남깁니다.
- **security-assessment** — 인가 범위를 선언·검증하고 그 안에서 기성 오픈소스
  스캐너를 조율해 보안 취약점을 점검합니다. 게이트는 선언한 범위를 벗어나는
  실수를 막고 인가 주장을 기록하지만 동의의 진위는 검증하지 않습니다(악의적
  사용자는 막지 못함). 소스·IaC, 웹(비인증·비파괴), 클라우드 계정 설정(읽기 전용)을 점검하며, 인가 게이트부터 스캔
  수집(운영자 실행 출력 포함)·판정·증적 생성, sast-remediation으로의 SARIF 인계까지
  구현되어 있습니다. 웹 스캔은 실행 전에 사용자가 실행 계획을 확인합니다. 오탐·범위 밖 확정은
  사용자가 합니다.

각 스킬의 설치·사용·원리 문서는 [관련 문서](#관련-문서)에 스킬별로 정리되어
있습니다. 편집 기준이 되는 원본(정본)과 플러그인 배포 사본의 위치는 아래
[저장소 구조](#저장소-구조)에 있습니다.

## 설치 — 에이전트별

### 스킬 직접 설치 (Cursor, Grok 등 SKILL.md 지원 에이전트)

현재 프로젝트에 설치하려면 프로젝트 디렉터리에서 실행합니다.

```bash
npx skills add seo0tak/agent-skills
```

설치할 스킬과 대상 에이전트를 선택합니다. 기본 설치 범위는 현재 프로젝트이며,
여러 프로젝트에서 사용할 사용자 범위 설치에는 `-g`를 추가합니다. 실제 경로와
심볼릭 링크/복사 방식은 선택한 에이전트와 설치 방식에 따라 다릅니다.
([skills CLI 설치 범위](https://github.com/vercel-labs/skills#installation-scope))

Grok Build의 기본 스킬 경로는 프로젝트의 `.grok/skills/`와 사용자의
`~/.grok/skills/`입니다. 사용자 경로 `~/.agents/skills/`도 읽습니다.
([Grok 공식 안내](https://docs.x.ai/build/features/skills-plugins-marketplaces))

### Claude Code 플러그인 설치

```bash
claude plugin marketplace add seo0tak/agent-skills
claude plugin install sast-remediation@0tak
claude plugin install skill-architect@0tak
```

세션 안에서는 `/plugin marketplace add`, `/plugin install`을 사용합니다.
`sast-remediation`에는 기계적 파일 작업을 분담하는 `bulk-worker`와
소스 조치를 분담하는 `remediator`가 포함됩니다. 역할별 허용 범위는 각 지침을 따릅니다.

### Codex

```bash
codex plugin marketplace add seo0tak/agent-skills
codex plugin add sast-remediation@0tak
codex plugin add skill-architect@0tak
```

설치 후 새 대화 또는 CLI 세션을 시작하고 설치한 스킬이 표시되는지 확인합니다.
플러그인 설치는 이를 지원하는 앱 또는 CLI에서 진행합니다.
([Codex 플러그인 안내](https://learn.chatgpt.com/docs/plugins))

### 수동 복사 설치

저장소를 로컬에 받은 뒤 저장소 루트에서 실행하는 사용자 범위 설치 예시입니다.
같은 이름의 설치본이 있으면 먼저 기존 설치 위치와 버전을 확인하고 업데이트 방법을
선택하세요. 아래 명령은 같은 이름의 대상이 이미 있으면 복사하지 않습니다.

설치할 스킬 이름마다 아래를 반복합니다(`<이름>`은 [스킬](#스킬) 표의 이름).

```bash
mkdir -p ~/.agents/skills
name=<이름>   # 예: sast-remediation
test ! -e ~/.agents/skills/$name && test ! -L ~/.agents/skills/$name && \
  cp -R skills/$name ~/.agents/skills/
```

이 경로를 읽는 환경에서 사용하고, 설치 후 새 세션에서 인식 여부를 확인합니다.
같은 스킬을 플러그인과 여러 직접 설치 경로에 중복 설치하지 않는 편이 좋습니다.

## 사용 시작

설치한 스킬이 보이고 프로젝트 파일에 접근할 수 있는 세션에서 다음처럼 요청합니다.

**sast-remediation**
- "SAST 결과 조치해줘" (PDF·엑셀 또는 SARIF를 `input/`에 넣으라고 안내)
- "SAST 조치 이어서 해줘" · "이번 차수는 높음 이상만 분석·조치해줘"
- "실패한 검증과 종료 확인이 없는 작업 이력을 보여줘"

**security-assessment**
- "보안 취약점 점검해줘" (먼저 인가 범위를 `scope.json`에 선언하도록 안내)
- "인가 범위 안에서 소스 스캔 돌려줘"
- "운영자가 돌린 결과 파일 들여와서 판정해줘"

**skill-architect**
- "새 스킬을 설계하려는데 기준에 맞춰 같이 봐줘"
- "이 스킬 점검해줘" / "sast-remediation 스킬 감사해줘"

## 설치본 업데이트

카탈로그 갱신과 설치된 플러그인 갱신을 구분합니다. 다음은 Claude Code의
사용자 범위(`--scope user`) 설치 예시입니다. 프로젝트/로컬 범위 설치라면
실제 설치 범위(`project`/`local`)를 사용합니다.

```bash
claude plugin marketplace update 0tak
# 설치한 각 스킬에 대해 반복(아래 스킬 표의 이름):
claude plugin update <이름>@0tak --scope user
```

설치된 버전을 확인하고 Claude Code를 재시작하거나 지원되는
`/reload-plugins`로 반영합니다. 외부 마켓플레이스의 자동 업데이트는 기본
비활성화입니다([공식 안내](https://code.claude.com/docs/en/discover-plugins#configure-auto-updates)).

Codex는 다음 세 단계를 구분합니다.

1. `codex plugin marketplace upgrade 0tak`으로 카탈로그 스냅샷을 갱신합니다.
2. `codex plugin list`로 설치 상태를 확인하고, 앱의 플러그인 관리 화면 또는
   현재 CLI의 설치·업데이트 기능으로 필요한 설치본을 갱신합니다.
   CLI 설치 명령은 `codex plugin add <이름>@0tak`이며 해당 버전의 `--help`를 확인합니다.
3. 설치 버전을 확인한 뒤 새 대화 또는 CLI 세션에서 스킬을 사용합니다.

카탈로그 갱신만으로 설치본 갱신이 끝난 것은 아닙니다.
스킬 직접 설치는 처음 선택한 범위와 에이전트에 맞춰
`npx skills add seo0tak/agent-skills`를 재실행합니다. 사용자 범위라면 `-g`를 유지합니다.

스킬 설치본을 갱신해도 진행 중 프로젝트의 툴킷 복사본은 자동으로 바뀌지
않습니다. 프로젝트를 업그레이드할 때는 **새 설치본**의
[버전·업그레이드 정책](skills/sast-remediation/toolkit/docs/VERSIONING.md#업그레이드-자산-정책)을
먼저 읽고 배포 파일을 교체하되 사용자 변경을 보존하며 필요한 데이터 이전을 수행합니다.

## 왜 이렇게 만들었나

1. **역할 분리** — AI는 승인 범위에서 실행하고 사람은 업무 정책을 결정합니다.
   결과·임시 진행상태·체크포인트·브라우저 초안을 구분해 파일과 백업으로 남깁니다.
2. **검사 범위 명시** — 도구는 형식·상태·입력·소스 연결을 검사합니다.
   실제 검증의 충분성이나 사용자 권한·제출 승인은 별도로 확인합니다.
3. **미확인을 숨기지 않기** — 정책은 업무 사실로 묻고 모르는 내용은 보류하거나
   승인된 관찰 방법으로 확인합니다. 오래된 검증과 현재 검증을 구분합니다.
4. **목적에 맞는 소스 탐색** — 특정 도구가 아니라 탐색의 목표(정의·참조·호출
   관계를 정확히 찾기)를 앞세우고, 현재 환경에서 그에 최적화된 수단을
   우선합니다. 지금 쓰는 수단: 심볼·참조·타입은 사용 가능한 LSP(언어 서버),
   구문 구조의 반복은 AST 도구, 문구·설정값은 텍스트 검색(`rg` 등). 이런
   수단이 없거나 결과가 불완전하면 대체 방법과 확인하지 못한 범위를 남기며,
   도구를 임의로 설치하지 않습니다. 더 나은 탐색 수단이 생기면 같은 원칙으로
   추가합니다.

## 관련 문서

스킬별로 그 디렉터리의 문서를 따릅니다. 새 스킬을 추가하면 여기에 그 스킬의
항목을 더합니다.

**sast-remediation** — `skills/sast-remediation/toolkit/`
- [툴킷 시작하기](skills/sast-remediation/toolkit/README.md) — 설치 없이 복사해 사용, 실행 준비
- [사용 가이드](skills/sast-remediation/toolkit/USAGE.md) — 단계별 사용법, AI 요청 예, 명령어 요약
- [동작 원리와 재개](skills/sast-remediation/toolkit/docs/HOW_IT_WORKS.md) — 저장 정보, 재개, 검증 재사용 한계
- [위험도별 처리 범위](skills/sast-remediation/toolkit/docs/PROCESSING_SCOPE.md) — 위험도 선택, 적용·저장, 범위 밖 관리
- [작업 이력과 실행 로그](skills/sast-remediation/toolkit/docs/ACTIVITY_LOG.md) — 기록 보존, 실패·중단 확인, 이력 백업
- [정책 확인 가이드](skills/sast-remediation/toolkit/SECURITY_GRILL_GUIDE.md) — 업무 사실 중심 정책 확인
- [버전·업그레이드 정책](skills/sast-remediation/toolkit/docs/VERSIONING.md) — 버전·호환, 차수 업그레이드, 마이그레이션

**security-assessment** — `skills/security-assessment/toolkit/`
- [툴킷 시작하기](skills/security-assessment/toolkit/README.md) — 인가 게이트와 현재 구현 범위
- [동작 원리](skills/security-assessment/toolkit/docs/HOW_IT_WORKS.md) — 게이트의 보장·한계, 어댑터 판정, 수집·묶음·정규화
- [인가 절차 프롬프트](skills/security-assessment/toolkit/prompts/00-authorize.md) — 범위 선언과 인가 게이트 통과
- [판정 절차 프롬프트](skills/security-assessment/toolkit/prompts/01-triage.md) — 검출 판정, 판정 주체, 사용자 확인
- [웹 스캔 프롬프트](skills/security-assessment/toolkit/prompts/02-web-scan.md) — 범위 제어, 요청 상한, 실행 계획 확인
- [클라우드 설정 점검 프롬프트](skills/security-assessment/toolkit/prompts/03-cloud-scan.md) — 리전, 자격증명 참조, 기준 대조
- 설계 정본: [CONTEXT.md](CONTEXT.md), [ADR](docs/adr/), [계획·설계](docs/superpowers/plans/2026-10-14-security-assessment.md)

**skill-architect** — `skills/skill-architect/`
- [스킬 설계 기준](skills/skill-architect/ARCHITECTURE_CHECKLIST.md) — 10개 범주와 점검할 때의 판정
- [시작하기](skills/skill-architect/README.md) — 설계·점검·개선 기록 흐름
- [동작 원리](skills/skill-architect/docs/HOW_IT_WORKS.md) — 구성 파일과 개선 기록의 경계

## 개선 기록과 자동화의 경계

skill-architect의 [선택적 개선 기록](skills/skill-architect/references/improvement-workflow.md)은
문제 → 후보 → 평가 → 승인 참조 → 적용 → 회귀 검증을 프로젝트별로 남깁니다.
한 번의 검토만 요청한 경우에는 별도 개선 기록 디렉터리를 만들지 않습니다.
기록 도구는 명령·패치·테스트를 실행하지
않으며 실제 사용자 권한을 부여하거나 인증하지 않습니다.
스킬들은 자동 재시작·네트워크 감시·무승인 자체 수정·배포는 하지 않습니다.

## 저장소 구조

```text
skills/<이름>/                    ← 정본 (에이전트 중립). 편집은 여기서만
plugins/<이름>/                   ← Claude Code / Codex 플러그인 배포 구성
  .claude-plugin/plugin.json      ← 버전 정본
  .codex-plugin/plugin.json       ← Codex 플러그인 정보 파일 (같은 버전)
  skills/<이름>/                  ← 정본의 사본 (scripts/sync-plugins.sh)
  agents/                         ← Claude 전용 서브에이전트
  hooks/ · types/ · tests/        ← Claude Code 전용 화면 확장(mod). sast-remediation 진행률 패널
.claude-plugin/marketplace.json   ← Claude Code 카탈로그 (name: 0tak)
.agents/plugins/marketplace.json  ← Codex 카탈로그
```

버전 기준은 `plugins/<이름>/.claude-plugin/plugin.json`입니다. 버전을 변경하면
Codex 정보 파일과 README 표도 갱신한 뒤 `scripts/check-versions.sh`로 일치를 검사합니다.

## 새 스킬 추가

1. [스킬 설계 기준](skills/skill-architect/ARCHITECTURE_CHECKLIST.md)으로 설계를 정한 뒤
   `skills/<이름>/SKILL.md` 작성 (지원 파일 동봉 가능). skill-architect에 "새 스킬을
   설계하려는데 기준에 맞춰 같이 봐줘"로 요청할 수 있습니다.
2. `plugins/<이름>/.claude-plugin/plugin.json`, `.codex-plugin/plugin.json` 작성
3. `scripts/sync-plugins.sh`로 사본 생성
4. 두 카탈로그(`.claude-plugin/marketplace.json`, `.agents/plugins/marketplace.json`)에 등록
5. `scripts/check-versions.sh`, `scripts/sync-plugins.sh --check` 통과 확인
6. README의 [스킬](#스킬) 표와 [관련 문서](#관련-문서)에 그 스킬 항목을 추가
   (버전 표 행은 `scripts/check-versions.sh`가 강제하고, 문서 항목은 손으로 추가)
7. `skill-architect`로 설계 기준과 대조해 점검
