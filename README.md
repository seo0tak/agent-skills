# 0tak agent-skills

이미 생성된 SAST 검출 결과의 검토·조치·검증·증적 관리를 지원하는
`sast-remediation`과, 에이전트 스킬의 설계와 품질을 검토하는
`skill-architect`를 제공합니다.

두 스킬은 `SKILL.md` 형식으로 작성되었습니다. 이 형식을 지원하는 에이전트에서
사용할 수 있으며, 설치 방식과 사용 가능한 도구·전용 에이전트는 환경에 따라 다릅니다.

`sast-remediation`은 새 취약점을 탐지하는 스캐너가 아닙니다. 기존 보고서와
소스를 대조하고, 오탐 검토·조치·검증 결과와 제출 검토에 필요한 근거를 관리합니다.
정책은 업무 사실을 중심으로 질문하고, 확인하지 못한 사항은 별도로 남깁니다.
도구의 데이터 검사와 실제 검증·사용자 권한·제출 승인은 구분합니다.

## 스킬

| 스킬 | 무엇을 하나 | 버전 |
|---|---|---|
| **sast-remediation** | 기존 SAST 보고서(PDF·스프레드시트 또는 SARIF)의 검토·조치·검증 근거를 관리합니다. 저장된 기록으로 작업을 수동 재개하고, 브라우저에서 추출한 결과 초안을 백업할 수 있습니다. | 1.12.3 |
| **skill-architect** | 입력·상태·복구·검증 등 스킬 설계를 10개 범주로 검토합니다. 요청 시 승인된 개선 범위와 평가·적용·재개 이력을 기록합니다. | 0.4.2 |

PDF·스프레드시트 입력 절차는 **Sparrow 보고서**를 기준으로 정리했습니다.
다른 SAST 검사 도구의 보고서는 컬럼과 위험도 의미를 별도로 대조하며,
Sparrow의 해석을 그대로 적용하지 않습니다.

편집 기준이 되는 원본(정본)과 플러그인 배포 사본의 위치는 아래
[저장소 구조](#저장소-구조)에 있습니다.

## 설치 — 에이전트별

### 스킬 직접 설치 (Cursor, Grok 등 SKILL.md 지원 에이전트)

현재 프로젝트에 설치하려면 프로젝트 디렉터리에서 실행합니다.

```bash
npx skills add seo0tak/agent-skills
```

설치할 두 스킬과 대상 에이전트를 선택합니다. 기본 설치 범위는 현재 프로젝트이며,
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

설치 후 새 대화 또는 CLI 세션을 시작하고 두 스킬이 표시되는지 확인합니다.
플러그인 설치는 이를 지원하는 앱 또는 CLI에서 진행합니다.
([Codex 플러그인 안내](https://learn.chatgpt.com/docs/plugins))

### 수동 복사 설치

저장소를 로컬에 받은 뒤 저장소 루트에서 실행하는 사용자 범위 설치 예시입니다.
같은 이름의 설치본이 있으면 먼저 기존 설치 위치와 버전을 확인하고 업데이트 방법을
선택하세요. 아래 명령은 같은 이름의 대상이 이미 있으면 복사하지 않습니다.

```bash
mkdir -p ~/.agents/skills
test ! -e ~/.agents/skills/sast-remediation && test ! -L ~/.agents/skills/sast-remediation && cp -R skills/sast-remediation ~/.agents/skills/
test ! -e ~/.agents/skills/skill-architect && test ! -L ~/.agents/skills/skill-architect && cp -R skills/skill-architect ~/.agents/skills/
```

이 경로를 읽는 환경에서 사용하고, 설치 후 새 세션에서 인식 여부를 확인합니다.
같은 스킬을 플러그인과 여러 직접 설치 경로에 중복 설치하지 않는 편이 좋습니다.

## 사용 시작

설치한 스킬이 보이고 프로젝트 파일에 접근할 수 있는 세션에서 다음처럼 요청합니다.

| 작업 | 요청 예 |
|---|---|
| SAST 결과 조치 | "SAST 결과 조치해줘" (PDF·엑셀 또는 SARIF를 `input/`에 넣으라고 안내함) |
| 이어서 작업 | "SAST 조치 이어서 해줘" |
| 스킬 품질 점검 | "이 스킬 감사해줘" / "sast-remediation 스킬 감사해줘" |

## 왜 이렇게 만들었나

1. **역할 분리** — AI는 승인 범위에서 실행하고 사람은 업무 정책을 결정합니다.
   결과·임시 진행상태·체크포인트·브라우저 초안을 구분해 파일과 백업으로 남깁니다.
2. **검사 범위 명시** — 도구는 형식·상태·입력·소스 연결을 검사합니다.
   실제 검증의 충분성이나 사용자 권한·제출 승인은 별도로 확인합니다.
3. **미확인을 숨기지 않기** — 정책은 업무 사실로 묻고 모르는 내용은 보류하거나
   승인된 관찰 방법으로 확인합니다. 오래된 검증과 현재 검증을 구분합니다.
4. **목적에 맞는 소스 탐색** — 두 스킬 모두 현재 환경에서 LSP(언어 서버)의
   사용 가능 여부를 먼저 확인합니다. 정의·참조·타입은 LSP를 우선하고,
   문구·설정값은 텍스트로 검색합니다. LSP가 없거나 불완전하면 대체 방법과
   확인하지 못한 범위를 남기며, 도구를 임의로 설치하지 않습니다.

## 관련 문서

| 문서 | 내용 |
|---|---|
| [toolkit/README.md](skills/sast-remediation/toolkit/README.md) | 스킬 설치 없이 툴킷을 복사해 사용하는 방법과 실행 준비 |
| [USAGE.md](skills/sast-remediation/toolkit/USAGE.md) | 단계별 사용법, AI 요청 예, 명령어 요약, 자주 겪는 상황 |
| [HOW_IT_WORKS.md](skills/sast-remediation/toolkit/docs/HOW_IT_WORKS.md) | 저장되는 정보, 중단 후 재개, 검증 결과의 재사용 조건과 한계 |
| [SECURITY_GRILL_GUIDE.md](skills/sast-remediation/toolkit/SECURITY_GRILL_GUIDE.md) | 업무 사실을 중심으로 정책을 확인하는 방법과 확인이 어려울 때의 처리 |
| [VERSIONING.md](skills/sast-remediation/toolkit/docs/VERSIONING.md) | 버전·호환 정책, 진행 중 차수 업그레이드, 마이그레이션 기록 |
| [ARCHITECTURE_CHECKLIST.md](skills/skill-architect/ARCHITECTURE_CHECKLIST.md) | 스킬 품질 기준 10범주 |

## 개선 기록과 자동화의 경계

skill-architect의 [선택적 개선 기록](skills/skill-architect/references/improvement-workflow.md)은
문제 → 후보 → 평가 → 승인 참조 → 적용 → 회귀 검증을 프로젝트별로 남깁니다.
한 번의 검토만 요청한 경우에는 별도 개선 기록 디렉터리를 만들지 않습니다.
기록 도구는 명령·패치·테스트를 실행하지
않으며 실제 사용자 권한을 부여하거나 인증하지 않습니다.
두 스킬 모두 자동 재시작·네트워크 감시·무승인 자체 수정·배포는 하지 않습니다.

## 저장소 구조

```text
skills/<이름>/                    ← 정본 (에이전트 중립). 편집은 여기서만
plugins/<이름>/                   ← Claude Code / Codex 플러그인 배포 구성
  .claude-plugin/plugin.json      ← 버전 정본
  .codex-plugin/plugin.json       ← Codex 플러그인 정보 파일 (같은 버전)
  skills/<이름>/                  ← 정본의 사본 (scripts/sync-plugins.sh)
  agents/                         ← Claude 전용 서브에이전트
.claude-plugin/marketplace.json   ← Claude Code 카탈로그 (name: 0tak)
.agents/plugins/marketplace.json  ← Codex 카탈로그
```

버전 기준은 `plugins/<이름>/.claude-plugin/plugin.json`입니다. 버전을 변경하면
Codex 정보 파일과 README 표도 갱신한 뒤 `scripts/check-versions.sh`로 일치를 검사합니다.

## 설치본 업데이트

카탈로그 갱신과 설치된 플러그인 갱신을 구분합니다. 다음은 Claude Code의
사용자 범위(`--scope user`) 설치 예시입니다. 프로젝트/로컬 범위 설치라면
실제 설치 범위(`project`/`local`)를 사용합니다.

```bash
claude plugin marketplace update 0tak
claude plugin update sast-remediation@0tak --scope user
claude plugin update skill-architect@0tak --scope user
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
[VERSIONING.md](skills/sast-remediation/toolkit/docs/VERSIONING.md#업그레이드-자산-정책)를
먼저 읽고 배포 파일을 교체하되 사용자 변경을 보존하며 필요한 데이터 이전을 수행합니다.

## 새 스킬 추가

1. `skills/<이름>/SKILL.md` 작성 (지원 파일 동봉 가능)
2. `plugins/<이름>/.claude-plugin/plugin.json`, `.codex-plugin/plugin.json` 작성
3. `scripts/sync-plugins.sh`로 사본 생성
4. 두 카탈로그(`.claude-plugin/marketplace.json`, `.agents/plugins/marketplace.json`)에 등록
5. `scripts/check-versions.sh`, `scripts/sync-plugins.sh --check` 통과 확인
6. `skill-architect`로 한 번 감사
