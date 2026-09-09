# 0tak agent-skills

SAST 결과를 사람이 감당할 수 있게 만드는 스킬과, 스킬 자체의 품질을 감사하는
스킬. Agent Skills 표준(`SKILL.md`)이라 Claude Code·Codex·Cursor·Grok 등
어디서든 가져다 씁니다.

> **This is not a scanner.** `sast-remediation` manages SAST findings you
> already have — vendor PDF+spreadsheet or SARIF — through input gating,
> source-to-report mapping, false-positive review, remediation waves with
> verification, cross-round carry-over, and submission-ready evidence. State
> lives in files; validators check data consistency, while actual evidence and user authority still require review. Its
> policy questions are designed for people who don't know the codebase or
> security well. `skill-architect` audits skills against a 10-category
> production-quality checklist derived from running the former.

## 스킬

| 스킬 | 무엇을 하나 | 버전 |
|---|---|---|
| **sast-remediation** | 이미 받은 SAST 결과(벤더 PDF+스프레드시트 또는 SARIF)를 조치·오탐검토·검증·증적까지 관리하는 파일 기반 워크플로우. 게이트, 수동 재개·소스 검증 연결·상세 초안 백업 포함 | 1.12.0 |
| **skill-architect** | 스킬을 목적과 근거에 맞춰 감사·설계. 선택적으로 승인 범위의 개선·평가·재개 이력을 관리 | 0.4.0 |

정본은 `skills/<이름>/`, 버전 정본은 `plugins/<이름>/.claude-plugin/plugin.json`.
위 표는 요약이므로 버전을 올릴 때 `scripts/check-versions.sh`로 맞춥니다.

## 설치 — 에이전트별

### 범용 (Cursor, Grok, 기타 SKILL.md 지원 에이전트)

```bash
npx skills add seo0tak/agent-skills
```

`~/.agents/skills/`에 두 스킬이 설치되고 각 에이전트 경로에 링크됩니다.
Grok Build CLI는 `~/.agents/skills/`(유저) / `.agents/skills/`(프로젝트)를
그대로 읽습니다.

### Claude Code (풀기능 — 서브에이전트·버전 관리)

```bash
claude plugin marketplace add seo0tak/agent-skills
claude plugin install sast-remediation@0tak
claude plugin install skill-architect@0tak
```

세션 안에서는 `/plugin marketplace add`, `/plugin install`. sast-remediation은
저비용 모델 서브에이전트 2종(bulk-worker, remediator)이 함께 설치됩니다.

### Codex

```bash
codex plugin marketplace add seo0tak/agent-skills
codex plugin add sast-remediation@0tak
codex plugin add skill-architect@0tak
```

수동으로는 `cp -R skills/<이름> ~/.agents/skills/`.

설치 후 프로젝트 안에서 이렇게 말하면 시작됩니다.

| 상황 | 이렇게 |
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

| 문서 | 내용 |
|---|---|
| [toolkit/README.md](skills/sast-remediation/toolkit/README.md) | 툴킷 단독 사용 — 스킬 없이 디렉터리 복사만으로 |
| [USAGE.md](skills/sast-remediation/toolkit/USAGE.md) | 단계별 사용법, AI에게 말하는 법, 명령어 치트시트, 자주 겪는 상황 |
| [HOW_IT_WORKS.md](skills/sast-remediation/toolkit/docs/HOW_IT_WORKS.md) | 저장 경계·수동 재개·검증 신선도와 한계 |
| [SECURITY_GRILL_GUIDE.md](skills/sast-remediation/toolkit/SECURITY_GRILL_GUIDE.md) | 정책 질문을 어떻게 묻는가 (답하는 사람이 모를 때 포함) |
| [VERSIONING.md](skills/sast-remediation/toolkit/docs/VERSIONING.md) | 버전·호환 정책, 진행 중 차수 업그레이드, 마이그레이션 기록 |
| [ARCHITECTURE_CHECKLIST.md](skills/skill-architect/ARCHITECTURE_CHECKLIST.md) | 스킬 품질 기준 10범주 |

## 개선 기록과 자동화의 경계

skill-architect의 [선택적 개선 기록](skills/skill-architect/references/improvement-workflow.md)은
문제 → 후보 → 평가 → 승인 참조 → 적용 → 회귀 검증을 프로젝트별로 남깁니다.
단회 감사에는 저장소가 필요 없습니다. 기록 도구는 명령·패치·테스트를 실행하지
않으며 실제 사용자 권한을 부여하거나 인증하지 않습니다.
두 스킬 모두 자동 재시작·네트워크 감시·무승인 자체 수정·배포는 하지 않습니다.

## 저장소 구조

```text
skills/<이름>/                    ← 정본 (에이전트 중립). 편집은 여기서만
plugins/<이름>/                   ← Claude Code / Codex 포장
  .claude-plugin/plugin.json      ← 버전 정본
  .codex-plugin/plugin.json       ← Codex 매니페스트 (같은 버전)
  skills/<이름>/                  ← 정본의 사본 (scripts/sync-plugins.sh)
  agents/                         ← Claude 전용 서브에이전트
.claude-plugin/marketplace.json   ← Claude Code 카탈로그 (name: 0tak)
.agents/plugins/marketplace.json  ← Codex 카탈로그
```

## 업데이트 배포

카탈로그 갱신과 설치된 플러그인 갱신을 구분합니다. Claude Code의 user
scope 설치 예시는 다음과 같습니다. project/local 설치라면 실제 scope를 씁니다.

```bash
claude plugin marketplace update 0tak
claude plugin update sast-remediation@0tak --scope user
claude plugin update skill-architect@0tak --scope user
```

설치된 버전을 확인하고 Claude Code를 재시작하거나 지원되는
`/reload-plugins`로 반영합니다. 제삼자 마켓의 자동 업데이트는 기본
비활성화입니다([공식 안내](https://code.claude.com/docs/en/discover-plugins#configure-auto-updates)).

Codex는 `codex plugin marketplace upgrade 0tak`으로 카탈로그 스냅샷을
갱신한 뒤 `codex plugin list`에서 설치 상태를 확인합니다. 이 명령의 실행만으로
설치 캐시 갱신까지 끝났다고 가정하지 말고, 현재 CLI/앱의 설치·업데이트
경로로 두 플러그인을 갱신하고 설치 버전을 확인합니다. CLI 설치 명령은
`codex plugin add <이름>@0tak`이며 세부 동작은 해당 버전의 `--help`를 따릅니다.
범용 설치는 `npx skills add seo0tak/agent-skills`를 재실행합니다.

스킬 설치본을 갱신해도 진행 중 프로젝트의 툴킷 복사본은 자동으로 바뀌지
않습니다. 프로젝트를 업그레이드할 때는 **새 설치본**의
[VERSIONING.md](skills/sast-remediation/toolkit/docs/VERSIONING.md#업그레이드-자산-정책)를
먼저 읽고 자산 교체·사용자 수정 보존·마이그레이션을 수행합니다.

## 새 스킬 추가

1. `skills/<이름>/SKILL.md` 작성 (지원 파일 동봉 가능)
2. `plugins/<이름>/.claude-plugin/plugin.json`, `.codex-plugin/plugin.json` 작성
3. `scripts/sync-plugins.sh`로 사본 생성
4. 두 카탈로그(`.claude-plugin/marketplace.json`, `.agents/plugins/marketplace.json`)에 등록
5. `scripts/check-versions.sh`, `scripts/sync-plugins.sh --check` 통과 확인
6. `skill-architect`로 한 번 감사
