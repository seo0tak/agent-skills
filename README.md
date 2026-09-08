# 0tak agent-skills

SAST 결과를 사람이 감당할 수 있게 만드는 스킬과, 스킬 자체의 품질을 감사하는
스킬. Agent Skills 표준(`SKILL.md`)이라 Claude Code·Codex·Cursor·Grok 등
어디서든 가져다 씁니다.

> **This is not a scanner.** `sast-remediation` manages SAST findings you
> already have — vendor PDF+spreadsheet or SARIF — through input gating,
> source-to-report mapping, false-positive review, remediation waves with
> verification, cross-round carry-over, and submission-ready evidence. State
> lives in files, rules are enforced by a validator rather than by prose, and
> policy questions are designed for people who don't know the codebase or
> security well. `skill-architect` audits skills against a 10-category
> production-quality checklist derived from running the former.

## 스킬

| 스킬 | 무엇을 하나 | 버전 |
|---|---|---|
| **sast-remediation** | 이미 받은 SAST 결과(벤더 PDF+스프레드시트 또는 SARIF)를 조치·오탐검토·검증·증적까지 관리하는 파일 기반 워크플로우. 게이트, 차수 이월, 모델 티어링, 중단 내성 포함 | 1.10.1 |
| **skill-architect** | 스킬을 프로덕션 품질 기준(10범주 체크리스트)으로 감사하고, 새 스킬을 설계 | 0.2.1 |

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

1. **역할 분리** — AI가 실행자, 사람은 정책 결정자, 파일이 상태 저장소,
   검증기(`validate`)가 심판. 진행 상태는 대화가 아니라 파일에 남아 세션이
   끊겨도 이어집니다.
2. **규칙은 문서가 아니라 도구가 강제** — 근거 없는 오탐 판정, 검증 없는
   완료, 관찰 장치 없는 미확인 결정은 validate가 에러로 막습니다.
3. **모르는 사람이 써도 안전** — 정책 질문은 보안 용어가 아니라 업무 사실로
   묻고, "모르겠다"가 정식 답이며, 모를 때는 동작을 보존하는 쪽을 택해
   현실이 답을 알려주게 합니다.

| 문서 | 내용 |
|---|---|
| [toolkit/README.md](skills/sast-remediation/toolkit/README.md) | 툴킷 단독 사용 — 스킬 없이 디렉터리 복사만으로 |
| [USAGE.md](skills/sast-remediation/toolkit/USAGE.md) | 단계별 사용법, AI에게 말하는 법, 명령어 치트시트, 자주 겪는 상황 |
| [HOW_IT_WORKS.md](skills/sast-remediation/toolkit/docs/HOW_IT_WORKS.md) | 왜 이렇게 움직이는지 — 핵심 원리 10가지 |
| [SECURITY_GRILL_GUIDE.md](skills/sast-remediation/toolkit/SECURITY_GRILL_GUIDE.md) | 정책 질문을 어떻게 묻는가 (답하는 사람이 모를 때 포함) |
| [VERSIONING.md](skills/sast-remediation/toolkit/docs/VERSIONING.md) | 버전·호환 정책, 진행 중 차수 업그레이드, 마이그레이션 기록 |
| [ARCHITECTURE_CHECKLIST.md](skills/skill-architect/ARCHITECTURE_CHECKLIST.md) | 스킬 품질 기준 10범주 |

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

이 저장소에 커밋·푸시하면 사용자 쪽에서는 다음으로 반영됩니다.

```bash
claude plugin marketplace update 0tak     # Claude Code
codex plugin marketplace upgrade          # Codex
npx skills add seo0tak/agent-skills       # 범용 (재실행)
```

진행 중인 차수가 있는 프로젝트는 업그레이드 후 `validate`를 돌리고 경고까지
읽습니다 — 절차는 VERSIONING.md.

## 새 스킬 추가

1. `skills/<이름>/SKILL.md` 작성 (지원 파일 동봉 가능)
2. `plugins/<이름>/.claude-plugin/plugin.json`, `.codex-plugin/plugin.json` 작성
3. `scripts/sync-plugins.sh`로 사본 생성
4. 두 카탈로그(`.claude-plugin/marketplace.json`, `.agents/plugins/marketplace.json`)에 등록
5. `scripts/check-versions.sh`, `scripts/sync-plugins.sh --check` 통과 확인
6. `skill-architect`로 한 번 감사
