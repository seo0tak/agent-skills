# seo0tak Claude Skills

Claude Code용 개인 스킬 마켓플레이스입니다. 지금은 두 개가 있습니다.

| 플러그인 | 무엇을 하나 | 버전 |
|---|---|---|
| **sast-remediation** | 이미 받은 SAST 결과(벤더 PDF+스프레드시트 또는 SARIF)를 조치·오탐검토·검증·증적까지 관리하는 파일 기반 워크플로우. 게이트, 차수 이월, 모델 티어링, 중단 내성 포함 | 1.10.0 |
| **skill-architect** | 스킬을 프로덕션 품질 기준(10범주 체크리스트)으로 감사하고, 새 스킬을 설계 | 0.2.0 |

버전 정본은 각 플러그인의 `.claude-plugin/plugin.json`입니다. 위 표는 요약이므로
버전을 올릴 때 함께 갱신합니다.

## 빠른 시작

```bash
# 마켓플레이스 등록
claude plugin marketplace add seo0tak/claude-skills
# private 저장소면:
# claude plugin marketplace add git@github.com:seo0tak/claude-skills.git

# 플러그인 설치
claude plugin install sast-remediation@seo0tak-skills
claude plugin install skill-architect@seo0tak-skills
```

세션 안에서는 `/plugin marketplace add`, `/plugin install`로 동일하게 가능합니다.

설치 후 프로젝트 안에서 이렇게 말하면 시작됩니다.

| 상황 | 이렇게 |
|---|---|
| SAST 결과 조치 | "SAST 결과 조치해줘" (PDF·엑셀 또는 SARIF를 `input/`에 넣으라고 안내함) |
| 이어서 작업 | "SAST 조치 이어서 해줘" |
| 스킬 품질 점검 | "이 스킬 감사해줘" / "sast-remediation 스킬 감사해줘" |

## 왜 이렇게 만들었나

sast-remediation은 스캐너가 아닙니다. 스캐너가 뱉은 수천 건을 **사람이 감당할
수 있게** 만드는 쪽입니다. 설계의 뼈대는 세 가지입니다.

1. **역할 분리** — AI가 실행자, 사람은 정책 결정자, 파일이 상태 저장소,
   검증기(`validate`)가 심판. 진행 상태는 대화가 아니라 파일에 남아 세션이
   끊겨도 이어집니다.
2. **규칙은 문서가 아니라 도구가 강제** — 근거 없는 오탐 판정, 검증 없는
   완료, 관찰 장치 없는 미확인 결정은 validate가 에러로 막습니다. AI가 규칙을
   잊어도 빨간불이 켜집니다.
3. **모르는 사람이 써도 안전** — 정책 질문은 보안 용어가 아니라 업무 사실로
   묻고, "모르겠다"가 정식 답이며, 모를 때는 동작을 보존하는 쪽을 택해
   현실이 답을 알려주게 합니다.

자세한 원리는 [HOW_IT_WORKS](plugins/sast-remediation/skills/sast-remediation/toolkit/docs/HOW_IT_WORKS.md)에
있습니다. skill-architect의 체크리스트는 이 스킬을 운영하며 도출된 기준입니다.

## 문서

| 문서 | 내용 |
|---|---|
| [USAGE.md](plugins/sast-remediation/skills/sast-remediation/toolkit/USAGE.md) | 단계별 사용법, AI에게 말하는 법, 명령어 치트시트, 자주 겪는 상황 |
| [HOW_IT_WORKS.md](plugins/sast-remediation/skills/sast-remediation/toolkit/docs/HOW_IT_WORKS.md) | 왜 이렇게 움직이는지 — 핵심 원리 10가지 |
| [SECURITY_GRILL_GUIDE.md](plugins/sast-remediation/skills/sast-remediation/toolkit/SECURITY_GRILL_GUIDE.md) | 정책 질문을 어떻게 묻는가 (답하는 사람이 모를 때 포함) |
| [VERSIONING.md](plugins/sast-remediation/skills/sast-remediation/toolkit/docs/VERSIONING.md) | 버전·호환 정책, 진행 중 차수 업그레이드, 마이그레이션 기록 |
| [ARCHITECTURE_CHECKLIST.md](plugins/skill-architect/skills/skill-architect/ARCHITECTURE_CHECKLIST.md) | 스킬 품질 기준 10범주 |

툴킷은 스킬 없이도 씁니다 — `toolkit/` 디렉터리를 프로젝트에 복사하고
[toolkit/README.md](plugins/sast-remediation/skills/sast-remediation/toolkit/README.md)의
빠른 시작을 따르면 됩니다.

## 업데이트 배포

이 저장소에 커밋·푸시하면 사용자 쪽에서는 다음으로 반영됩니다.

```bash
claude plugin marketplace update seo0tak-skills
```

진행 중인 차수가 있는 프로젝트는 업그레이드 후 `validate`를 돌리고 경고까지
읽습니다 — 절차는 VERSIONING.md.

## 새 스킬 추가

1. `plugins/<이름>/` 디렉터리 생성
2. `.claude-plugin/plugin.json` 작성
3. `skills/<이름>/SKILL.md` 작성 (지원 파일 동봉 가능)
4. `.claude-plugin/marketplace.json`의 plugins 배열에 등록
5. `skill-architect`로 한 번 감사

## English summary

A personal Claude Code plugin marketplace. **sast-remediation** manages SAST
findings you already have (vendor PDF+spreadsheet or SARIF) through input
gating, source-to-report mapping, false-positive review, remediation waves
with verification, cross-round carry-over, and submission-ready evidence.
State lives in files, rules are enforced by a validator rather than by
prose, and policy questions are designed for people who don't know the
codebase or security well. **skill-architect** audits and designs skills
against a 10-category production-quality checklist derived from running
the former. See [HOW_IT_WORKS](plugins/sast-remediation/skills/sast-remediation/toolkit/docs/HOW_IT_WORKS.md).
