# 사용 가이드

이 문서는 실제 검사 차수를 처리하는 순서 그대로 정리한 실전 가이드입니다.
설계 배경은 `docs/DESIGN.md`, 단계별 규칙은 `SECURITY_SAST_WORKFLOW.md`를
참고합니다.

## 전체 흐름 요약

```text
[준비] 툴킷 복사 + input/에 PDF·스프레드시트
   ↓
[00] 사전 점검 게이트 (preflight → AI 대조 → gate READY)
   ↓
[01] 초기 분석 (프로젝트 분석, 검출 정규화, 소스 매핑)
   ↓
[06] 차수 이월 (이전 차수 있을 때만 — 오탐·예외 결론 승계)
   ↓
[02] 정책 질문 (AI가 물으면 하나씩 답변 → 정책·결정 로그 누적)
   ↓
[03] 조치 웨이브 (작업 묶음 단위로 반복)
   ↓
[04] 결과 대조 (진행상태와 결과 파일 정합성 확인)
   ↓
[05] 증적 생성 (제출용 xlsx 4종)
   ↓
[제출 전] validate --strict 통과 확인
```

## 스킬로 설치 (Claude Code, 선택)

툴킷을 스킬로 설치하면 프로젝트마다 복사할 필요 없이 어느 프로젝트에서든
"SAST 조치해줘" 한마디로 시작할 수 있습니다. 배포된
`sast-remediation-skill.zip`을 `~/.claude/skills/`에 풀면 끝입니다.

```text
~/.claude/skills/sast-remediation/
├── SKILL.md
└── toolkit/        # 이 툴킷 전체 동봉
```

이후 아무 프로젝트에서나 `/sast-remediation` 또는 자연어로 요청하면
스킬이 툴킷 복사부터 워크플로우까지 알아서 진행합니다. 이 경우 아래
"AI에게 말하는 법"의 방식 A는 스킬 호출로 대체됩니다.

## AI에게 말하는 법

각 단계의 요청문은 `prompts/` 파일 안에 이미 완성되어 있습니다. 새로
문장을 쓸 필요 없이 둘 중 한 방식으로 전달하면 됩니다.

**방식 A — 파일을 읽게 하기** (Claude Code 등 파일 접근 가능한 환경, 권장)

```text
sast-remediation-toolkit/prompts/00-preflight.md 읽고 그대로 수행해줘
```

단계가 바뀌면 파일명만 바꿉니다. 이월처럼 추가 정보가 필요한 단계는
한 줄 덧붙입니다.

```text
prompts/06-carry-over.md 수행해줘. 이전 차수는 ../sast-2025-2차/ 에 있어
```

**방식 B — 내용 복붙** (파일 접근이 없는 채팅 환경)

프롬프트 파일을 열어 코드블록 안의 요청문을 복사해 붙여넣습니다.

그 외 상황은 자연어로 말하면 됩니다. 자주 쓰는 표현:

| 상황 | 이렇게 |
|---|---|
| 다음 단계 진행 | "다음 웨이브 진행해줘" |
| 특정 항목만 | "FIND-0231만 다시 분석해줘" |
| 상태 반영 | "sync 하고 validate 돌려줘" |
| 대시보드 백업 반영 | "이 JSON을 progress에 반영해줘" (백업 파일 첨부) |
| fingerprint 에러 | "매핑된 항목에 fingerprint 채워줘" |

## 0. 준비

1. `sast-remediation-toolkit/` 디렉터리 전체를 대상 프로젝트 루트 안에
   복사합니다.
2. 이번 차수의 SAST 자료를 `input/`에 넣습니다. 둘 중 한 조합:
   벤더 PDF(분할 시 여러 개 가능)+스프레드시트 1개, 또는 표준 SARIF
   파일 1개(Semgrep, CodeQL 등의 출력). 같은 검사 차수의 자료여야
   합니다. 리포트가 여러 벌이면 `input/<세트명>/` 폴더로 구분해 두면
   세트 단위로 인식합니다(여럿이면 preflight 때 세트 지정).
3. 에이전트를 쓰는 경우 `AGENTS_SNIPPET.md` 내용을 프로젝트의 에이전트
   지침 파일에 붙여 넣습니다.

## 1. 사전 점검 게이트 — prompts/00

AI에게 `prompts/00-preflight.md`의 요청문을 그대로 전달합니다.

내부적으로 일어나는 일:

1. `python3 tools/sast_toolkit.py preflight` — 소스 존재, 입력 개수,
   파일 시그니처를 기계적으로 검사해 `data/input-validation.json`에
   기록합니다.
2. AI가 소스·PDF·스프레드시트의 프로젝트 식별정보, 검사 차수, 검출
   건수, 소스 범위를 대조해 판정을 기록합니다.
3. `python3 tools/sast_toolkit.py gate` — 판정과 현재 입력 파일을
   재대조합니다. 입력 파일을 바꾸면 이전 승인은 자동 무효가 됩니다.

`GATE: READY`이면 AI가 `prompts/01-initialize.md` 절차까지 이어서
진행합니다. `BLOCKED`이면 차단 사유에 맞게 입력을 바로잡고 00부터 다시
실행합니다. READY 전에는 어떤 분석·조치도 시작하지 않습니다.

## 2. 초기 분석 확인 — prompts/01 산출물

AI가 생성한 다음을 검토합니다.

| 산출물 | 확인 포인트 |
|---|---|
| `project/PROJECT_ANALYSIS.md` | 모듈·빌드·테스트 명령이 실제와 맞는지 |
| `data/findings.json` | 검출 건수가 스프레드시트와 일치하는지 |
| `SECURITY_CHECKLIST.html` | 브라우저에서 열어 목록·집계 확인 |

소스 매핑이 `exact`/`relocated`/`changed`인 항목에는 `fingerprint`가
기록됩니다. 다음 차수 이월의 매칭 키이므로 비어 있으면 validate가
에러를 냅니다.

## 3. 차수 이월 — prompts/06 (재검사 차수만)

이전 차수의 툴킷 산출물(findings, progress, security-results)이 있으면
`prompts/06-carry-over.md`를 전달합니다. 이전 차수 디렉터리 경로를 함께
알려줍니다.

- 오탐·예외 결론은 코드가 그대로일 때만 자동 승계됩니다.
- 코드가 바뀐 항목과 수정했는데 재검출된 항목(회귀 의심)은
  `needs-review`로 남습니다.
- 첫 차수라면 이 단계는 건너뜁니다.

## 4. 정책 질문 답변 — prompts/02

AI는 소스와 보고서로 판단할 수 없는 것만, 한 번에 하나씩, 추천 답변과
함께 질문합니다. 답변은 `project/PROJECT_SECURITY_POLICY.md`와
`project/DECISION_LOG.md`에 누적되어 같은 질문이 반복되지 않습니다.

## 5. 조치 웨이브 — prompts/03

`prompts/03-remediation-wave.md`로 작업 묶음(work group) 단위 조치를
요청합니다. 필요한 만큼 반복합니다.

- 웨이브 시작 전에 gate READY를 다시 확인합니다.
- 항목별 결과는 `security-results/<ID>.json`에 기록됩니다. 이것이 상태의
  기준이며 `data/progress.json`은 대시보드용 집계입니다.
- 검증(빌드·테스트)이 통과하지 않은 수정은 `verified`가 될 수 없습니다.

## 6. 대시보드로 검토

`SECURITY_CHECKLIST.html`을 브라우저에서 직접 엽니다(서버 불필요).

| 버튼 | 용도 |
|---|---|
| 전체 결과 갱신 | AI가 갱신한 파일 상태 다시 읽기 |
| 상태 백업 | 브라우저 변경분을 JSON으로 내려받기 |
| 상태 불러오기 | 백업 JSON을 다시 반영 |

파일과 브라우저 저장본이 다르면 항목별 `updatedAt`이 최신인 쪽이
반영되고 상단에 충돌 배너가 뜹니다. **배너에 "브라우저에만 있는 변경
n건"이 보이면 상태 백업으로 내려받아 `data/progress.json`에 반영한 뒤
AI에게 `sync`를 요청**합니다.

## 7. 결과 대조와 증적 — prompts/04, 05

- `prompts/04-reconcile-results.md`: 진행상태·결과·대시보드가 서로 맞는지
  대조합니다.
- `prompts/05-final-evidence.md`: 제출용 xlsx 4종을 `evidence/`에
  생성합니다. 파일명을 바꾸려면 `data/project-profile.json`의
  `evidence.outputs`에 지정합니다.

## 8. 제출 전 최종 점검

```text
python3 tools/sast_toolkit.py validate --strict
```

strict는 게이트 미통과, 입력 누락, 미초기화 메타데이터, 상태 불일치를
전부 오류로 처리합니다. `OK`가 나와야 제출 준비 완료입니다.

## 명령어 치트시트

`sast-remediation-toolkit/` 디렉터리에서 실행합니다. 외부 라이브러리는
필요 없습니다(Python 3 표준 라이브러리만 사용).

| 명령 | 용도 |
|---|---|
| `python3 tools/sast_toolkit.py preflight` | 입력·소스 기계 점검 |
| `python3 tools/sast_toolkit.py gate` | 게이트 판정(READY/BLOCKED) |
| `python3 tools/sast_toolkit.py init` | 게이트 통과 후 초기화 |
| `python3 tools/sast_toolkit.py sync` | JSON → JS 미러·인덱스 동기화 |
| `python3 tools/sast_toolkit.py validate` | 데이터 정합성 검증 |
| `python3 tools/sast_toolkit.py validate --strict` | 제출 전 최종 검증 |

프로젝트 루트가 툴킷 상위 디렉터리가 아니면 `--project-root <경로>`를
붙입니다.

## 자주 겪는 상황

| 증상 | 조치 |
|---|---|
| `GATE: BLOCKED` — 입력 개수 | `input/`에 PDF 1개·스프레드시트 1개만 남기기 |
| `GATE: BLOCKED` — recorded ... differs | 입력 파일이 바뀜. 00 사전 점검부터 재실행 |
| validate: fingerprint is empty | AI에게 "매핑된 항목에 fingerprint 채워줘" 요청 |
| validate: progress and result disagree | AI에게 04 대조 요청. results가 기준 |
| 대시보드가 비어 보임 | `sync` 실행 여부 확인 후 새로고침 |
| 브라우저 변경이 사라질까 걱정될 때 | 상태 백업 먼저, 그다음 파일 작업 |
| 기존 진행 중 프로젝트에 새 툴킷 덮어씀 | fingerprint 에러 발생 시 위 요청 한 번 실행 |
