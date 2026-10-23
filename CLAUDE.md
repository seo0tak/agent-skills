# 저장소 규약

## 구조 — 편집 원본과 플러그인 배포 사본

```text
skills/<이름>/                 ← 스킬 편집 원본(정본). 에이전트 공통 지침
plugins/<이름>/                ← Claude Code / Codex 플러그인 배포 구성
  .claude-plugin/plugin.json   ← 버전 정본
  .codex-plugin/plugin.json    ← Codex 정보 파일 (같은 버전)
  skills/<이름>/                ← 정본의 사본 (scripts/sync-plugins.sh가 생성)
  agents/                      ← Claude 전용 서브에이전트. 정본으로 옮기지 않음
  hooks/ · types/ · tests/     ← Claude Code 전용 화면 확장(mod). 정본으로 옮기지 않음.
                                 고친 뒤 `claude plugin validate`·`claude plugin test`로 확인
.claude-plugin/marketplace.json  ← Claude Code 카탈로그 (name: 0tak)
.agents/plugins/marketplace.json ← Codex 카탈로그 (같은 플러그인 목록)
```

- 스킬 본체는 `skills/`에서만 편집한다. `plugins/*/skills/*`는
  `scripts/sync-plugins.sh`가 만드는 사본이며 손으로 고치지 않는다.
  커밋 전 `scripts/sync-plugins.sh --check`가 통과해야 한다.
- 심링크를 쓰지 않는 이유: Claude Code는 설치 시 심링크를 실제 파일로 풀지만,
  Codex CLI는 빈 디렉터리로 복사한다(둘 다 로컬 설치로 실측). 사본이어야 두
  실행 환경에 같은 배포 구성을 제공한다. 이 제약은 당시 로컬 설치 결과에
  근거하며, 설치 도구가 바뀌면 별도 승인된 설치 시험으로 다시 확인한다.
- 버전은 `plugins/*/.claude-plugin/plugin.json`이 정본. 마켓플레이스
  카탈로그에는 version을 쓰지 않는다. README 표는 손으로 맞춘다.
- 새 스킬을 추가하면 README의 스킬 표(버전은 check-versions가 강제)와 관련 문서
  섹션에 그 스킬 항목을 더한다. README는 공통 설치·구조·스킬 목록만 담고,
  스킬별 상세는 각 `skills/<이름>/` 문서에 둔다.
- 스킬 표에는 유형(보안·메타 등)과 버전을 둔다(버전은 마지막 칸 — check-versions
  정규식이 마지막 `| 버전 |`을 읽는다). README는 특정 범주를 전제하지 않는다.
- 스킬 내부 규칙은 `skills/sast-remediation/toolkit/docs/HOW_IT_WORKS.md`,
  버전·호환은 `skills/sast-remediation/toolkit/docs/VERSIONING.md`, 인수인계는 `HANDOFF.md`.

## 작업 전 확인

- 툴킷 변경 후 툴킷 루트에서 `python3 -B tools/sast_toolkit.py validate`,
  `python3 -B -m unittest tools.test_toolkit tools.test_sast_state tools.test_usage_renderer tools.test_activity`,
  `node --test tools/test_dashboard.cjs tools/test_activity_dashboard.cjs`를 실행한다.
- 저장소 루트에서 `python3 -B -m unittest discover -s skills/skill-architect/scripts -p 'test_*.py'`
  및 `python3 -B -m unittest scripts.test_packaging`를 실행한다.
- 저장소 안에서 `preflight`/`init`을 돌리지 않는다 — 산출물이 배포물에 섞인다.
- USAGE.md·data/decisions.json 수정 후 `sync` (USAGE.html·DECISION_LOG.md는 생성물).
## 문서 규칙

- 사용자용 문서(README·SKILL.md·HOW_IT_WORKS·USAGE·프롬프트)는 스킬이 어떻게 동작하는지만
  쓴다. 결정 날짜, 대화·질의 번호, 개발 단계 표시(M1 등)는 넣지 않는다. 결정 경위는
  `docs/adr/`, 작업 이력은 `HANDOFF.md`, 단계 이력은 각 스킬 `docs/VERSIONING.md`에 둔다.
- 다이어그램은 스킬 단위로 둔다. 스킬 README에 작업 흐름도 한 장, HOW_IT_WORKS에 구조도
  한 장. 사람이 승인하는 지점이 있는 스킬은 HOW_IT_WORKS에 시퀀스를 둔다. 순서나 상태
  전이가 핵심인 절차 문서(기록 순서, 상태 기계)에는 그 문서에 시퀀스·상태도를 더한다.
  루트 README에는 그림을 두지 않는다. 동작을 바꾸면 흐름도·시퀀스·구조도와 USAGE의 텍스트
  흐름이 서로 같은 순서와 승인 지점을 보이는지 함께 확인한다.
- 흐름도는 README 안의 mermaid, 구조도는 D2, 시퀀스·상태도는 PlantUML로 그린다. 단, 생성되는
  HTML 가이드(USAGE.html)에도 보여야 하는 흐름도는 D2 SVG 하나로 그려 README와 USAGE가 같이 쓴다
  (USAGE 렌더러는 mermaid를 못 그리고 툴킷 안 상대 경로 이미지만 그린다). 텍스트 화살표로
  흐름을 대신하지 않는다. D2·PlantUML 원본은
  `docs/diagrams/*.d2|*.puml`에 두고 `python3 scripts/render_diagrams.py`로 만든 SVG를 함께
  커밋한다(d2, plantuml 또는 `PLANTUML_JAR` 필요). 커밋 전 `--check`가 통과해야 하며, 이
  검사는 도구 없이 SVG 끝의 원본 해시만 비교한다. 그린 뒤 SVG를 열어 겹침·잘림을 눈으로
  확인한다. mermaid를 고치면 렌더링해 파싱 오류가 없는지, 라벨이 자동 줄바꿈으로 단어 중간에서
  끊기지 않는지 확인한다(긴 라벨은 `<br/>`로 직접 나눈다). 코드 블록 안 명령은 100칸을 넘기지 않게
  옵션 경계에서 `\` 줄 이음으로 나눈다.

- 문구를 고칠 때는 동작 주체·입력 조건·저장/검증/승인의 의미를 유지한다.
  JSON 키·enum·고정 응답 라벨·증적 열 이름·코드 원문은 문체 교정 대상으로 바꾸지 않는다.
