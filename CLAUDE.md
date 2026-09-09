# 저장소 규약

## 구조 — 편집 원본과 플러그인 배포 사본

```text
skills/<이름>/                 ← 스킬 편집 원본(정본). 에이전트 공통 지침
plugins/<이름>/                ← Claude Code / Codex 플러그인 배포 구성
  .claude-plugin/plugin.json   ← 버전 정본
  .codex-plugin/plugin.json    ← Codex 정보 파일 (같은 버전)
  skills/<이름>/                ← 정본의 사본 (scripts/sync-plugins.sh가 생성)
  agents/                      ← Claude 전용 서브에이전트. 정본으로 옮기지 않음
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
- 스킬 내부 규칙은 `skills/sast-remediation/toolkit/docs/HOW_IT_WORKS.md`,
  버전·호환은 `skills/sast-remediation/toolkit/docs/VERSIONING.md`, 인수인계는 `HANDOFF.md`.

## 작업 전 확인

- 툴킷 변경 후 툴킷 루트에서 `python3 -B tools/sast_toolkit.py validate`,
  `python3 -B -m unittest tools.test_toolkit tools.test_sast_state tools.test_usage_renderer`,
  `node --test tools/test_dashboard.cjs`를 실행한다.
- 저장소 루트에서 `python3 -B -m unittest discover -s skills/skill-architect/scripts -p 'test_*.py'`
  및 `python3 -B -m unittest scripts.test_packaging`를 실행한다.
- 저장소 안에서 `preflight`/`init`을 돌리지 않는다 — 산출물이 배포물에 섞인다.
- USAGE.md·data/decisions.json 수정 후 `sync` (USAGE.html·DECISION_LOG.md는 생성물).
- 문구를 고칠 때는 동작 주체·입력 조건·저장/검증/승인의 의미를 유지한다.
  JSON 키·enum·고정 응답 라벨·증적 열 이름·코드 원문은 문체 교정 대상으로 바꾸지 않는다.
