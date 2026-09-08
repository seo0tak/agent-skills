# 저장소 규약

## 구조 — 정본 1벌 + 포장 N개

```text
skills/<이름>/                 ← 스킬 정본 (에이전트 중립). 편집은 여기서만
plugins/<이름>/                ← Claude Code 포장
  .claude-plugin/plugin.json   ← 버전 정본
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
  하네스가 같은 포장을 쓴다.
- 버전은 `plugins/*/.claude-plugin/plugin.json`이 정본. 마켓플레이스
  카탈로그에는 version을 쓰지 않는다. README 표는 손으로 맞춘다.
- 스킬 내부 규칙은 `skills/sast-remediation/toolkit/docs/HOW_IT_WORKS.md`,
  버전·호환은 `docs/VERSIONING.md`, 인수인계는 `HANDOFF.md`.

## 작업 전 확인

- 툴킷 변경 후: `cd skills/sast-remediation/toolkit && python3 tools/sast_toolkit.py validate && python3 -m unittest tools.test_toolkit`
- 저장소 안에서 `preflight`/`init`을 돌리지 않는다 — 산출물이 배포물에 섞인다.
- USAGE.md·data/decisions.json 수정 후 `sync` (USAGE.html·DECISION_LOG.md는 생성물).
