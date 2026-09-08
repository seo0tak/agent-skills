#!/usr/bin/env bash
# 플러그인 버전이 세 곳에서 같은지 확인한다:
#   plugins/<이름>/.claude-plugin/plugin.json  (정본)
#   plugins/<이름>/.codex-plugin/plugin.json   (Codex 포장 — 같은 값이어야 함)
#   README.md 플러그인 표
# 카탈로그(.claude-plugin/marketplace.json, .agents/plugins/marketplace.json)에는
# version을 쓰지 않으므로 검사 대상이 아니다.
set -euo pipefail
cd "$(dirname "$0")/.."
status=0
for dir in plugins/*/; do
  name="$(basename "$dir")"
  claude="$(python3 -c "import json;print(json.load(open('$dir/.claude-plugin/plugin.json'))['version'])")"
  codex="$(python3 -c "import json;print(json.load(open('$dir/.codex-plugin/plugin.json'))['version'])" 2>/dev/null || echo "<missing>")"
  readme="$(grep -E "^\| \*\*?$name\*\*? \|" README.md | sed -E 's/.*\| *([0-9][0-9.]*) *\|$/\1/' || true)"
  if [ "$claude" = "$codex" ] && [ "$claude" = "$readme" ]; then
    echo "ok: $name $claude"
  else
    echo "MISMATCH: $name claude=$claude codex=$codex readme=${readme:-<none>}"
    status=1
  fi
done
exit $status
