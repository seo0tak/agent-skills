#!/usr/bin/env bash
# 정본 skills/<이름>/ → Claude/Codex 포장 plugins/<이름>/skills/<이름>/ 사본 동기화.
#
# 심링크를 쓰지 않는 이유: Codex CLI의 플러그인 설치가 심링크를 빈 디렉터리로
# 복사한다(실측). Claude Code는 심링크를 실제 파일로 풀지만 두 하네스를 같은
# 포장으로 섬기려면 사본이어야 한다. 사본은 이 스크립트로만 만들고 손으로
# 편집하지 않는다. `--check`는 정본과 사본이 같은지만 확인한다(커밋 전·CI용).
set -euo pipefail
cd "$(dirname "$0")/.."

mode="${1:-sync}"
status=0
for src in skills/*/; do
  name="$(basename "$src")"
  dst="plugins/$name/skills/$name"
  if [ "$mode" = "--check" ]; then
    if [ ! -d "$dst" ] || ! diff -rq --exclude=__pycache__ --exclude='*.pyc' "$src" "$dst" >/dev/null; then
      echo "OUT OF SYNC: $dst != $src (run scripts/sync-plugins.sh)"
      status=1
    else
      echo "in sync: $dst"
    fi
    continue
  fi
  mkdir -p "plugins/$name/skills"
  rm -rf "$dst"
  # 캐시 부산물은 포장에 넣지 않는다
  rsync -a --exclude=__pycache__ --exclude='*.pyc' "$src" "$dst/"
  echo "synced: $src -> $dst"
done
exit $status
