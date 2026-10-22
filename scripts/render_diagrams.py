#!/usr/bin/env python3
"""Render skills/**/docs/diagrams/*.d2 and *.puml to committed SVGs.

Each SVG ends with a source-sha256 comment. --check needs neither d2 nor
PlantUML: it only confirms every source has an SVG rendered from its current text.

Tools: d2 (D2 env to override), PlantUML via `plantuml` or PLANTUML_JAR (+ JAVA).
"""
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCES = ("*.d2", "*.puml")
STAMP = re.compile(r"<!-- source-sha256: ([0-9a-f]{64}) -->\s*$")


def sources(root=ROOT):
    found = []
    for pattern in SOURCES:
        found += (root / "skills").glob(f"**/docs/diagrams/{pattern}")
    return sorted(found)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def stale(root=ROOT):
    problems = []
    for src in sources(root):
        svg = src.with_suffix(".svg")
        rel = src.relative_to(root)
        if not svg.exists():
            problems.append(f"{rel}: SVG 없음")
            continue
        match = STAMP.search(svg.read_text(encoding="utf-8"))
        if not match or match.group(1) != digest(src):
            problems.append(f"{rel}: SVG가 원본과 다름")
    return problems


def plantuml_cmd():
    if os.environ.get("PLANTUML_JAR"):
        return [os.environ.get("JAVA", "java"), "-jar", os.environ["PLANTUML_JAR"]]
    if shutil.which("plantuml"):
        return ["plantuml"]
    sys.exit("PlantUML이 없습니다. plantuml을 설치하거나 PLANTUML_JAR를 지정하세요.")


def render(src):
    svg = src.with_suffix(".svg")
    if src.suffix == ".d2":
        d2 = os.environ.get("D2", "d2")
        subprocess.run([d2, "--layout=elk", "--pad=24", str(src), str(svg)],
                       check=True, capture_output=True)
    else:
        with tempfile.TemporaryDirectory() as out:
            subprocess.run([*plantuml_cmd(), "-tsvg", "-charset", "UTF-8", "-o", out, str(src)],
                           check=True, capture_output=True)
            shutil.move(next(Path(out).glob("*.svg")), svg)
    text = svg.read_text(encoding="utf-8").rstrip()
    # d2 omits the root size, so <img> (GitHub included) falls back to 300x150
    text = re.sub(r'(<svg [^>]*?)viewBox="0 0 (\d+) (\d+)">',
                  r'\1viewBox="0 0 \2 \3" width="\2" height="\3">', text, count=1)
    svg.write_text(f"{text}\n<!-- source-sha256: {digest(src)} -->\n", encoding="utf-8")
    svg.chmod(0o644)


def main(argv):
    if "--check" in argv:
        problems = stale()
        for p in problems:
            print(f"DIAGRAM: {p}")
        if problems:
            print("python3 scripts/render_diagrams.py 로 다시 그리세요.")
            return 1
        print(f"DIAGRAM: {len(sources())}개 원본과 SVG가 일치합니다.")
        return 0
    for src in sources():
        render(src)
        print(f"rendered {src.relative_to(ROOT).with_suffix('.svg')}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
