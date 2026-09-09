"""Small, escaped Markdown subset for the bundled standalone usage guide.

Supports paragraphs, headings, fenced code, nested lists, pipe tables, inline
code/strong/emphasis and safe links. This is not a general CommonMark engine:
raw HTML, images, reference links and embedded scripts are deliberately absent.
"""
from __future__ import annotations

import re
from html import escape
from urllib.parse import urlsplit


def _safe_link(target: str) -> bool:
    if any(ord(char) < 32 for char in target) or "\\" in target:
        return False
    try:
        return urlsplit(target).scheme.lower() in {"", "http", "https", "mailto"}
    except ValueError:
        return False


def _closing(text: str, marker: str, start: int) -> int:
    """Find an emphasis delimiter without interpreting delimiters in code."""
    index = start
    while index < len(text):
        if text[index] == "`":
            run = re.match(r"`+", text[index:]).group()
            end = text.find(run, index + len(run))
            if end >= 0:
                index = end + len(run)
                continue
        if text.startswith(marker, index):
            return index
        index += 1
    return -1


def render_inline(text: str, *, _depth: int = 0) -> str:
    if _depth > 24:
        return escape(text)
    output = []
    index = 0
    while index < len(text):
        if text[index] == "`":
            run = re.match(r"`+", text[index:]).group()
            end = text.find(run, index + len(run))
            if end >= 0:
                output.append("<code>" + escape(text[index + len(run):end]) + "</code>")
                index = end + len(run)
                continue
        if text[index] == "*":
            marker = "**" if text.startswith("**", index) else "*"
            end = _closing(text, marker, index + len(marker))
            if end > index + len(marker):
                tag = "strong" if marker == "**" else "em"
                inner = render_inline(text[index + len(marker):end], _depth=_depth + 1)
                output.append(f"<{tag}>{inner}</{tag}>")
                index = end + len(marker)
                continue
        if text[index] == "[":
            label_end = text.find("](", index + 1)
            if label_end >= 0:
                end = label_end + 2
                balance = 1
                while end < len(text) and balance:
                    balance += (text[end] == "(") - (text[end] == ")")
                    end += 1
                if balance == 0:
                    target = text[label_end + 2:end - 1]
                    if target and not any(char.isspace() for char in target) and _safe_link(target):
                        label = render_inline(text[index + 1:label_end], _depth=_depth + 1)
                        output.append(f'<a href="{escape(target, quote=True)}">{label}</a>')
                        index = end
                        continue
        if text[index] == "\\" and index + 1 < len(text) and text[index + 1] in "*`[]|\\":
            index += 1
        output.append(escape(text[index]))
        index += 1
    return "".join(output)


_BULLET = re.compile(r"^( *)([-+*]|\d+[.)]) +(.*)$")
_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
_HEADING = re.compile(r"^ {0,3}(#{1,6}) +(.*)$")


def _cells(line: str) -> list[str]:
    return [cell.strip() for cell in re.split(r"(?<!\\)\|", line.strip().strip("|"))]


def _table_start(lines: list[str], index: int) -> bool:
    return (index + 1 < len(lines) and "|" in lines[index]
            and all(re.fullmatch(r":?-{3,}:?", cell) for cell in _cells(lines[index + 1])))


class _Renderer:
    def __init__(self):
        self.title = "사용 가이드"
        self.toc = []

    def blocks(self, lines: list[str], *, top: bool = False, depth: int = 0) -> str:
        if depth > 24:
            return "<pre><code>" + escape("\n".join(lines)) + "</code></pre>"
        output = []
        index = 0
        section_open = False
        while index < len(lines):
            line = lines[index]
            if not line.strip():
                index += 1
                continue
            fence = _FENCE.match(line)
            heading = _HEADING.match(line)
            bullet = _BULLET.match(line)
            if fence:
                marker = fence.group(1)
                code = []
                index += 1
                while index < len(lines) and not re.fullmatch(r" {0,3}" + re.escape(marker[0]) + "{" + str(len(marker)) + r",}\s*", lines[index]):
                    code.append(lines[index])
                    index += 1
                output.append("<pre><code>" + escape("\n".join(code)) + "</code></pre>")
                index += 1
            elif heading:
                level, text = len(heading.group(1)), heading.group(2)
                if level == 1 and top:
                    self.title = text
                else:
                    if level == 2 and top:
                        if section_open:
                            output.append("</section>")
                        anchor = f"s{len(self.toc) + 1}"
                        self.toc.append((anchor, text))
                        output.append(f'<section id="{anchor}">')
                        section_open = True
                    output.append(f"<h{level}>{render_inline(text)}</h{level}>")
                index += 1
            elif _table_start(lines, index):
                headers = _cells(line)
                output.append('<div class="table-scroll"><table><thead><tr>' + "".join(
                    f'<th scope="col">{render_inline(cell)}</th>' for cell in headers) + "</tr></thead><tbody>")
                index += 2
                while index < len(lines) and "|" in lines[index] and lines[index].strip():
                    cells = _cells(lines[index])
                    cells = (cells + [""] * len(headers))[:len(headers)]
                    output.append("<tr>" + "".join(f"<td>{render_inline(cell)}</td>" for cell in cells) + "</tr>")
                    index += 1
                output.append("</tbody></table></div>")
            elif bullet:
                kind = "ol" if bullet.group(2)[0].isdigit() else "ul"
                base_indent = len(bullet.group(1))
                start = int(bullet.group(2)[:-1]) if kind == "ol" else 1
                attr = f' start="{start}"' if start != 1 else ""
                output.append(f"<{kind}{attr}>")
                while index < len(lines):
                    match = _BULLET.match(lines[index])
                    if not match or len(match.group(1)) != base_indent or ("ol" if match.group(2)[0].isdigit() else "ul") != kind:
                        break
                    content_indent = match.start(3)
                    item = [match.group(3)]
                    index += 1
                    while index < len(lines):
                        current = lines[index]
                        if not current.strip():
                            lookahead = index + 1
                            while lookahead < len(lines) and not lines[lookahead].strip():
                                lookahead += 1
                            if lookahead < len(lines) and len(lines[lookahead]) - len(lines[lookahead].lstrip()) >= content_indent:
                                item.append("")
                                index += 1
                                continue
                            if lookahead < len(lines) and _BULLET.match(lines[lookahead]):
                                index = lookahead
                            break
                        indent = len(current) - len(current.lstrip())
                        if indent < content_indent:
                            break
                        item.append(current[content_indent:])
                        index += 1
                    output.append("<li>" + self.blocks(item, depth=depth + 1) + "</li>")
                output.append(f"</{kind}>")
            elif re.fullmatch(r" {0,3}([-*_])(?:\s*\1){2,}\s*", line):
                output.append("<hr>")
                index += 1
            else:
                paragraph = [line.strip()]
                index += 1
                while index < len(lines) and lines[index].strip():
                    if _BULLET.match(lines[index]) or _FENCE.match(lines[index]) or _HEADING.match(lines[index]) or _table_start(lines, index):
                        break
                    paragraph.append(lines[index].strip())
                    index += 1
                output.append("<p>" + render_inline(" ".join(paragraph)) + "</p>")
        if section_open:
            output.append("</section>")
        return "\n".join(output)


def render_usage_html(markdown: str, css: str = "", generated_marker: str = "") -> str:
    renderer = _Renderer()
    body = renderer.blocks(markdown.expandtabs(4).splitlines(), top=True)
    nav = "\n".join(f'<a href="#{anchor}">{render_inline(title)}</a>' for anchor, title in renderer.toc)
    marker = (generated_marker + " from USAGE.md. 직접 편집하지 말고 USAGE.md를 고친 뒤 sync를 실행한다. -->\n") if generated_marker else ""
    return (
        '<!DOCTYPE html>\n<html lang="ko">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f'<title>{escape(renderer.title)}</title>\n<style>\n{css}</style>\n</head>\n<body>\n'
        + marker + '<div class="layout">\n'
        f'<nav class="toc" aria-label="목차">\n{nav}\n</nav>\n<main>\n'
        f'<header class="page"><h1>{escape(renderer.title)}</h1>'
        '<p>이 페이지는 <code>USAGE.md</code>에서 생성한 읽기용 가이드입니다.</p></header>\n'
        + body + '\n</main>\n</div>\n</body>\n</html>\n'
    )
