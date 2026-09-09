"""Semantic regressions for the standalone user-guide renderer."""
import unittest
from html.parser import HTMLParser

from tools.sast_toolkit import render_inline, render_usage_html


class Structure(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.stack = []
        self.parents = []
        self.anchors = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        self.parents.append((tag, tuple(self.stack)))
        if tag == "a":
            self.anchors.append(dict(attrs).get("href"))
        if tag not in {"meta", "hr", "br", "input", "img", "link"}:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if tag in self.stack:
            self.stack = self.stack[:len(self.stack) - 1 - self.stack[::-1].index(tag)]


class UsageRendererTests(unittest.TestCase):
    def test_strong_can_contain_inline_code(self):
        self.assertEqual(render_inline("**백업 후 `sync`**"),
                         "<strong>백업 후 <code>sync</code></strong>")

    def test_two_space_continuation_stays_in_list_item(self):
        html = render_usage_html("# 안내\n\n- 기록을\n  대조합니다.\n\n다음 단계입니다.")
        self.assertIn("기록을 대조합니다.", html)
        for tag, parents in Structure(html).parents:
            if tag == "p" and parents[-1:] in [("ul",), ("ol",)]:
                self.fail("a paragraph cannot be a direct child of a list")

    def test_nested_list_is_inside_parent_item(self):
        html = render_usage_html("- 부모\n  - 자식\n    1. 손자\n  - 둘째\n- 다음")
        lists = [(tag, parents) for tag, parents in Structure(html).parents if tag in {"ul", "ol"}]
        self.assertEqual(len(lists), 3)
        self.assertEqual(lists[1][1][-1], "li")
        self.assertEqual(lists[2][1][-1], "li")
        self.assertNotIn("- 자식", html)

    def test_fence_preserves_code_and_does_not_parse_headings(self):
        html = render_usage_html("# 안내\n\n```diff\n- <old>\n+ **new**\n## literal\n```\n\n## 끝")
        self.assertIn("<pre><code>- &lt;old&gt;\n+ **new**\n## literal</code></pre>", html)
        self.assertNotIn("<h2>literal</h2>", html)

    def test_inline_code_is_literal(self):
        self.assertEqual(render_inline("`**<x>**`"), "<code>**&lt;x&gt;**</code>")

    def test_unsafe_links_and_raw_html_are_not_executable(self):
        html = render_inline('[bad](javascript:alert) [data](data:text/plain,no) <img src=x onerror=x> [safe](https://example.test/?a=1&b=2)')
        self.assertEqual(Structure(html).anchors, ["https://example.test/?a=1&b=2"])
        self.assertIn("&lt;img", html)
        self.assertNotIn("<img", html)

    def test_link_attribute_quotes_are_escaped(self):
        html = render_inline('[link](https://example.test/"onmouseover="bad)')
        self.assertNotIn('"onmouseover=', html)

    def test_ordered_start_and_list_paragraph(self):
        html = render_usage_html("3. 첫 항목\n\n   같은 항목의 추가 설명.\n4. 다음")
        self.assertIn('<ol start="3">', html)
        self.assertIn("같은 항목의 추가 설명.", html)
        paragraphs = [parents for tag, parents in Structure(html).parents if tag == "p" and "ol" in parents]
        self.assertTrue(paragraphs)
        self.assertTrue(all(parents[-1] == "li" for parents in paragraphs))

    def test_table_has_header_and_body(self):
        html = render_usage_html("| 항목 | 의미 |\n|---|---|\n| `id` | 식별자 |")
        self.assertIn("<thead>", html)
        self.assertIn("<tbody>", html)
        self.assertIn("<code>id</code>", html)


if __name__ == "__main__":
    unittest.main()
