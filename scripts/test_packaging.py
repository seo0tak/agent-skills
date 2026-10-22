"""Packaging must omit local runtime locks without deleting the live lock."""
from pathlib import Path
import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest


class PackagingTests(unittest.TestCase):
    def test_sync_excludes_runtime_lock_and_check_ignores_it(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            script = root / "scripts/sync-plugins.sh"
            script.parent.mkdir()
            shutil.copyfile(Path(__file__).with_name("sync-plugins.sh"), script)
            source = root / "skills/example"
            source.mkdir(parents=True)
            (source / "SKILL.md").write_text("# Fixture\n", encoding="utf-8")
            lock = source / ".sast-write.lock"
            lock.write_text("active lock fixture", encoding="utf-8")
            result = subprocess.run(["bash", str(script)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            packaged = root / "plugins/example/skills/example"
            self.assertFalse((packaged / ".sast-write.lock").exists(), "runtime lock must not ship")
            self.assertEqual(lock.read_text(), "active lock fixture")
            check = subprocess.run(["bash", str(script), "--check"], capture_output=True, text=True)
            self.assertEqual(check.returncode, 0, check.stdout + check.stderr)


class DiagramTests(unittest.TestCase):
    def test_committed_svgs_match_sources(self):
        result = subprocess.run(
            [sys.executable, str(Path(__file__).with_name("render_diagrams.py")), "--check"],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_check_flags_missing_and_edited_sources(self):
        spec = importlib.util.spec_from_file_location(
            "render_diagrams", Path(__file__).with_name("render_diagrams.py"))
        assert spec and spec.loader
        render_diagrams = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(render_diagrams)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            diagrams = root / "skills/example/docs/diagrams"
            diagrams.mkdir(parents=True)
            src = diagrams / "architecture.d2"
            src.write_text("a -> b\n", encoding="utf-8")
            self.assertIn("SVG 없음", render_diagrams.stale(root)[0])
            stamp = render_diagrams.digest(src)
            src.with_suffix(".svg").write_text(f"<svg/>\n<!-- source-sha256: {stamp} -->\n", encoding="utf-8")
            self.assertEqual(render_diagrams.stale(root), [])
            src.write_text("a -> c\n", encoding="utf-8")
            self.assertIn("원본과 다름", render_diagrams.stale(root)[0])


if __name__ == "__main__":
    unittest.main()
