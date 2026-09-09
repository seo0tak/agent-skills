"""Packaging must omit local runtime locks without deleting the live lock."""
from pathlib import Path
import shutil
import subprocess
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


if __name__ == "__main__":
    unittest.main()
