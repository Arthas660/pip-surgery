import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

def run_cli(*arguments: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "pip_surgery", *arguments],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )

class CliTests(unittest.TestCase):
    def test_help(self):
        result = run_cli("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("inventory", result.stdout)

    def test_unknown_command_is_rejected(self):
        result = run_cli("unknown-command")
        self.assertEqual(result.returncode, 2)
        self.assertIn("invalid choice", result.stderr)

    def test_existing_report_is_not_overwritten(self):
        with TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            output.write_text("keep this content", encoding="utf-8")
            result = run_cli("inventory","--output",str(output),)
            self.assertEqual(result.returncode, 1)
            self.assertIn("already exists", result.stderr)
            self.assertNotIn("Traceback", result.stderr)
            self.assertEqual(
                output.read_text(encoding="utf-8"),
                "keep this content",
            )

if __name__ == "__main__":
    unittest.main()