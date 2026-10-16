import json
import unittest
from contextlib import chdir
from pathlib import Path
from tempfile import TemporaryDirectory
from pip_surgery.inventory import get_packages, save_report
from unittest.mock import Mock
from pip_surgery.inventory import get_protection_reasons

class InventoryTests(unittest.TestCase):
    def test_packages_are_sorted(self):
        packages = get_packages()
        names = [package["name"] for package in packages]
        self.assertEqual(names, sorted(names, key=str.casefold))

    def test_package_size_matches_files(self):
        for package in get_packages():
            with self.subTest(package=package["name"]):
                expected_size = sum(
                    file["size_bytes"]
                    for file in package["files"]
                    if file["size_bytes"] is not None)
                self.assertEqual(package["size_bytes"], expected_size)

    def test_report_is_saved(self):
        sample = [{
            "name": "example",
            "version": "1.0",
            "files": [],
            "file_list_available": True,
            "size_bytes": 0,}]

        with TemporaryDirectory() as directory:
            with chdir(directory):
                report_path = save_report(sample)
                self.assertTrue(report_path.is_file())
                report = json.loads(
                    report_path.read_text(encoding="utf-8"))
                self.assertEqual(report["schema_version"], 1)
                self.assertEqual(report["packages"], sample)
                second_path = save_report(sample)
                self.assertNotEqual(report_path, second_path)
                self.assertTrue(Path(second_path).is_file())

    def test_editable_package_is_protected(self):
        package = Mock()
        package.read_text.return_value = (
            '{"dir_info": {"editable": true}}')
        
        reasons = get_protection_reasons(package, ["example.py"])
        self.assertTrue(
            any("Editable installation" in reason for reason in reasons)
        )

    def test_empty_file_list_is_protected(self):
        package = Mock()
        package.read_text.return_value = None
        reasons = get_protection_reasons(package, [])
        self.assertIn(
            "Package file list is missing or empty.",
            reasons,)
        
    def test_native_package_is_protected(self):
        package = Mock()
        package.read_text.return_value = None

        reasons = get_protection_reasons(
            package,
            ["example/__init__.py", "example/core.pyd"],)

        self.assertIn("Native components detected: preserve the whole package.", reasons,)

    def test_python_files_do_not_trigger_native_protection(self):
        package = Mock()
        package.read_text.return_value = None
        reasons = get_protection_reasons(package,["example/__init__.py", "example/core.py"],)
        self.assertEqual(reasons, [])
        
if __name__ == "__main__":
    unittest.main()