import json
import unittest
from contextlib import chdir
from pathlib import Path
from tempfile import TemporaryDirectory
from pip_surgery.inventory import get_packages, save_report
from unittest.mock import Mock
from pip_surgery.inventory import get_protection_reasons
from pip_surgery.inventory import get_file_protection_reasons
from pip_surgery.inventory import mark_shared_files

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

    def test_report_uses_requested_path(self):
        with TemporaryDirectory() as directory:
            output = Path(directory) / "nested" / "report.json"
            result = save_report([], output=output)

            self.assertEqual(result, output)
            self.assertTrue(output.is_file())

            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["packages"], [])

    def test_existing_report_is_not_overwritten(self):
        with TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            output.write_text("original content", encoding="utf-8")

            with self.assertRaises(FileExistsError):
                save_report([], output=output)

            self.assertEqual(
                output.read_text(encoding="utf-8"),
                "original content",)

    def test_license_file_is_protected(self):
        with TemporaryDirectory() as directory:
            environment = Path(directory)
            path = environment / "example" / "LICENSE.txt"
            reasons = get_file_protection_reasons(path, environment)
            self.assertIn("License or attribution file.", reasons)

    def test_metadata_file_is_protected(self):
        with TemporaryDirectory() as directory:
            environment = Path(directory)
            path = environment / "example-1.0.dist-info" / "METADATA"
            reasons = get_file_protection_reasons(path, environment)
            self.assertIn("Package metadata.", reasons)

    def test_file_outside_environment_is_protected(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            environment = root / "venv"
            outside_file = root / "outside.txt"

            reasons = get_file_protection_reasons(
                outside_file,
                environment,)
            self.assertIn("File is outside the Python environment.",reasons,)

    def test_shared_file_is_protected(self):
        with TemporaryDirectory() as directory:
            shared_path = str(Path(directory) / "shared.py")

            packages = [
                {
                    "name": name,
                    "version": "1.0",
                    "files": [{
                        "path": shared_path,
                        "protected": False,
                        "protection_reasons": [],
                    }],
                }
                for name in ("first", "second")]

            mark_shared_files(packages)

            for package in packages:
                file = package["files"][0]

                self.assertTrue(file["protected"])
                self.assertEqual(
                    file["owners"],
                    ["first==1.0", "second==1.0"],)
                
                self.assertIn(
                    "File is shared by multiple packages.",
                    file["protection_reasons"],)

    def test_single_owner_does_not_trigger_shared_protection(self):
        with TemporaryDirectory() as directory:
            packages = [{
                "name": "example",
                "version": "1.0",
                "files": [{
                    "path": str(Path(directory) / "example.py"),
                    "protected": False,
                    "protection_reasons": [],
                }],
            }]

            mark_shared_files(packages)
            file = packages[0]["files"][0]
            self.assertEqual(file["owners"], ["example==1.0"])
            self.assertFalse(file["protected"])
            self.assertEqual(file["protection_reasons"], [])

    def test_similar_directory_name_is_outside_environment(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            environment = root / ".venv"
            outside_file = root / ".venv-backup" / "example.py"

            reasons = get_file_protection_reasons(
                outside_file,
                environment,
            )

            self.assertIn("File is outside the Python environment.",reasons,)

    def test_regular_internal_file_has_no_file_protection_reason(self):
        with TemporaryDirectory() as directory:
            environment = Path(directory)
            internal_file = environment / "example" / "core.py"
            internal_file.parent.mkdir()
            internal_file.write_text("value = 1\n", encoding="utf-8")

            reasons = get_file_protection_reasons(
                internal_file,
                environment,
            )
            self.assertEqual(reasons, [])
            
if __name__ == "__main__":
    unittest.main()