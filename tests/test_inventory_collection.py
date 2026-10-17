import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch
from pip_surgery.inventory import get_packages

class InventoryCollectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.environment = Path(self.temporary_directory.name)

    def make_package(self, records):
        package = Mock()
        package.metadata = {"Name": "example"}
        package.version = "1.0"
        package.files = [Path(record) for record in records]
        package.read_text.return_value = None
        package.locate_file.side_effect = (
            lambda record: self.environment / record
        )
        return package

    def collect_package(self, package):
        with (
            patch(
                "pip_surgery.inventory.distributions",
                return_value=[package],
            ),
            patch(
                "pip_surgery.inventory.sys.prefix",
                str(self.environment),
            ),
        ):
            return get_packages()[0]

    def test_collects_real_files_and_preserves_license(self):
        package_directory = self.environment / "example"
        package_directory.mkdir()

        module = package_directory / "core.py"
        license_file = package_directory / "LICENSE"

        module.write_bytes(b"abc")
        license_file.write_bytes(b"MIT\n")

        package = self.make_package(["example/core.py","example/LICENSE",])
        result = self.collect_package(package)

        self.assertEqual(result["name"], "example")
        self.assertEqual(result["version"], "1.0")
        self.assertEqual(result["size_bytes"], 7)
        self.assertEqual(len(result["files"]), 2)

        files = {Path(file["path"]).name: file for file in result["files"]}

        self.assertEqual(files["core.py"]["size_bytes"], 3)
        self.assertEqual(files["LICENSE"]["size_bytes"], 4)
        self.assertTrue(files["LICENSE"]["protected"])
        self.assertIn(
            "License or attribution file.",
            files["LICENSE"]["protection_reasons"],
        )

        # Inventory must not modify the inspected files.
        self.assertEqual(module.read_bytes(), b"abc")
        self.assertEqual(license_file.read_bytes(), b"MIT\n")

    def test_missing_file_protects_package(self):
        package = self.make_package(["example/missing.py",])

        result = self.collect_package(package)
        file = result["files"][0]

        self.assertIsNone(file["size_bytes"])
        self.assertIsNotNone(file["error"])
        self.assertTrue(result["protected"])
        self.assertIn("Some recorded files could not be inspected.",result["protection_reasons"],)

if __name__ == "__main__":
    unittest.main()