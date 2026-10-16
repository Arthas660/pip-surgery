from importlib.metadata import distributions
import json
import sys
from datetime import datetime
from pathlib import Path

def get_packages() -> list[dict]:
    packages = []

    for package in distributions():
        name = package.metadata.get("Name")
        if not name:
            continue

        files = []
        file_records = package.files

        for record in file_records or []:
            path = package.locate_file(record)
            try:
                size = path.stat().st_size if path.is_file() else None
                error = None if size is not None else "Missing or not a regular file"
            except OSError as exc:
                size = None
                error = str(exc)

            files.append({
                "path": str(path.absolute()),
                "size_bytes": size,
                "error": error,})

        packages.append({
            "name": name,
            "version": package.version,
            "files": files,
            "file_list_available": file_records is not None,
            "size_bytes": sum(
                file["size_bytes"]
                for file in files
                if file["size_bytes"] is not None),
                })

    return sorted(packages, key=lambda item: item["name"].casefold())

def save_report(packages: list[dict]) -> Path:
    output_dir = Path(".surgery")
    output_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    output_path = output_dir / f"inventory-{timestamp}.json"

    report = {
        "schema_version": 1,
        "python_version": sys.version.split()[0],
        "python_executable": sys.executable,
        "environment": sys.prefix,
        "packages": packages,}

    with output_path.open("x", encoding="utf-8") as file:
        json.dump(report, file, ensure_ascii=False, indent=2)
    return output_path

def main() -> None:
    packages = get_packages()

    for package in packages:
        size_mb = package["size_bytes"] / (1024 * 1024)
        unreadable = sum(
            file["size_bytes"] is None
            for file in package["files"])

        print(f"{package['name']}=={package['version']}")
        print(f"  Recorded files: {len(package['files'])}")
        print(f"  Readable file size: {size_mb:.2f} MiB")
        print(f"  Unavailable files: {unreadable}")

        if not package["file_list_available"]:
            print("  Warning: package file list is unavailable.")

    print(f"\nTotal packages: {len(packages)}")
    report_path = save_report(packages)
    print(f"Report saved: {report_path}")

if __name__ == "__main__":
    main()