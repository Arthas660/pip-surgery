from importlib.metadata import distributions
import json
import sys
from datetime import datetime
from pathlib import Path
import sysconfig
import os

def get_protection_reasons(package, file_records) -> list[str]:
    reasons = []

    if not file_records:
        reasons.append("Package file list is missing or empty.")
    native_extensions = (".dll", ".pyd", ".so", ".dylib", ".exe")

    for record in file_records or []:
        filename = str(record).casefold()
        if filename.endswith(native_extensions) or ".so." in filename:
            reasons.append("Native components detected: preserve the whole package.")
            break

    try:
        direct_url_text = package.read_text("direct_url.json")

        if direct_url_text:
            direct_url = json.loads(direct_url_text)

            if not isinstance(direct_url, dict):
                raise ValueError("Invalid installation metadata")

            directory_info = direct_url.get("dir_info", {})

            if not isinstance(directory_info, dict):
                raise ValueError("Invalid directory metadata")

            if directory_info.get("editable") is True:
                reasons.append("Editable installation: source files must be preserved.")

    except (OSError, UnicodeError, ValueError):
        reasons.append("Installation metadata could not be read reliably.")
    return reasons

def get_file_protection_reasons(path: Path, environment: Path,) -> list[str]:
    reasons = []
    filename = path.name.casefold()
    if filename.startswith(("license", "licence", "notice", "copying")):
        reasons.append("License or attribution file.")
    if any(
        part.casefold().endswith((".dist-info", ".egg-info"))for part in path.parts):
        reasons.append("Package metadata.")

    try:
        resolved_path = path.resolve()
        resolved_environment = environment.resolve()
        if not resolved_path.is_relative_to(resolved_environment):
            reasons.append("File is outside the Python environment.")

        if path.is_symlink():
            reasons.append("Symbolic link requires separate review.")

    except (OSError, RuntimeError, ValueError):
        reasons.append("File location could not be resolved reliably.")
    return reasons

def mark_shared_files(packages: list[dict]) -> None:
    files_by_path = {}
    for package in packages:
        owner = f"{package['name']}=={package['version']}"

        for file in package["files"]:
            try:
                normalized_path = os.path.normcase(str(Path(file["path"]).resolve()))
            except (OSError, RuntimeError, ValueError):
                file["protected"] = True
                reason = "File ownership could not be checked reliably."

                if reason not in file["protection_reasons"]:
                    file["protection_reasons"].append(reason)
                continue

            files_by_path.setdefault(normalized_path, []).append((owner, file))

    for records in files_by_path.values():
        owners = sorted({owner for owner, _ in records})

        for _, file in records:
            file["owners"] = owners

            if len(owners) > 1:
                file["protected"] = True
                reason = "File is shared by multiple packages."

                if reason not in file["protection_reasons"]:
                    file["protection_reasons"].append(reason)

def get_packages() -> list[dict]:
    packages = []

    package_paths = sorted({
        sysconfig.get_path("purelib"),
        sysconfig.get_path("platlib"),
    })

    for package in distributions(path=package_paths):
        name = package.metadata.get("Name")
        if not name:
            continue

        files = []
        file_records = package.files
        protection_reasons = get_protection_reasons(package, file_records)

        for record in file_records or []:
            path = package.locate_file(record)
            try:
                size = path.stat().st_size if path.is_file() else None
                error = None if size is not None else "Missing or not a regular file"
            except OSError as exc:
                size = None
                error = str(exc)

            file_protection_reasons = get_file_protection_reasons(Path(path),Path(sys.prefix),
            )
            files.append({
                "path": str(path.absolute()),
                "size_bytes": size,
                "error": error,
                "protected": bool(file_protection_reasons),
                "protection_reasons": file_protection_reasons,
            })
            
        if any(file["error"] is not None for file in files):
            protection_reasons.append("Some recorded files could not be inspected.")

        packages.append({
            "name": name,
            "version": package.version,
            "files": files,
            "file_list_available": file_records is not None,
            "protected": bool(protection_reasons),
            "protection_reasons": protection_reasons,
            "size_bytes": sum(
                file["size_bytes"]
                for file in files
                if file["size_bytes"] is not None),
        })

    mark_shared_files(packages)
    return sorted(packages, key=lambda item: item["name"].casefold())

def save_report(
    packages: list[dict],
    output: Path | None = None,) -> Path:
    if output is None:
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        output = Path(".surgery") / f"inventory-{timestamp}.json"

    output.parent.mkdir(parents=True, exist_ok=True)

    report = {
        "schema_version": 1,
        "python_version": sys.version.split()[0],
        "python_executable": sys.executable,
        "environment": sys.prefix,
        "packages": packages,
    }

    with output.open("x", encoding="utf-8") as file:
        json.dump(report, file, ensure_ascii=False, indent=2)

    return output

def main(output: Path | None = None) -> None:
    packages = get_packages()

    for package in packages:
        size_mb = package["size_bytes"] / (1024 * 1024)
        unreadable = sum(
            file["size_bytes"] is None
            for file in package["files"])

        print(f"{package['name']}=={package['version']}")
        print(f"  Recorded files: {len(package['files'])}")
        print(f"  Readable file size: {size_mb:.2f} MiB")
        for reason in package["protection_reasons"]:
            print(f"  Protected: {reason}")
        print(f"  Unavailable files: {unreadable}")

        if not package["file_list_available"]:
            print("  Warning: package file list is unavailable.")

    print(f"\nTotal packages: {len(packages)}")
    report_path = save_report(packages, output)
    print(f"Report saved: {report_path}")

if __name__ == "__main__":
    main()