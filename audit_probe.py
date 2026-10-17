import json
import sys
import tempfile
from pathlib import Path
import os

events = []

capture_exists = False
exists_audit_names = []

def audit_hook(event, args):
    if capture_exists:
        exists_audit_names.append(event)
    if event in ("os.listdir", "os.scandir"):
        events.append({
            "event": event,
            "raw_path": args[0],
        })
        return
    if event != "open":
        return

    raw_path = args[0]

    try:
        cwd = os.getcwd()
    except OSError:
        cwd = None

    # Лише лексичне перетворення для нашого контрольованого тесту.
    # Не встановлює ідентичність файла й не розкриває symlink/junction.
    if isinstance(raw_path, str) and cwd is not None:
        path_candidate = os.path.normpath(
            os.path.join(cwd, raw_path)
        )
    else:
        path_candidate = None

    events.append({
        "event": event,
        "raw_path": raw_path if isinstance(raw_path, str) else None,
        "cwd_at_event": cwd,
        "path_candidate": path_candidate,
        "path_resolution": (
            "lexical_only" if path_candidate is not None else "unknown"
        ),
        "mode": args[1],
        "flags": args[2],
    })


with tempfile.TemporaryDirectory(prefix="pip surgery тест ") as folder:
    existing = Path(folder) / "дані.txt"
    missing = Path(folder) / "немає.txt"

    # Підготовка до початку спостереження.
    existing.write_text("Привіт!", encoding="utf-8")

    sys.addaudithook(audit_hook)
    previous_cwd = os.getcwd()
    try:
        os.chdir(folder)

        for _ in range(2):
            with open("дані.txt", encoding="utf-8") as stream:
                stream.read()
    finally:
        os.chdir(previous_cwd)

    try:
        with open(existing, encoding="utf-8") as stream:
            stream.read()
        existing_result = "read_ok"
    except OSError as exc:
        existing_result = type(exc).__name__

    try:
        with open(missing, encoding="utf-8") as stream:
            stream.read()
        missing_result = "unexpected_success"
    except FileNotFoundError:
        missing_result = "FileNotFoundError"

    # Знімок до очищення тимчасової папки.
    capture_exists = True
    try:
        exists_probe = {
            "existing": existing.exists(),
            "missing": missing.exists(),
        }
    finally:
        capture_exists = False
    
    metadata_results = {
        "exists_probe": exists_probe,
        "exists_audit_names": exists_audit_names,
        "existing_exists": existing.exists(),
        "missing_exists": missing.exists(),
        "listdir_names": sorted(os.listdir(folder)),
    }

    with os.scandir(folder) as entries:
        metadata_results["scandir_names"] = sorted(
            entry.name for entry in entries
        )
    captured = list(events)

result = {
    "metadata_results": metadata_results,
    "test_results": {
        "existing_file": existing_result,
        "missing_file": missing_result,
    },
    "audit_events": captured,
}

Path("audit-result.json").write_text(
    json.dumps(result, ensure_ascii=False, indent=2),
    encoding="utf-8",
)

print("Saved: audit-result.json")