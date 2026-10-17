import importlib
import importlib.resources
import json
import sys
import tempfile
from pathlib import Path

events = []


def audit_hook(event, args):
    if event == "import":
        events.append({
            "event": event,
            "module": args[0],
            "filename": args[1],
        })
    elif event == "open":
        raw_path = args[0]
        events.append({
            "event": event,
            "raw_path": raw_path if isinstance(raw_path, str) else None,
            "mode": args[1],
            "flags": args[2],
        })


with tempfile.TemporaryDirectory(prefix="pip surgery імпорт ") as folder:
    root = Path(folder)

    # Підготовка власних тестових файлів до спостереження.
    (root / "surgery_probe_static.py").write_text(
        "VALUE = 'static_ok'\n",
        encoding="utf-8",
    )
    (root / "surgery_probe_dynamic.py").write_text(
        "VALUE = 'dynamic_ok'\n",
        encoding="utf-8",
    )

    package_dir = root / "surgery_probe_resources"
    package_dir.mkdir()

    (package_dir / "__init__.py").write_text(
        "",
        encoding="utf-8",
    )
    (package_dir / "ресурс.txt").write_text(
        "resource_ok",
        encoding="utf-8",
    )

    previous_dont_write_bytecode = sys.dont_write_bytecode
    sys.path.insert(0, folder)
    sys.dont_write_bytecode = True

    try:
        sys.addaudithook(audit_hook)

        # Сценарій 1: звичайний імпорт.
        import surgery_probe_static

        # Сценарій 2: динамічний імпорт.
        dynamic = importlib.import_module("surgery_probe_dynamic")

        import_events = list(events)

        # Сценарій 3: ресурс пакета, розташованого в каталозі.
        resource_event_start = len(events)

        resource_value = (
            importlib.resources.files("surgery_probe_resources")
            .joinpath("ресурс.txt")
            .read_text(encoding="utf-8")
        )

        resource_events = list(events[resource_event_start:])

        # Результати тестів відокремлені від audit-подій.
        result = {
            "test_results": {
                "static": surgery_probe_static.VALUE,
                "dynamic": dynamic.VALUE,
            },
            "audit_events": import_events,
            "resource_result": resource_value,
            "resource_audit_events": resource_events,
        }
    finally:
        sys.path.remove(folder)
        sys.dont_write_bytecode = previous_dont_write_bytecode

# Запис результату не входить у збережені знімки подій.
output = Path("import-result.json")
output.write_text(
    json.dumps(result, ensure_ascii=False, indent=2),
    encoding="utf-8",
)

print(f"Saved: {output.absolute()}")
print("Resource result:", result["resource_result"])
print("Resource audit events:", len(result["resource_audit_events"]))