import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

events = []
recording = False

# Відомий тестовий код, який запускаємо в кожному дочірньому процесі.
CHILD_CODE = """
import json
import os
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    content = stream.read()

print(json.dumps({
    "pid": os.getpid(),
    "content": content,
}))
"""


def audit_hook(event, args):
    if not recording:
        return

    if event == "open":
        raw_path = args[0]
        events.append({
            "event": event,
            "observer_pid": os.getpid(),
            "raw_path": raw_path if isinstance(raw_path, str) else None,
            "mode": args[1],
        })

    elif event == "subprocess.Popen":
        events.append({
            "event": event,
            "observer_pid": os.getpid(),
            "executable": args[0],
        })


def stop_children(processes):
    for process in processes:
        if process.poll() is None:
            process.kill()

    for process in processes:
        process.communicate()


with tempfile.TemporaryDirectory(prefix="pip surgery діти ") as folder:
    root = Path(folder)
    files = [
        root / "дитина 1.txt",
        root / "дитина 2.txt",
    ]

    # Створення файлів відбувається до спостереження.
    for index, path in enumerate(files, start=1):
        path.write_text(f"child_{index}_ok", encoding="utf-8")

    processes = []
    child_results = []

    sys.addaudithook(audit_hook)
    recording = True

    try:
        # Спочатку запускаємо обидва процеси, потім чекаємо.
        for path in files:
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-c",
                    CHILD_CODE,
                    str(path),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            processes.append(process)

        for path, process in zip(files, processes):
            stdout, stderr = process.communicate(timeout=20)

            child_results.append({
                "pid": process.pid,
                "test_file": str(path),
                "returncode": process.returncode,
                "stdout": stdout.decode("utf-8", errors="replace"),
                "stderr": stderr.decode("utf-8", errors="replace"),
            })

        captured = list(events)
    finally:
        recording = False
        stop_children(processes)

    target_paths = {str(path) for path in files}

    result = {
        "parent_pid": os.getpid(),
        "children": child_results,
        "parent_audit_events": captured,
        "target_file_events_seen_by_parent": [
            event
            for event in captured
            if event["event"] == "open"
            and event["raw_path"] in target_paths
        ],
    }

Path("child-result.json").write_text(
    json.dumps(result, ensure_ascii=False, indent=2),
    encoding="utf-8",
)

print("Saved: child-result.json")
print("Child return codes:", [
    child["returncode"] for child in result["children"]
])
print("Target file events seen by parent:", len(
    result["target_file_events_seen_by_parent"]
))