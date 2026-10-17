from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys

if len(sys.argv) != 2:
    raise SystemExit(
        'Usage: python validate_process_identity.py "probe-folder"'
    )

folder = Path(sys.argv[1]).absolute()
report = json.loads(
    (folder / "report.json").read_text(encoding="utf-8")
)
inspection = json.loads(
    (folder / "process-inspection.json").read_text(encoding="utf-8")
)

if report["capture_id"] != inspection["capture_id"]:
    raise SystemExit("Capture IDs do not match.")

capture_id = report["capture_id"]
control = report["observer_measured_child_identity"]
expected_pid = control["pid"]
expected_creation = int(control["creation_time_filetime"])


def integer(value):
    if value is None:
        return None
    try:
        return int(str(value).strip(), 10)
    except ValueError:
        return None


def utc_to_filetime(value):
    # Приймаємо лише явний UTC із Z.
    # Не виправляємо часові зони й не округлюємо точність.
    match = re.fullmatch(
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
        r"(?:\.(\d{1,9}))?Z",
        value or "",
    )
    if not match:
        raise ValueError(f"Unsupported UTC timestamp: {value!r}")

    fraction = match.group(2) or ""

    # FILETIME має 7 десяткових розрядів секунди.
    # Додаткові розряди дозволені лише якщо вони нульові.
    if any(char != "0" for char in fraction[7:]):
        raise ValueError("Timestamp cannot be represented exactly as FILETIME.")

    fraction_ticks = int(fraction[:7].ljust(7, "0"))
    instant = datetime.strptime(
        match.group(1), "%Y-%m-%dT%H:%M:%S"
    ).replace(tzinfo=timezone.utc)

    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    delta = instant - epoch
    seconds = delta.days * 86400 + delta.seconds

    return seconds * 10_000_000 + fraction_ticks


records = inspection["records"]

# Підтримуємо лише реально побачені тут версії подій.
starts = [
    record for record in records
    if record["event_id"] == "1"
    and record["version"] == "4"
    and record["task_id"] == "1"
    and integer(record["payload"].get("ProcessID")) == expected_pid
]
stops = [
    record for record in records
    if record["event_id"] == "2"
    and record["version"] == "2"
    and record["task_id"] == "2"
    and integer(record["payload"].get("ProcessID")) == expected_pid
]

checks = {
    "control_measurements_match": (
        report["child_self_identity"] == control
    ),
    "unique_supported_process_start": len(starts) == 1,
    "unique_supported_process_stop": len(stops) == 1,
    "start_creation_matches_control": False,
    "stop_creation_matches_control": False,
    "parent_pid_matches_observer": False,
    "sequence_number_matches_start_stop": False,
    "worker_exited_with_zero": report["child_returncode"] == 0,
    "capture_stopped_cleanly": (
        report["recording_stopped_cleanly"] is True
    ),
}

errors = []
sequence = None

if len(starts) == 1:
    start = starts[0]
    payload = start["payload"]

    checks["parent_pid_matches_observer"] = (
        integer(payload.get("ParentProcessID")) == report["observer_pid"]
    )
    sequence = integer(payload.get("ProcessSequenceNumber"))

    try:
        checks["start_creation_matches_control"] = (
            utc_to_filetime(payload.get("CreateTime")) == expected_creation
        )
    except ValueError as exc:
        errors.append(str(exc))

if len(stops) == 1:
    stop = stops[0]
    payload = stop["payload"]

    try:
        checks["stop_creation_matches_control"] = (
            utc_to_filetime(payload.get("CreateTime")) == expected_creation
        )
    except ValueError as exc:
        errors.append(str(exc))

    stop_sequence = integer(payload.get("ProcessSequenceNumber"))
    checks["sequence_number_matches_start_stop"] = (
        sequence is not None
        and stop_sequence is not None
        and sequence == stop_sequence
    )

verified = all(checks.values()) and not errors

blocking_reasons = [
    "file_and_process_events_not_captured_together",
    "unverified_event_timestamps",
]
if not verified:
    blocking_reasons.append("process_identity_checks_failed")

result = {
    "kind": "controlled_process_identity_validation",
    "capture_id": capture_id,
    "checks": checks,
    "process_identity_verified_in_controlled_test": verified,
    "process_identity": {
        "pid": expected_pid,
        "creation_time_filetime": str(expected_creation),
        "etw_process_sequence_number": sequence,
        "sequence_scope": "this_capture",
    } if verified else None,
    "evidence": {
        "capture_id": capture_id,
        "control": "report.json",
        "start_records": [record["evidence_id"] for record in starts],
        "stop_records": [record["evidence_id"] for record in stops],
    },
    "reported_events_lost": inspection["reported_events_lost"],
    "analysis_readiness": {
        "usable_for_usage_matching": False,
        "usable_for_exclusion_planning": False,
        "blocking_reasons": blocking_reasons,
    },
    "warnings": [
        "Validation covers one controlled child process.",
        "Process sequence number is not treated as a global permanent ID.",
        "Event-header timestamps remain unmodified and unverified.",
        "This does not retroactively identify processes in other captures.",
    ],
    "errors": errors,
}

output = folder / "process-validation.json"
output.write_text(
    json.dumps(result, ensure_ascii=False, indent=2),
    encoding="utf-8",
)

print(json.dumps(result, ensure_ascii=False, indent=2))
print("Saved:", output)