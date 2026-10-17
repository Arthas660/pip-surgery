"""Conservative observation v1 export; no inventory mutation or exclusion decisions.

One event is emitted per Kernel-File record, including unknown/unattributed
records. A file's absence from the events never establishes non-use.
"""
import json
from pathlib import Path

FILE_PROVIDER = "{edd08927-9cc4-4e65-b970-c2560fb5c289}"
OPERATION = {
    ("12", "1"): "open_or_create",
    ("13", "1"): "cleanup",
    ("14", "1"): "close",
    ("15", "1"): "read",
    ("22", "1"): "query_information",
    ("23", "1"): "filesystem_control",
    ("24", "0"): "operation_end",
}


def make_observation(report, diagnostic, records):
    capture = report["capture_id"]
    if diagnostic["capture_id"] != capture:
        raise ValueError("Capture IDs do not match.")
    if any(record.get("capture_id") != capture for record in records):
        raise ValueError("A raw record belongs to another capture.")
    ids = [record["evidence_id"] for record in records]
    if len(set(ids)) != len(ids):
        raise ValueError("Duplicate raw-record evidence IDs.")
    available = set(ids)
    selected = diagnostic.get("selected_records", [])
    if any(record["evidence_id"] not in available for record in selected):
        raise ValueError("Selected evidence is missing from raw records.")
    # Cross-check the controlled attribution against the exported raw records,
    # not just a boolean or an arbitrary evidence ID.
    by_id = {record["evidence_id"]: record for record in records}
    if any(by_id[record["evidence_id"]] != record for record in selected):
        raise ValueError("Selected evidence differs from the raw record.")
    passed = diagnostic.get("controlled_chain_checks_pass") is True
    selected_ids = {record["evidence_id"] for record in selected} if passed else set()
    process = diagnostic.get("process_identity_candidate")
    target_pid = process.get("pid") if isinstance(process, dict) else None
    path_candidates = [record for record in selected
                       if record["provider_guid"] == FILE_PROVIDER
                       and record["event_id"] == "12" and record["version"] == "1"]
    linked_create = path_candidates[0] if passed and len(path_candidates) == 1 else None
    events = []
    for record in records:
        if record["provider_guid"] != FILE_PROVIDER:
            continue
        controlled = (record["evidence_id"] in selected_ids
                      and target_pid is not None and record.get("header_pid") == target_pid)
        raw_path = record["payload"].get("FileName")
        if not isinstance(raw_path, str):
            raw_path = None
        operation = OPERATION.get((record["event_id"], record["version"]), "unknown")
        event = {
            "event_id": f'{capture}:{record["evidence_id"]}',
            "capture_id": capture,
            "scenario": "controlled_native_read" if controlled else None,
            "pid": target_pid if controlled else None,
            "process_identity": dict(process) if controlled else None,
            "process_attribution": "validated_in_controlled_test" if controlled else "unresolved",
            "operation": operation,
            "raw_path": raw_path,
            "normalized_path": None,
            "path_resolution": "unresolved_for_inventory",
            "correlated_path_candidate": None,
            "success": None,
            "timestamp": None,
            "timestamp_raw": record.get("timestamp_raw"),
            "source": "windows-etw:Microsoft-Windows-Kernel-File",
            "evidence": {"capture_id": capture,
                         "artifact": "raw-kernel-records.jsonl",
                         "record_id": record["evidence_id"],
                         "additional_record_ids": []},
        }
        if controlled and operation == "read" and linked_create:
            event["correlated_path_candidate"] = {
                "raw_path": linked_create["payload"].get("FileName"),
                "status": "validated_in_controlled_test_only",
                "capture_id": capture,
                "record_id": linked_create["evidence_id"],
            }
        if controlled:
            event["evidence"]["additional_record_ids"] = sorted(selected_ids - {record["evidence_id"]})
        events.append(event)

    warnings = list(report.get("warnings", [])) + [
        "Prototype scope: one controlled child and native read, not arbitrary-command tracing.",
        "Every Kernel-File record is retained, even when its path, operation or process is unresolved.",
        "Header PID alone is not treated as verified process attribution.",
        "raw_path comes only from the event; correlated paths have separate provenance.",
        "No inventory-normalized path has been established; no normcase/resolve shortcut is applied.",
        "Event timestamps remain raw; tracerpt and Get-WinEvent differed by 60 seconds in the tested capture.",
        "Known zero ETW losses is not proof of complete coverage.",
        "No file may be classified as unused or deleted based on this report.",
        "started_at/finished_at are runner boundaries, not exact first/last ETW event times.",
    ]
    blockers = ["unresolved_paths", "unverified_absolute_event_timestamps", "general_correlation_not_validated", "process_tree_not_tracked"]
    if any(event["pid"] is None for event in events):
        blockers.append("unresolved_process_attribution")
    if not passed:
        blockers.append("controlled_chain_checks_failed_or_incomplete")
    return {
        "schema_version": 1,
        "kind": "file_usage_observation",
        "capture_id": capture,
        "environment": dict(report["environment"]),
        "backend": {"name": "windows-etw-logman-tracerpt",
                    "providers": [{"guid": FILE_PROVIDER, "keywords": "0x1f0", "level": 4},
                                  {"guid": "{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}", "keywords": "0x10", "level": 4}]},
        "started_at": report.get("started_at"),
        "finished_at": report.get("finished_at"),
        "scope": {"collection": "system-wide", "workflow": "one_controlled_native_read",
                  "process_tree_discovery": False, "coverage": "partial",
                  "inventory_matching_implemented": False},
        "recording_stopped_cleanly": report.get("recording_stopped_cleanly"),
        "postprocessing_completed": True,
        "losses": dict(diagnostic["losses"]),
        "analysis_readiness": {"usable_for_usage_matching": False,
                               "usable_for_exclusion_planning": False,
                               "blocking_reasons": blockers},
        "warnings": warnings,
        "errors": list(report.get("errors", [])) + list(diagnostic.get("diagnostics", [])),
        "counts": {"kernel_file_records": len(events),
                   "unresolved_inventory_paths": sum(e["normalized_path"] is None for e in events),
                   "unresolved_processes": sum(e["pid"] is None for e in events),
                   "unknown_operations": sum(e["operation"] == "unknown" for e in events)},
        "evidence": {"capture_id": capture, "raw_records": "raw-kernel-records.jsonl",
                     "decoded_events": "decoded.xml", "runner_report": "report.json",
                     "diagnostic": "combined-inspection.json", "loss_summary": "trace-summary.txt"},
        "events": events,
    }


def export_observation(folder, report, diagnostic, records):
    observation = make_observation(report, diagnostic, records)
    folder = Path(folder)
    # Re-running replaces only these derived files in the same capture directory.
    with (folder / "raw-kernel-records.jsonl").open("w", encoding="utf-8") as stream:
        for record in records:
            stream.write(json.dumps(record, ensure_ascii=False) + "\n")
    output = folder / "observation.json"
    output.write_text(json.dumps(observation, ensure_ascii=False, indent=2), encoding="utf-8")
    return output
