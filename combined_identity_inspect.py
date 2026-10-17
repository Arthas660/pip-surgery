"""Offline diagnostic for combined_identity_probe.py; not a production backend."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from datetime import datetime, timezone
import xml.etree.ElementTree as ET

FILE = "{edd08927-9cc4-4e65-b970-c2560fb5c289}"
PROCESS = "{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}"
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def number(value):
    if value is None:
        return None
    try:
        value = str(value).strip()
        return int(value, 16) if value.lower().startswith("0x") else int(value, 10)
    except ValueError:
        return None


def timestamp_parts(value):
    """Return exact wall-clock nanoseconds plus untouched offset label.

    This does NOT convert the value to UTC or certify its absolute accuracy.
    Values are compared only when the offset labels are identical.
    """
    match = re.fullmatch(
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})",
        value or "",
    )
    if not match:
        raise ValueError(f"Unsupported timestamp: {value!r}")
    base = datetime.strptime(match[1], "%Y-%m-%dT%H:%M:%S")
    delta = base - datetime(1601, 1, 1)
    fraction = int((match[2] or "").ljust(9, "0"))
    return ((delta.days * 86400 + delta.seconds) * 1_000_000_000 + fraction, match[3])


def utc_filetime(value):
    ticks_ns, offset = timestamp_parts(value)
    if offset != "Z" or ticks_ns % 100:
        raise ValueError("Expected exact UTC representable as FILETIME.")
    return ticks_ns // 100


def payload(record):
    return record["payload"]


def signature(record, provider, event_id, version):
    return (record["provider_guid"] == provider
            and record["event_id"] == event_id
            and record["version"] == version)


def analyze(report, records, lost):
    messages = report.get("worker_messages", [])
    ready_list = [item for item in messages if item.get("phase") == "ready"]
    result_list = [item for item in messages if item.get("phase") == "result"]
    if len(ready_list) != 1 or len(result_list) != 1:
        raise ValueError("Expected exactly one ready and one result control message.")
    ready, worker = ready_list[0], result_list[0]
    control = report["observer_measured_child_identity"]
    pid, tid = control["pid"], ready["windows_tid"]
    creation = int(control["creation_time_filetime"])
    before, after = ready["handle_before_read"], worker.get("handle_after_read")
    nt_path = before["nt_path"]
    checks = {
        "control_process_identities_match": control == ready["process_identity"] == worker.get("process_identity_after_read"),
        "control_file_identity_stable": bool(after) and before["file_identity"] == after["file_identity"],
        "control_paths_stable": bool(after) and before["nt_path"] == after["nt_path"] and before["dos_path"] == after["dos_path"],
        "control_thread_stable": tid == worker.get("windows_tid_after_read"),
        "control_read_succeeded": worker.get("read_success") is True,
        "control_content_matches": worker.get("content_matches") is True,
        "control_close_succeeded": worker.get("close_handle_success") is True,
        "worker_exited_cleanly": report.get("child_returncode") == 0 and not worker.get("errors"),
        "capture_stopped_cleanly": report.get("recording_stopped_cleanly") is True,
        "unique_process_start": False, "unique_process_stop": False,
        "start_creation_matches_control": False, "stop_creation_matches_control": False,
        "parent_pid_matches_observer": False, "process_sequence_matches": False,
        "unique_exact_path_create_with_pid_tid": False,
        "single_read_with_same_file_object_pid_tid": False,
        "close_boundary_found": False,
        "relative_lifecycle_order_consistent": False,
        "no_observed_file_object_reuse_before_close": False,
        "tracerpt_reports_zero_events_lost": lost == 0,
    }
    diagnostics = []
    starts = [r for r in records if signature(r, PROCESS, "1", "4") and number(payload(r).get("ProcessID")) == pid]
    stops = [r for r in records if signature(r, PROCESS, "2", "2") and number(payload(r).get("ProcessID")) == pid]
    checks["unique_process_start"], checks["unique_process_stop"] = len(starts) == 1, len(stops) == 1
    start = starts[0] if len(starts) == 1 else None
    stop = stops[0] if len(stops) == 1 else None
    sequence = None
    if start:
        checks["parent_pid_matches_observer"] = number(payload(start).get("ParentProcessID")) == report["observer_pid"]
        sequence = number(payload(start).get("ProcessSequenceNumber"))
        try:
            checks["start_creation_matches_control"] = utc_filetime(payload(start).get("CreateTime")) == creation
        except ValueError as exc:
            diagnostics.append(str(exc))
    if stop:
        try:
            checks["stop_creation_matches_control"] = utc_filetime(payload(stop).get("CreateTime")) == creation
        except ValueError as exc:
            diagnostics.append(str(exc))
        checks["process_sequence_matches"] = sequence is not None and sequence == number(payload(stop).get("ProcessSequenceNumber"))

    def target_thread(record):
        return (record["header_pid"] == pid and record["header_tid"] == tid
                and number(payload(record).get("IssuingThreadId")) == tid)

    creates = [r for r in records if signature(r, FILE, "12", "1") and payload(r).get("FileName") == nt_path and target_thread(r)]
    checks["unique_exact_path_create_with_pid_tid"] = len(creates) == 1
    create = creates[0] if len(creates) == 1 else None
    file_records, reads = [], []
    selected_read, close_record = None, None
    file_object = number(payload(create).get("FileObject")) if create else None
    if file_object not in (None, 0):
        file_records = [r for r in records if r["provider_guid"] == FILE and number(payload(r).get("FileObject")) == file_object]
        reads = [r for r in file_records if signature(r, FILE, "15", "1") and target_thread(r)]
        # Deliberately conservative: do not silently choose among repeated reads.
        checks["single_read_with_same_file_object_pid_tid"] = len(reads) == 1
        selected_read = reads[0] if len(reads) == 1 else None
        if selected_read:
            try:
                create_time, offset = timestamp_parts(create["timestamp_raw"])
                read_time, read_offset = timestamp_parts(selected_read["timestamp_raw"])
                timed = [(r, timestamp_parts(r["timestamp_raw"])) for r in file_records]
                if read_offset != offset or any(item[1][1] != offset for item in timed):
                    raise ValueError("Different serialized offsets in the FileObject evidence.")
                close_candidates = [(r, value[0]) for r, value in timed if signature(r, FILE, "14", "1") and value[0] > read_time]
                if close_candidates:
                    first_time = min(value for _, value in close_candidates)
                    first = [r for r, value in close_candidates if value == first_time]
                    if len(first) == 1:
                        close_record = first[0]
                        checks["close_boundary_found"] = True
                        # Include all Create/Close versions when checking object reuse.
                        conflicting = [r for r, value in timed if r["evidence_id"] != create["evidence_id"]
                                       and r["event_id"] in ("12", "14") and create_time <= value[0] < first_time]
                        checks["no_observed_file_object_reuse_before_close"] = not conflicting
                        if start and stop:
                            start_time, start_offset = timestamp_parts(start["timestamp_raw"])
                            stop_time, stop_offset = timestamp_parts(stop["timestamp_raw"])
                            checks["relative_lifecycle_order_consistent"] = (
                                start_offset == stop_offset == offset
                                and start_time < create_time < read_time < first_time < stop_time)
            except ValueError as exc:
                diagnostics.append(str(exc))
    passed = all(checks.values()) and not diagnostics
    chosen = [r for r in (start, create, selected_read, close_record, stop) if r]
    return {
        "kind": "combined_controlled_chain_diagnostic",
        "capture_id": report["capture_id"],
        "checks": checks,
        "controlled_chain_checks_pass": passed,
        "process_identity_candidate": {"pid": pid, "creation_time_filetime": str(creation), "etw_process_sequence_number": sequence, "sequence_scope": "this_capture"},
        "path_comparison": {"kind": "exact_nt_path_from_control_handle", "control_nt_path": nt_path,
                            "etw_create_raw_path": payload(create).get("FileName") if create else None,
                            "normalized_path": None},
        "read_event": {"raw_path": payload(selected_read).get("FileName") if selected_read else None,
                       "normalized_path": None, "success": None, "timestamp": None,
                       "timestamp_raw": selected_read["timestamp_raw"] if selected_read else None},
        "ordering_basis": "Relative header times with identical serialized offsets, not corrected UTC and not XML position.",
        "losses": {"tracerpt_total_events_lost": lost, "buffers_lost": None, "evidence": "trace-summary.txt"},
        "analysis_readiness": {"usable_for_usage_matching": False, "usable_for_exclusion_planning": False,
            "blocking_reasons": ["inventory_path_normalization_not_verified", "unverified_absolute_event_timestamps", "general_correlation_not_validated"]
                + ([] if passed else ["controlled_chain_checks_failed_or_incomplete"])},
        "warnings": ["Only one controlled read is tested; this is not a general correlator.",
                     "Zero reported losses is not proof that no evidence is missing.",
                     "FileKey is not equated with the handle-derived file ID.",
                     "OperationEnd was not correlated; read success remains unknown to this diagnostic.",
                     "Control DOS path is not substituted for an observed inventory path.",
                     "Other or unmatched events must not be interpreted as unused files."],
        "diagnostics": diagnostics,
        "evidence": {"capture_id": report["capture_id"], "control": "report.json",
                     "selected_records": [r["evidence_id"] for r in chosen]},
        "selected_records": chosen,
        "same_file_object_records": file_records,
        "target_process_start_candidates": starts,
        "target_process_stop_candidates": stops,
        "target_create_candidates": creates,
        "target_read_candidates": reads,
    }


def parse_records(path, capture_id):
    records, total = [], 0
    def text_at(element, query):
        child = element.find(query, NS)
        return child.text.strip() if child is not None and child.text else None
    for _, element in ET.iterparse(path, events=("end",)):
        if element.tag.rsplit("}", 1)[-1] != "Event":
            continue
        total += 1
        provider = element.find("e:System/e:Provider", NS)
        guid = provider.get("Guid", "").lower() if provider is not None else ""
        if guid in (FILE, PROCESS):
            execution = element.find("e:System/e:Execution", NS)
            timestamp = element.find("e:System/e:TimeCreated", NS)
            records.append({
                "capture_id": capture_id, "evidence_id": f"decoded.xml:event:{total}",
                "provider_guid": guid,
                "event_id": text_at(element, "e:System/e:EventID"),
                "version": text_at(element, "e:System/e:Version"),
                "task": text_at(element, "e:RenderingInfo/e:Task"),
                "header_pid": number(execution.get("ProcessID")) if execution is not None else None,
                "header_tid": number(execution.get("ThreadID")) if execution is not None else None,
                "timestamp_raw": timestamp.get("SystemTime") if timestamp is not None else None,
                "payload": {d.get("Name"): d.text for d in element.findall("e:EventData/e:Data", NS) if d.get("Name")},
                "raw_xml": ET.tostring(element, encoding="unicode"),
            })
        element.clear()
    return records, total


def reported_losses(path):
    if not path.is_file():
        return None
    raw = path.read_bytes()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        text = raw.decode("utf-16")
    else:
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            text = raw.decode("mbcs", errors="replace")
    match = re.search(r"Total\s+Events\s+Lost\s+(\d+)", text, re.IGNORECASE)
    return int(match[1]) if match else None


def self_test():
    import copy
    assert utc_filetime("2026-10-17T19:20:43.731306500Z") == 134367384437313065
    assert utc_filetime("2026-10-17T19:20:43.7313065Z") == 134367384437313065
    for invalid in ("2026-10-17T19:20:43.731306501Z", "2026-10-17T22:20:43.731306500+02:59"):
        try:
            utc_filetime(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError("Unsupported FILETIME input accepted")
    pid, tid, path = 123, 456, "\\Device\\TestVolume\\fixture.txt"
    ident = {"pid": pid, "creation_time_filetime": str(utc_filetime("2026-10-17T19:20:43Z"))}
    snap = {"nt_path": path, "dos_path": "\\\\?\\C:\\fixture.txt", "file_identity": {"id": "test"}}
    report = {"capture_id": "synthetic-test", "observer_pid": 10, "observer_measured_child_identity": ident,
              "child_returncode": 0, "recording_stopped_cleanly": True,
              "worker_messages": [{"phase": "ready", "process_identity": ident, "windows_tid": tid, "handle_before_read": snap},
                 {"phase": "result", "process_identity_after_read": ident, "handle_after_read": snap,
                  "windows_tid_after_read": tid, "read_success": True, "content_matches": True, "close_handle_success": True, "errors": []}]}
    def record(provider, event_id, version, micro, data):
        return {"capture_id": "synthetic-test", "provider_guid": provider, "event_id": event_id, "version": version,
                "header_pid": pid, "header_tid": tid, "evidence_id": f"test:{micro}",
                "timestamp_raw": f"2026-10-17T22:20:43.{micro:09d}+02:59", "payload": data}
    proc = {"ProcessID": str(pid), "CreateTime": "2026-10-17T19:20:43Z", "ProcessSequenceNumber": "99", "ParentProcessID": "10"}
    obj = {"FileObject": "0x123", "IssuingThreadId": str(tid), "Irp": "0xaaa"}
    records = [record(PROCESS, "1", "4", 100, proc), record(FILE, "12", "1", 200, dict(obj, FileName=path)),
               record(FILE, "15", "1", 300, obj), record(FILE, "14", "1", 400, obj), record(PROCESS, "2", "2", 500, proc)]
    assert analyze(report, records, 0)["controlled_chain_checks_pass"]
    assert analyze(report, list(reversed(records)), 0)["controlled_chain_checks_pass"]  # no XML-order dependency
    assert not analyze(report, records, None)["controlled_chain_checks_pass"]
    assert not analyze(report, records[:-1], 0)["controlled_chain_checks_pass"]
    bad = copy.deepcopy(records)
    bad[2]["header_pid"] = 999
    assert not analyze(report, bad, 0)["controlled_chain_checks_pass"]
    assert not analyze(report, records + [record(FILE, "12", "1", 250, dict(obj, FileName="other"))], 0)["controlled_chain_checks_pass"]
    assert not analyze(report, records + [record(FILE, "15", "1", 350, obj)], 0)["controlled_chain_checks_pass"]
    print("PASS: exact time parsing, unsupported timestamps, positive chain, reordered records, unknown losses, missing stop, wrong PID, FileObject reuse, repeated Read.")


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return
    if sys.platform != "win32" or len(sys.argv) != 2:
        raise SystemExit('On Windows: python combined_identity_inspect.py "probe-folder"')
    folder = Path(sys.argv[1]).absolute()
    report = json.loads((folder / "report.json").read_text(encoding="utf-8"))
    if report.get("kind") != "combined_file_process_identity_probe" or report.get("probe_format_version") != 1:
        raise SystemExit("Unsupported probe report.")
    if report.get("recording_stopped_cleanly") is not True:
        raise SystemExit("A clean ETW stop is not confirmed.")
    etls = sorted(folder.glob("*.etl"))
    if not etls:
        raise SystemExit("No ETL files found.")
    tracerpt = Path(os.environ["SystemRoot"]) / "System32" / "tracerpt.exe"
    xml, summary = folder / "decoded.xml", folder / "trace-summary.txt"
    completed = subprocess.run([str(tracerpt), *map(str, etls), "-o", str(xml), "-of", "XML", "-summary", str(summary), "-y"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, check=False)
    print("tracerpt return code:", completed.returncode)
    if completed.returncode:
        print(completed.stdout.decode("mbcs", errors="replace"))
        print(completed.stderr.decode("mbcs", errors="replace"))
        raise SystemExit("Conversion failed.")
    records, total = parse_records(xml, report["capture_id"])
    result = analyze(report, records, reported_losses(summary))
    result["total_decoded_events"] = total
    result["supported_provider_records"] = len(records)
    output = folder / "combined-inspection.json"
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print("Capture:", report["capture_id"])
    print("Total decoded events:", total)
    print("Checks:")
    print(json.dumps(result["checks"], ensure_ascii=False, indent=2))
    print("Controlled chain checks pass:", result["controlled_chain_checks_pass"])
    print("Diagnostics:", result["diagnostics"])
    print("Losses:", json.dumps(result["losses"], ensure_ascii=False))
    print("Process identity candidate:", json.dumps(result["process_identity_candidate"], ensure_ascii=False))
    print("Path comparison:", json.dumps(result["path_comparison"], ensure_ascii=False))
    print("Evidence:", json.dumps(result["evidence"], ensure_ascii=False))
    print("Analysis readiness:", json.dumps(result["analysis_readiness"], ensure_ascii=False))
    print("Saved:", output)
    for record in result["selected_records"]:
        print(json.dumps({k: v for k, v in record.items() if k != "raw_xml"}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
